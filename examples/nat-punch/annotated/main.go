// nat-punch 是一个极简、零依赖的 UDP 打洞（hole punching）测试工具。
//
// 它存在的原因：examples/derp-nat 只能回答一个问题 —— “derphole 那一整套机制
// 是否打通了直连路径？” 而这套机制环节很多（DERP 信令、4 条并行 UDP 通道、
// 固定 1.2s 的打洞窗口、2/4 通道多数裁决、最后是 QUIC 握手）。一旦失败，你
// 根本判断不出是哪一层出了问题。本工具把上面这些全部剥掉，只测试最底下那一件事：
// 两台各自位于 NAT 之后的主机，能不能把“单个 UDP 包”送到对方手里？
//
// 它同时可以替代 tcpdump / nc 那套手工判断 NAT 类型的方法，并且在 Windows
// 和 Linux 上用法完全一致。
//
// 两种模式：
//
//	# 在公网 VPS 上运行 —— 把每个数据包的观测源地址原样反射回去。
//	# 在两台不同的 VPS 上各跑一个，才能区分 cone / symmetric NAT。
//	go run . -mode=reflect -listen=:3478
//
//	# 在每台待测试的机器上运行：
//	go run . -mode=punch -reflect=<vps1-ip>:3478,<vps2-ip>:3478
//	# 它会打印出你的公网地址，然后等你把对端的地址粘贴进来。
//	# 两台机器都启动后，在几秒之内互粘对方地址 —— 只有双方几乎同时发包，
//	# 打洞才有可能成功。
//
// 整个会话只使用“一个 socket”，这正是结果有意义的前提：反射服务器看到的地址，
// 就是接下来打洞包会使用的同一个 NAT 映射。重启进程会得到一个新的映射。
package main

import (
	"bufio"           // 从终端读取一行输入（粘贴对端地址）
	"encoding/binary" // 把发送序号按大端序写进打洞报文
	"flag"            // 命令行参数解析
	"fmt"             // 向终端打印结果（不带时间戳）
	"log"             // 带时间戳的日志输出
	"net"             // UDP 地址解析、监听、收发
	"os"              // 标准输入 Stdin / 标准错误 Stderr
	"strings"         // 字符串切分、去空格、前后缀判断
	"sync"            // Mutex、Once：反射服务器并发保护与一次性关闭
	"sync/atomic"     // 打洞循环中的原子计数器与布尔标志
	"time"            // 超时、定时器、时间间隔
)

const (
	whoamiMagic  = "WHOAMI?" // 探测报文内容：请反射服务器告诉我“你看到的我是谁”
	statusPrefix = "STATUS " // 查询报文前缀：问反射服务器“某个地址最近活跃吗”
	// peerActiveWindow：反射服务器判定一个地址“活跃”的时间窗口。
	// 打洞端每隔几秒就发一次 STATUS 查询，所以真正在跑的对端一定会落在这个窗口内。
	peerActiveWindow = 15 * time.Second
)

func main() {
	// 译：punch=被测试的机器，reflect=公网 VPS 上的辅助服务
	mode := flag.String("mode", "punch", "punch (machine under test) or reflect (public VPS helper)") // -mode：运行模式，默认 punch
	// 译：reflect 模式监听的 UDP 地址
	listen := flag.String("listen", ":3478", "reflect mode: UDP address to listen on") // -listen：reflect 模式监听地址
	// 译：逗号分隔的反射服务器地址；给两个不同公网 IP 的才能判定 NAT 类型
	reflect := flag.String("reflect", "", "punch mode: comma-separated reflector addresses; give TWO on different IPs to classify the NAT") // -reflect：反射服务器列表
	// 译：本地绑定的 UDP 端口，0=让系统随机选
	local := flag.Int("local", 0, "punch mode: local UDP port to bind (0 = let the OS pick)") // -local：本地端口，0 = 系统分配
	// 译：超过该时长就放弃；0=一直打到收到包（推荐，不必让两端在几秒内同时启动）
	duration := flag.Duration("duration", 0, "punch mode: give up after this long (0 = keep punching until a packet arrives; recommended, since it removes the need to start both sides within seconds of each other)") // -duration：超时时间
	// 译：两个打洞包之间的发送间隔
	interval := flag.Duration("interval", 200*time.Millisecond, "punch mode: gap between outgoing punch packets") // -interval：打洞发包间隔，默认 200ms
	flag.Parse()                                                                                                  // 真正解析命令行参数，之后上面各个指针才有值

	switch *mode { // 根据模式分发
	case "reflect":
		runReflect(*listen) // 反射服务器模式：部署在公网 VPS 上
	case "punch":
		runPunch(*reflect, *local, *duration, *interval) // 打洞模式：运行在被测试的两台机器上
	default:
		log.Fatal("-mode must be punch or reflect") // 模式非法，直接退出（退出码 1）
	}
}

// runReflect 做两件事：
//  1. 对 "WHOAMI?" 回应该报文“被观测到的源地址”（即对方的公网 ip:port）；
//  2. 对 "STATUS <addr>" 回应 <addr> 最近是否活跃（ACTIVE / IDLE）。
//
// 第 2 点是“打洞失败可解释”的关键：反射服务器同时跟两台机器通信，因此它能告诉你
// “对端当时到底有没有在打洞”。这件事靠墙上时钟时间戳是判断不了的 —— 两台主机的
// 时钟可能根本不同步。
func runReflect(listen string) {
	addr, err := net.ResolveUDPAddr("udp4", listen) // 把 ":3478" 之类的字符串解析成 UDP 地址结构
	if err != nil {
		log.Fatalf("resolve %s: %v", listen, err) // 地址写错，直接退出
	}
	conn, err := net.ListenUDP("udp4", addr) // 在该地址上建立 UDP 监听（只支持 IPv4）
	if err != nil {
		log.Fatalf("listen %s: %v", listen, err) // 端口被占用等情况，直接退出
	}
	defer conn.Close()                                        // 函数返回前关闭 socket（本函数实际是死循环，靠进程退出兜底）
	log.Printf("reflector listening on %s", conn.LocalAddr()) // 打印实际监听地址，方便确认

	var mu sync.Mutex              // 保护下面的 seen（单协程循环其实用不到，但保留并发安全）
	seen := map[string]time.Time{} // key 是 "ip:port" 字符串，value 是该地址最后一次发包的时刻

	buf := make([]byte, 1024) // 复用的接收缓冲区，1024 字节远超本工具用到的报文长度
	for {                     // 主循环：一直接收、一直回应
		n, from, err := conn.ReadFromUDP(buf) // 阻塞读一个 UDP 包，n 是长度，from 是源地址
		if err != nil {
			log.Printf("read: %v", err) // 读出错只记录，不退出，继续下一轮
			continue
		}
		payload := string(buf[:n]) // 把收到的字节转成字符串，方便做前缀判断

		mu.Lock()                        // 加锁写 map
		seen[from.String()] = time.Now() // 无论报文内容是什么，都先把这个源地址标记为“刚活跃过”
		mu.Unlock()                      // 解锁

		var reply string                                                // 准备要回给对方的内容
		if target, ok := strings.CutPrefix(payload, statusPrefix); ok { // 情况 A：是 "STATUS <addr>" 查询
			target = strings.TrimSpace(target) // 去掉地址两端可能的空白/换行
			mu.Lock()
			last, known := seen[target] // 查这个被问询的地址，我们见过它吗、最后一次是何时
			mu.Unlock()
			if known && time.Since(last) < peerActiveWindow { // 见过，且距今在 15s 活跃窗口内
				reply = "ACTIVE" // 对端在打洞，是“活跃”的
			} else {
				reply = "IDLE" // 没见过，或太久没动静
			}
			log.Printf("status query from %s about %s -> %s", from, target, reply) // 记录查询与结论
		} else { // 情况 B：不是 STATUS，一律当作 WHOAMI 探测（含老版本的探测包）
			reply = from.String()                    // 把我们看到的它的公网地址原样回过去
			log.Printf("saw %s (%d bytes)", from, n) // 记录一下见过谁
		}
		if _, err := conn.WriteToUDP([]byte(reply), from); err != nil { // 把 reply 发回源地址
			log.Printf("reply to %s: %v", from, err) // 发送失败（如对方已不可达）只记录
		}
	}
}

func runPunch(reflectors string, localPort int, duration, interval time.Duration) {
	// 关键：整个进程从头到尾只用这一个 socket。
	// NAT 映射是“按 socket 四元组”分配的，换一个 socket 就等于换一个公网端口，
	// 那反射服务器看到的地址就和打洞用的地址不是一回事了。
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{Port: localPort}) // 绑定本地端口（IP 留空 = 0.0.0.0 全网卡）
	if err != nil {
		log.Fatalf("bind local port %d: %v", localPort, err) // 绑定失败，退出
	}
	defer conn.Close()                               // 退出前关闭 socket
	log.Printf("local socket: %s", conn.LocalAddr()) // 打印本地实际绑定的 ip:port

	if reflectors == "" { // 未指定 -reflect，无法得知自己的公网地址
		log.Fatal("-reflect is required in punch mode (run -mode=reflect on a public VPS first)") // 提示先去 VPS 上跑 reflect 模式
	}
	list := strings.Split(reflectors, ",") // 按逗号切分，得到反射服务器地址列表
	announced := classifyNAT(conn, list)   // 探测公网地址并判定 NAT 类型；返回值是“将告诉对端的那个地址”

	// NAT 可能在短短 30 秒后就回收一个空闲的 UDP 映射。而“把地址复制到另一台机器上”
	// 这个停顿很容易就超过 30 秒；一旦映射过期，你交给对端的地址就指向了一个不存在的
	// 端口，双方会朝着死端口无限打洞。所以这里要持续保活。
	stopKeepalive := startKeepalive(conn, list) // 启动后台保活协程，返回停止函数

	fmt.Fprintln(os.Stderr, "\nPaste the peer's public address (ip:port) and press Enter:") // 提示用户粘贴对端地址（走 stderr，避免污染 stdout 的结果）
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')                                 // 从标准输入读一整行
	if err != nil {
		log.Fatalf("read peer address: %v", err) // 读取失败（如 EOF），退出
	}
	peer, err := net.ResolveUDPAddr("udp4", strings.TrimSpace(line)) // 去掉首尾空白后解析成对端 UDP 地址
	if err != nil {
		log.Fatalf("parse peer address: %v", err) // 地址格式不对，退出
	}
	stopKeepalive()                               // 已经拿到对端地址，停止保活协程，避免它的回包干扰后面的收包判断
	verifyMappingUnchanged(conn, list, announced) // 重新问一次反射服务器，确认映射没漂移；漂移了就说明给对端的地址已经作废

	// 把第一个反射服务器作为“对端存活探针”的通道（后续会周期性向它发 STATUS 查询）
	statusVia, err := net.ResolveUDPAddr("udp4", strings.TrimSpace(list[0]))
	if err != nil {
		statusVia = nil // 解析失败就不做存活探测，退化为纯打洞
	}
	punch(conn, peer, statusVia, duration, interval) // 进入真正的打洞主循环
}

// startKeepalive 每 10 秒向每个反射服务器发一个 WHOAMI 包，
// 目的不是取地址，而是让 NAT 映射在你“把地址抄到另一台机器”的这段时间里保持存活。
// 这些探测的回包会堆积在 socket 缓冲区里没被读走 —— 这没关系：
// 打洞循环会按源地址过滤，而且复查映射前会调用 drainSocket 把它们清掉。
func startKeepalive(conn *net.UDPConn, reflectors []string) func() {
	stop := make(chan struct{}) // 用于通知后台协程停止
	var once sync.Once          // 保证 stop 通道只被关闭一次（重复 close 会 panic）
	go func() {                 // 启动后台协程
		ticker := time.NewTicker(10 * time.Second) // 每 10 秒触发一次
		defer ticker.Stop()                        // 协程退出时释放定时器
		for {                                      // 循环等待两个事件之一
			select {
			case <-stop: // 收到停止信号
				return // 协程结束
			case <-ticker.C: // 每 10 秒到点
				for _, r := range reflectors { // 遍历所有反射服务器
					addr, err := net.ResolveUDPAddr("udp4", strings.TrimSpace(r)) // 解析反射服务器地址
					if err != nil {
						continue // 解析失败就跳过这一个，不影响其它
					}
					_, _ = conn.WriteToUDP([]byte(whoamiMagic), addr) // 发一个 WHOAMI 包，只为刷新 NAT 映射；错误可忽略
				}
			}
		}
	}()
	return func() { once.Do(func() { close(stop) }) } // 返回一个幂等的停止函数
}

// verifyMappingUnchanged 重新问反射服务器“你现在看到的我是谁”，
// 如果和当初告诉对端的地址不一致就告警 —— 那种情况下对端正在打的地址已经失效，
// 必须重新交换地址，否则这次测试注定失败。
func verifyMappingUnchanged(conn *net.UDPConn, reflectors []string, announced string) {
	if announced == "" || len(reflectors) == 0 { // 当初没探测到地址，或没有反射服务器，无从对比
		return // 直接返回
	}
	addr, err := net.ResolveUDPAddr("udp4", strings.TrimSpace(reflectors[0])) // 用第一个反射服务器复查
	if err != nil {
		return // 地址都解析不了，放弃复查
	}
	drainSocket(conn)                                                     // 先把 socket 缓冲区里堆积的旧包（保活回包等）清空，避免读到陈旧应答
	if _, err := conn.WriteToUDP([]byte(whoamiMagic), addr); err != nil { // 发一个 WHOAMI 探测
		return // 发不出去（网络问题），放弃复查
	}
	now, ok := readReflectorReply(conn, addr, 3*time.Second) // 等最多 3 秒，读该反射服务器的回复
	if !ok {
		log.Printf("could not re-check mapping (reflector did not answer); continuing anyway") // 没回答就提示一下，但不阻断流程
		return
	}
	if now == announced { // 映射没变
		log.Printf("mapping still %s — the address your peer has is current", now) // 告诉用户对端手里的地址仍然有效
		return
	}
	// 映射变了：对端正在打的地址已经是个死端口
	log.Printf("WARNING: mapping changed %s -> %s. The address your peer is punching is DEAD; "+
		"re-exchange addresses (use the new one) or this test cannot succeed.", announced, now)
}

// drainSocket 丢弃 socket 缓冲区里已有的所有数据报，
// 保证紧接着的一次 read 拿到的是“新鲜”的应答，而不是某个过期的保活回包。
func drainSocket(conn *net.UDPConn) {
	buf := make([]byte, 1024) // 临时接收缓冲区
	for {                     // 一直读到超时（说明缓冲区空了）为止
		_ = conn.SetReadDeadline(time.Now().Add(150 * time.Millisecond)) // 设置 150ms 读超时
		if _, _, err := conn.ReadFromUDP(buf); err != nil {              // 读一个包；读不到（超时）即认为清空完毕
			_ = conn.SetReadDeadline(time.Time{}) // 把读截止时间清零，恢复为永久阻塞
			return                                // 结束
		}
		// 读到了就丢弃，继续下一轮
	}
}

// classifyNAT 用“同一个 socket”依次向每个反射服务器发探测包。
// 如果 NAT 无论目的地是谁都只分配同一个外部端口（endpoint-independent mapping，
// 即“锥形 / cone NAT”），那它就是可打洞的；如果每个目的地都换一个新端口
// （对称型 / symmetric），就打不通 —— 因为你告诉对端的那个端口，并不是它实际会看到的端口。
// 返回值是“将公布给对端的地址”（即第一个反射服务器看到的地址），
// 供调用方稍后检查映射是否发生了漂移。
func classifyNAT(conn *net.UDPConn, reflectors []string) string {
	var observed []string          // 收集每个反射服务器看到的我的公网地址
	for _, r := range reflectors { // 逐个探测
		r = strings.TrimSpace(r) // 去掉用户可能手滑加的空格
		if r == "" {             // 空项（比如多打了个逗号）跳过
			continue
		}
		addr, err := net.ResolveUDPAddr("udp4", r) // 解析反射服务器地址
		if err != nil {
			log.Printf("reflector %s: resolve: %v", r, err) // 只是这一个地址写错了，记录后继续
			continue
		}
		if _, err := conn.WriteToUDP([]byte(whoamiMagic), addr); err != nil { // 发出 WHOAMI 探测
			log.Printf("reflector %s: write: %v", r, err) // 发送失败（如本地无路由），记录后继续
			continue
		}
		// 只允许“该反射服务器自己的回包”被当作我的公网地址。
		// 对端很可能已经在对着我打洞了，而我正在探测；如果把它的包误当成应答，
		// 就会悄悄污染整个测试唯一依赖的那个关键值。
		seen, ok := readReflectorReply(conn, addr, 3*time.Second) // 只认来自 addr 的回包，最多等 3 秒
		if !ok {
			log.Printf("reflector %s: no reply — is it running, and is UDP open on that port?", r) // 常见原因：服务没起、云厂商安全组没放 UDP
			continue
		}
		log.Printf("reflector %s sees me as %s", r, seen) // 打印这个反射服务器眼中的我
		observed = append(observed, seen)                 // 记录下来，稍后比较
	}
	_ = conn.SetReadDeadline(time.Time{}) // 探测结束，清掉读截止时间

	switch { // 根据拿到的地址个数/内容下结论
	case len(observed) == 0: // 一个反射服务器都没回应
		log.Printf("NAT type: UNKNOWN — no reflector answered") // 无法判定
		return ""                                               // 返回空地址
	case len(observed) == 1: // 只有一个反射服务器
		fmt.Printf("\nYour public address: %s\n", observed[0])                                                         // 打印公网地址给用户复制给对端
		log.Printf("NAT type: UNKNOWN — need a second reflector on a DIFFERENT public IP to tell cone from symmetric") // 判定 cone/symmetric 必须比较两个不同目的地
	default: // 两个及以上
		fmt.Printf("\nYour public address: %s\n", observed[0]) // 公布第一个反射服务器看到的地址
		same := true                                           // 先假设所有观测一致
		for _, o := range observed[1:] {                       // 和第一个逐个比较
			if o != observed[0] {
				same = false // 出现不一致
				break        // 不用再比了
			}
		}
		if same {
			log.Printf("NAT type: CONE (endpoint-independent mapping) — same mapping toward every reflector, punchable") // 锥形 NAT：可打洞
		} else {
			// 对称型 NAT：每个目的地一个映射，打洞理论上是打不通的
			log.Printf("NAT type: SYMMETRIC — mapping changes per destination (%s), hole punching will not work here", strings.Join(observed, " vs "))
		}
	}
	return observed[0] // 返回要交给对端的那个地址
}

// readReflectorReply 等待“恰好来自指定反射服务器”的一个包，
// 期间落到 socket 上的其它来源的包全部跳过（比如对端提前开始打洞的包）。
func readReflectorReply(conn *net.UDPConn, reflector *net.UDPAddr, wait time.Duration) (string, bool) {
	buf := make([]byte, 1024)       // 接收缓冲区
	giveUp := time.Now().Add(wait)  // 计算出绝对超时时刻
	for time.Now().Before(giveUp) { // 只要还没到超时就继续尝试
		_ = conn.SetReadDeadline(giveUp)      // 用绝对时刻设读超时，多轮循环不会累积延长总等待
		n, from, err := conn.ReadFromUDP(buf) // 读一个包
		if err != nil {
			return "", false // 超时或出错，本次探测失败
		}
		if from.IP.Equal(reflector.IP) && from.Port == reflector.Port { // 来源 IP 与端口都对得上
			return string(buf[:n]), true // 这就是反射服务器的应答，返回其内容
		}
		log.Printf("ignoring packet from %s while probing reflector %s", from, reflector) // 来源不符，丢弃并记一行日志（通常就是对端的打洞包）
	}
	return "", false // 循环耗尽仍未拿到，失败
}

// punch 一边朝对端狂发包，一边监听对端发来的包。
// 双方必须在同一时间窗口内都在发包 —— 每一方发出的包，正是为自己 NAT 打开“回程通道”的动作，
// 所以对端才能进来。因此这里是“一直打到收到包为止”，而不是跑固定时长就停。
// “把两个终端对齐到秒级”是打洞明明能成功却被报成 FAILED 的头号原因。
// statusVia 非 nil 时，是一个反射服务器地址：每隔几秒问它一次“对端现在在打洞吗”，
// 这样一次 FAILED 结果就能被区分成“网络真的不通”和“对面根本没在跑”。
func punch(conn *net.UDPConn, peer *net.UDPAddr, statusVia *net.UDPAddr, duration, interval time.Duration) {
	if duration > 0 { // 指定了超时
		log.Printf("punching to %s, giving up after %s if nothing arrives", peer, duration) // 到点放弃
	} else {
		log.Printf("punching to %s until a packet arrives (Ctrl-C to stop)", peer) // 一直打，直到收到包或用户 Ctrl-C 中断
	}
	var received atomic.Int64      // 收到的“有效对端包”计数（跨 goroutine 安全）
	var peerSeenActive atomic.Bool // 反射服务器是否确认过对端正在打洞
	var staleReflector atomic.Bool // 反射服务器是否是老版本（不认识 STATUS）
	done := make(chan struct{})    // 通知接收协程退出
	success := make(chan struct{}) // 收到第一个对端包时关闭，主循环据此转入收尾

	go func() { // 接收协程：专职读包并分类
		buf := make([]byte, 1024) // 自己的缓冲区，避免和主循环共享
		for {                     // 持续读取
			_ = conn.SetReadDeadline(time.Now().Add(time.Second)) // 每次只等 1 秒，好让协程能及时响应 done
			n, from, err := conn.ReadFromUDP(buf)                 // 读一个包
			if err != nil {
				select {
				case <-done: // 主循环已经结束，是时候退出
					return
				default:
					continue // 只是 1 秒读超时，继续轮询
				}
			}
			// 只有来自“我们正在打的这个地址”的包才算数。
			// 其它来源（仍在途的反射服务器回包、无关流量）若被当作成功，就会误报。
			// 而“来自对端 IP 但端口不同”的包也值得单独点名：那正是对端侧存在对称型 NAT 的表现。
			switch {
			case from.IP.Equal(peer.IP) && from.Port == peer.Port: // 完全匹配：打洞成功的证据
				if received.Add(1) == 1 { // 原子加一，仅在“第一个包”时进入
					log.Printf("FIRST PACKET IN from %s: %q", from, string(buf[:n])) // 打印收到的第一个包内容
					close(success)                                                   // 通知主循环：成功了
				}
			// 这一条要排在下面“仅 IP 相同”的分支之前：当反射服务器和对端在同一 IP
			// （比如本地回环测试）时，与反射服务器的精确匹配是更具体的答案；
			// 把它的状态应答误读成“对端换了端口”，会是严重的误导。
			case statusVia != nil && from.IP.Equal(statusVia.IP) && from.Port == statusVia.Port: // 反射服务器的状态应答
				switch string(buf[:n]) { // 看它回的是什么
				case "ACTIVE":
					if !peerSeenActive.Swap(true) { // 只在第一次置位时打印，避免刷屏
						log.Printf("reflector confirms the peer is punching right now — both sides are live, so a failure here is a real network failure") // 双方都活着 → 失败就是真失败
					}
				case "IDLE":
					log.Printf("reflector has NOT heard from %s recently — the peer is probably not running; this round proves nothing", peer) // 对端没在跑，这一轮不作数
				default:
					// 老版本反射服务器对任何包都回源地址，于是它会把查询内容原样回显。
					// 明确说出来，别让它看起来像是“对端不存在”。
					if !staleReflector.Swap(true) { // 只提示一次
						log.Printf("this reflector does not understand STATUS (older build) — redeploy it on the VPS to get peer-liveness confirmation")
					}
				}
			case from.IP.Equal(peer.IP): // IP 相同但端口不同
				log.Printf("packet from peer IP but port %d, not the expected %d — their NAT remapped the port (symmetric behavior)", from.Port, peer.Port) // 对端 NAT 重映射了端口
			default: // 完全无关的来源
				log.Printf("ignoring packet from unrelated source %s", from) // 忽略并记录
			}
		}
	}()

	ticker := time.NewTicker(interval)          // 打洞发包节拍器：每 interval 发一个
	defer ticker.Stop()                         // 函数返回时停掉
	progress := time.NewTicker(5 * time.Second) // 进度日志节拍器：每 5 秒汇报一次
	defer progress.Stop()
	statusTick := time.NewTicker(3 * time.Second) // 存活查询节拍器：每 3 秒问一次反射服务器
	defer statusTick.Stop()
	deadline := time.Now().Add(duration) // 若指定了 duration，算出绝对截止时间
	started := time.Now()                // 记录起点，用于打印已耗时
	var sent int                         // 已发送包数
	var drainDeadline time.Time          // 成功后的“善后发送”截止时间，零值表示尚未成功
loop: // 带标签的循环，方便一次性 break 出来
	for { // 主循环：事件驱动
		select { // 同时等待多个通道事件
		case <-statusTick.C: // 每 3 秒
			if statusVia != nil { // 有可用的反射服务器
				_, _ = conn.WriteToUDP([]byte(statusPrefix+peer.String()), statusVia) // 发 "STATUS <peer ip:port>" 查询对端是否活跃
			}
		case <-success: // 收到对端第一个包
			// 不要立刻停：对端可能启动得晚一些，它还需要收到我们的包才能确认它自己那个方向的通路。
			// 这里把 success 置为 nil，让这个 case 不再触发（已 close 的通道会一直可读，会空转）。
			drainDeadline = time.Now().Add(2 * time.Second) // 再继续发 2 秒
			success = nil                                   // 关闭该 case 的触发
		case <-progress.C: // 每 5 秒汇报进度，让人知道程序没死
			log.Printf("still punching: sent=%d received=%d elapsed=%s", sent, received.Load(), time.Since(started).Truncate(time.Second))
		case <-ticker.C: // 到点发一个打洞包
			if !drainDeadline.IsZero() && time.Now().After(drainDeadline) { // 已经成功且善后期结束
				break loop // 跳出主循环
			}
			if duration > 0 && time.Now().After(deadline) { // 指定了超时且已超时
				break loop // 跳出主循环
			}
			msg := make([]byte, 16)                               // 构造 16 字节报文
			binary.BigEndian.PutUint64(msg, uint64(sent))         // 前 8 字节放发送序号（大端），便于对端观察丢包/乱序
			copy(msg[8:], "PUNCH")                                // 后 8 字节放固定标识 "PUNCH"
			if _, err := conn.WriteToUDP(msg, peer); err != nil { // 朝对端公网地址发送
				log.Printf("send: %v", err) // 发送失败只记录（比如本地网络临时不可用）
			}
			sent++ // 发送计数加一
		}
	}
	close(done)                        // 通知接收协程退出
	time.Sleep(100 * time.Millisecond) // 给它一点时间收尾，避免和下面的统计竞争

	got := received.Load() // 读取最终收到的有效包数
	fmt.Printf(`
=== punch result ===
sent:       %d
received:   %d
peer live:  %s
verdict:    %s
`, sent, got, peerLive(got, peerSeenActive.Load(), staleReflector.Load(), statusVia), verdict(got, peerSeenActive.Load())) // 打印最终结论
}

// peerLive 回答“对端当时到底活着吗”，用于区分“打不通”和“对面没跑”。
func peerLive(received int64, seenActive, staleReflector bool, statusVia *net.UDPAddr) string {
	switch {
	// 它的包真的到了，这是最强的存活证据，优先于反射服务器的任何意见 ——
	// 打洞可能快到第一次状态查询都还没发出去就成功了。
	case received > 0:
		return "yes — its packets arrived here" // 是：它的包到了我这
	case statusVia == nil: // 没有反射服务器可问
		return "unknown (no reflector to ask)" // 未知
	case seenActive: // 反射服务器确认过
		return "yes — reflector saw the peer punching during this run" // 是：反射服务器看到它在打洞
	case staleReflector: // 反射服务器是老版本，不支持 STATUS
		return "unknown — the reflector is an older build with no STATUS support; redeploy it" // 未知，建议重新部署
	default: // 反射服务器一直没见过对端
		return "NO — reflector never saw the peer; it likely was not running" // 否：大概率对面没在跑
	}
}

// verdict 给出最终判定。
func verdict(received int64, peerSeenActive bool) string {
	switch {
	case received > 0: // 收到了对端的包
		return "SUCCESS — a direct UDP path exists between these two hosts" // 成功：两台主机间存在直连 UDP 通路
	case peerSeenActive: // 对端确认在跑，但一个包都没到
		return "FAILED — the peer was confirmed live and still nothing arrived. " +
			"Direct UDP between these two networks is genuinely blocked (ISP/CGNAT filtering, " +
			"or a NAT that does not behave as the type test suggests)" // 真失败：运营商/CGNAT 过滤，或 NAT 行为与类型测试结论不符
	default: // 没收到包，也没证据表明对端在跑
		return "INCONCLUSIVE — no packet arrived, but the peer was never seen to be running. " +
			"Start both sides so they overlap, then judge the result" // 不确定：让两端时间重叠后再判断
	}
}
