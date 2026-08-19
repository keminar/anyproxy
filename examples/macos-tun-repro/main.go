//go:build darwin

// macos-tun-repro 最小复现: macOS TUN 模式下 anyproxy 自身出向的逃逸问题。
//
// 背景: macOS 上 TUN(utun) + 0.0.0.0/1 + 128.0.0.0/1 全量路由接管流量后,
// anyproxy 自己的直连出向(tunDial)靠「绑物理网卡 IP + IP_BOUND_IF」逃逸
// (见 proto/dialer_darwin.go)。实测出现:
//
//	dial tcp <物理IP>:0 -> 目标:443 :connect: no route to host
//
// 本脚本在真机/CI(macOS)上重建该环境, 对每个目标跑四个场景:
//
//	[A] plain dial(不绑)                —— 预期被 0/1 吸进 utun 而超时
//	[D] 只绑源 IP(无 IP_BOUND_IF)       —— 区分 IP_BOUND_IF 是否生效
//	[B] 绑源 IP + IP_BOUND_IF(tunDial 现状) —— 验证是否复现 no route to host
//	[C] 先加 /32 via 物理网关 例外再拨号  —— 验证「动态 /32 例外」修复方案
//
// 用法: sudo go run ./examples/macos-tun-repro   (需 root 创建 utun/改路由)
package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"

	"github.com/keminar/anyproxy/tun"
)

// 测试目标: 先公网必达的 1.1.1.1, 再用户现场的目标(企微服务器)
var targets = []string{"1.1.1.1:443", "183.47.99.22:443"}

func main() {
	if err := run(); err != nil {
		log.Fatalf("FATAL: %v", err)
	}
	// [F] fake-ip 分流场景在主流程清理(0/1 路由删除、utun 关闭)后独立跑:
	// 需要"TUN 只接管 fake-ip 网段"的干净环境。
	probeFakeIP()
	fmt.Println("== done ==")
}

func run() error {
	gw, phyDev := defaultRoute()
	phyIP := ifaceIPv4(phyDev)
	idx := ifaceIndex(phyDev)
	fmt.Printf("== env: phyDev=%q phyIP=%q gw=%q ifIndex=%d ==\n", phyDev, phyIP, gw, idx)
	if phyIP == "" || gw == "" || idx <= 0 {
		return fmt.Errorf("cannot detect physical iface (dev=%q ip=%q gw=%q idx=%d)", phyDev, phyIP, gw, idx)
	}

	d, err := tun.New("", 1500)
	if err != nil {
		return fmt.Errorf("create tun: %w", err)
	}
	defer d.Close()
	if err := d.SetupAddr("10.9.0.1/24"); err != nil {
		return fmt.Errorf("setup tun addr: %w", err)
	}
	tunName := d.Name()
	fmt.Printf("== tun device: %s ==\n", tunName)

	// 保住 runner/本机现有连接: 把当前 ESTABLISHED TCP 对端 IP 全部加 /32 例外,
	// 否则 0/1 路由会吸走它们(CI 上会断掉 runner 自身连接导致任务失败)。
	var kept []string
	for _, ip := range establishedIPv4s() {
		if err := routeAdd32(ip, gw); err != nil {
			fmt.Printf("keep-alive route %s: %v\n", ip, err)
		} else {
			kept = append(kept, ip)
		}
	}
	fmt.Printf("== kept %d established peer routes ==\n", len(kept))
	defer func() {
		for _, ip := range kept {
			_ = routeDel32(ip, gw)
		}
	}()

	if err := routeCmd("-n", "add", "-net", "0.0.0.0/1", "-interface", tunName); err != nil {
		return fmt.Errorf("add 0/1 route: %w", err)
	}
	if err := routeCmd("-n", "add", "-net", "128.0.0.0/1", "-interface", tunName); err != nil {
		return fmt.Errorf("add 128/1 route: %w", err)
	}
	defer func() {
		_ = routeCmd("-n", "delete", "-net", "0.0.0.0/1")
		_ = routeCmd("-n", "delete", "-net", "128.0.0.0/1")
	}()

	for _, target := range targets {
		fmt.Printf("\n######## target %s ########\n", target)
		fmt.Println("[A] plain dial (no bind)")
		printDial(plainDial(target, 3*time.Second))

		fmt.Println("[D] bind src only (no IP_BOUND_IF)")
		printDial(boundDial(target, phyIP, -1, 3*time.Second))

		fmt.Printf("[B] bind src %s + IP_BOUND_IF ifIndex=%d (tunDial as-is)\n", phyIP, idx)
		printDial(boundDial(target, phyIP, idx, 3*time.Second))

		tip := host(target)
		// [C] 修复后 tunDial 的完整生命周期: 加 /32 例外 -> 拨号 -> 关连接 -> 删路由
		//     并验证路由确实被删(否则「访问过的目标永久直连、绕过代理」的副作用)
		fmt.Printf("[C] dynroute lifecycle: add /32 %s via %s -> dial -> close -> del -> verify\n", tip, gw)
		if err := routeCmd("-n", "add", "-net", tip+"/32", gw); err != nil {
			fmt.Printf("    (add /32 failed: %v)\n", err)
		} else {
			conn, err := plainDial(target, 3*time.Second)
			printDial(conn, err)
			if conn != nil {
				conn.Close()
				fmt.Println("    (connection closed)")
			}
			if err := routeCmd("-n", "delete", "-net", tip+"/32"); err != nil {
				fmt.Printf("    (del /32 failed: %v)\n", err)
			}
			if routeExists(tip) {
				fmt.Printf("    -> FAIL: /32 %s still present after close (permanent direct!)\n", tip)
			} else {
				fmt.Printf("    -> OK: /32 %s removed after close (no permanent direct)\n", tip)
			}
		}
	}

	// [U] UDP 逃逸验证(修复对象是 DNS): 对照普通拨号 / 旧 IP_BOUND_IF 方式 /
	//     加 /32 例外, 各发一次 DNS 查询。
	fmt.Println("\n######## UDP: DNS query to 1.1.1.1:53 ########")
	probeUDPDNS(gw, phyIP, idx)

	// [P] pf route-to + egress 源端口段(方案 7): 0/1 路由仍存在时, 验证
	//     pf 规则能否按源端口段强制出向走物理网卡(压过 0/1)。
	probePFRouteTo(gw, phyDev, phyIP)

	// [P2] 方案一(pf 透明重定向)的其余猜测: rdr 语法 / user-group 自排除 /
	//      本机自产流量能否被 rdr 捕获 / DIOCNATLOOK 还原原始目的。
	probePFScheme1(gw, phyDev)
	return nil
}

// [P] 方案 7: pf route-to + egress 源端口段。
// 原理: anyproxy 出向绑定专用源端口段(40001-49151), pf 规则
//   pass out proto {tcp udp} from any port 40001:49151 route-to (en0 网关)
// 在包转发层强制该段连接走物理网卡, 优先级高于路由表(0/1 → utun)。
// 验证: P-a 不绑端口 → 被 0/1 吸走失败; P-b 绑 egress 段端口 → route-to 生效成功。
func probePFRouteTo(gw, phyDev, phyIP string) {
	const egressLo, egressHi = 40001, 49151

	fmt.Println("\n######## [P] pf route-to + egress source-port band ########")

	// 1. 加载 pf。规则顺序关键:
	//    - pf filter 是 first-match: route-to 规则必须在 pass all 之前, 否则永远匹配不到
	//    - macOS pf 语法: route-to 紧跟 `pass out` 之后; 文件末尾必须空行
	conf := fmt.Sprintf(
		"pass out route-to (%s %s) proto tcp from any port %d:%d to any\n"+
			"pass out route-to (%s %s) proto udp from any port %d:%d to any\n"+
			"pass all\n\n",
		phyDev, gw, egressLo, egressHi, phyDev, gw, egressLo, egressHi)
	f, err := os.CreateTemp("", "anyproxy-pf-*.conf")
	if err != nil {
		fmt.Printf("    (create pf conf: %v)\n", err)
		return
	}
	path := f.Name()
	if _, err := f.WriteString(conf); err != nil {
		f.Close()
		os.Remove(path)
		fmt.Printf("    (write pf conf: %v)\n", err)
		return
	}
	f.Close()
	defer os.Remove(path)

	fmt.Printf("    pfctl -ef: %s\n", strings.ReplaceAll(strings.TrimSpace(conf), "\n", " | "))
	if out, err := exec.Command("pfctl", "-ef", path).CombinedOutput(); err != nil {
		fmt.Printf("    (pfctl load failed: %v: %s)\n", err, strings.TrimSpace(string(out)))
		return
	}
	// 恢复默认 pf(清规则 + 重载 /etc/pf.conf)
	defer func() {
		_ = exec.Command("pfctl", "-F", "all").Run()
		_ = exec.Command("pfctl", "-f", "/etc/pf.conf").Run()
	}()

	// 2. P-a 普通拨号(不绑 egress 端口) → 预期被 0/1 吸走而失败
	fmt.Println("[P-a] plain dial 1.1.1.1:443 (no egress port bind)")
	printDial(plainDial("1.1.1.1:443", 3*time.Second))

	// 3. P-b 绑「物理网卡 IP + egress 段源端口」拨号 → 预期 pf route-to 强制物理网卡 → 成功。
	//    必须绑物理 IP: route-to 不改源地址, 若源 IP 是 utun 的 10.9.0.1, 回包会被 0/1 吸回。
	fmt.Printf("[P-b] dial 1.1.1.1:443 with src %s:%d (phy IP + egress band, pf route-to)\n", phyIP, egressLo)
	printDial(boundSrcDial("1.1.1.1:443", phyIP, egressLo, 3*time.Second))
}

// boundSrcDial 绑物理网卡 IP + 源端口拨号——pf route-to 按源端口段匹配,
// 且源 IP 为物理 IP 时回包才能回到物理网卡(route-to 不改源地址)。
func boundSrcDial(target, srcIP string, port int, timeout time.Duration) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout, LocalAddr: &net.TCPAddr{IP: net.ParseIP(srcIP), Port: port}}
	return d.Dial("tcp", target)
}

// [P2] 方案一(pf 透明重定向)其余猜测的真机验证。
// 文字评估里对「pf rdr + 源端口段」这套方案给过几条判断, 这里逐条落到真机上验证:
//
//	猜测① macOS pf 支持 rdr(把连接重定向到本地监听端口)  —— pfctl 能否接受该语法
//	猜测② 可用 user/group 匹配排除自身出向(比源端口段更干净) —— macOS 这支 pf 是否保留该 token
//	猜测③ 取原始目的地址要对 /dev/pf 发 DIOCNATLOOK ioctl(不像 Linux 的 SO_ORIGINAL_DST)
//	猜测④ rdr 只作用于「入接口」的包; 本机自产的出向流量不经入接口, 故 rdr 难以直接捕获(fiddly)
//
// ①② 用 `pfctl -n -f`(只解析不加载)判定, 零风险且结论确定;
// ③④ 用「本地监听 + rdr + DIOCNATLOOK」端到端实测。
func probePFScheme1(gw, phyDev string) {
	fmt.Println("\n######## [P2] pf scheme-1 (transparent redirect) assumptions ########")

	// --- 猜测①②: 仅解析(pfctl -n -f), 不加载, 安全 ---
	uid, gid := os.Getuid(), os.Getgid()
	syntaxChecks := []struct{ name, rules string }{
		{"① rdr redirect -> local port",
			"rdr pass on lo0 inet proto tcp from any to 192.0.2.1 port 9443 -> 127.0.0.1 port 3129"},
		{"② user match (self-exclude by uid)",
			fmt.Sprintf("pass out proto tcp from any to any user %d", uid)},
		{"② group match (self-exclude by gid)",
			fmt.Sprintf("pass out proto tcp from any to any group %d", gid)},
		{"② route-to composed with user !=",
			fmt.Sprintf("pass out route-to (%s %s) proto tcp from any to any user != %d", phyDev, gw, uid)},
		{"  route-to by source-port band (sanity)",
			fmt.Sprintf("pass out route-to (%s %s) proto tcp from any port 40001:49151 to any", phyDev, gw)},
	}
	for _, c := range syntaxChecks {
		if ok, msg := pfctlParseOK(c.rules); ok {
			fmt.Printf("  [OK]   %s: pfctl accepts syntax\n", c.name)
		} else {
			fmt.Printf("  [FAIL] %s: %s\n", c.name, msg)
		}
	}

	// --- 猜测③④: 本机自产流量 rdr 到本地监听 + DIOCNATLOOK 还原原始目的 ---
	probePFRedirectE2E()
}

// pfctlParseOK 用 `pfctl -n -f`(仅解析、不加载)判定规则语法是否被当前内核的 pf 接受。
func pfctlParseOK(rules string) (bool, string) {
	f, err := os.CreateTemp("", "anyproxy-pfsyntax-*.conf")
	if err != nil {
		return false, err.Error()
	}
	path := f.Name()
	defer os.Remove(path)
	_, _ = f.WriteString(rules + "\n") // pfctl 要求文件以换行结尾
	_ = f.Close()
	out, err := exec.Command("pfctl", "-n", "-f", path).CombinedOutput()
	return err == nil, strings.TrimSpace(string(out))
}

// probePFRedirectE2E 端到端验证猜测③④:
// 本机进程拨向 192.0.2.1:9443(RFC5737 TEST-NET-1, 必定无真实主机/无路由), 试图让
// pf rdr 把它重定向到本地监听, 再用 DIOCNATLOOK 还原原始目的地址。
//
//	接受到连接 => 方案一「透明重定向」对本机流量在 macOS 可行, 且 DIOCNATLOOK 能取回原目的;
//	始终收不到 => 印证猜测④(本机自产流量不经入接口, rdr 抓不到), 方案一对本机代理不实用,
//	              只能退回 route-to(已在 [P] 验证) 或直接用 TUN。
func probePFRedirectE2E() {
	fmt.Println("[P2-e2e] host-local dial -> pf rdr -> local listener + DIOCNATLOOK")
	const testDst = "192.0.2.1" // RFC5737 TEST-NET-1
	const testPort = 9443

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Printf("    (listen: %v)\n", err)
		return
	}
	defer ln.Close()
	lport := ln.Addr().(*net.TCPAddr).Port

	// rdr 命中「到 testDst」的包 -> 本地监听; 并用 route-to 把本机出向该目的的包先送到 lo0,
	// 因为本机自产流量默认不经任何入接口, 不 route-to 到 lo0 就没有「入 lo0」这一步供 rdr 命中。
	// 这一步正是猜测④要验证的 fiddly 之处。
	rules := fmt.Sprintf(
		"rdr pass on lo0 inet proto tcp from any to %s port %d -> 127.0.0.1 port %d\n"+
			"pass out route-to (lo0 127.0.0.1) inet proto tcp from any to %s port %d\n\n",
		testDst, testPort, lport, testDst, testPort)
	if ok, msg := pfctlLoad(rules); !ok {
		fmt.Printf("    -> INCONCLUSIVE: pf load failed: %s\n", msg)
		return
	}
	defer pfRestore()

	// 后台 accept
	type accepted struct {
		conn net.Conn
		err  error
	}
	ch := make(chan accepted, 1)
	go func() {
		c, e := ln.Accept()
		ch <- accepted{c, e}
	}()
	// 后台拨号(命中 rdr 则连到本地监听; 未命中则无路由/超时失败)
	go func() {
		c, e := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", testDst, testPort), 3*time.Second)
		if e == nil {
			time.AfterFunc(2*time.Second, func() { _ = c.Close() })
		}
	}()

	select {
	case a := <-ch:
		if a.err != nil {
			fmt.Printf("    -> FAIL: accept: %v\n", a.err)
			return
		}
		defer a.conn.Close()
		fmt.Printf("    -> OK: rdr works, listener accepted from %v (local %v)\n",
			a.conn.RemoteAddr(), a.conn.LocalAddr())
		// 猜测③: DIOCNATLOOK 还原原始目的
		cAddr := a.conn.RemoteAddr().(*net.TCPAddr)
		lAddr := a.conn.LocalAddr().(*net.TCPAddr)
		rdIP, rdPort, err := pfNatLook(cAddr.IP, cAddr.Port, lAddr.IP, lAddr.Port)
		if err != nil {
			fmt.Printf("    -> DIOCNATLOOK FAIL: %v (struct/ioctl 需按机型微调)\n", err)
			return
		}
		if rdIP.String() == testDst && rdPort == testPort {
			fmt.Printf("    -> DIOCNATLOOK OK: recovered original dst %s:%d (matches!)\n", rdIP, rdPort)
		} else {
			fmt.Printf("    -> DIOCNATLOOK got %s:%d (expected %s:%d)\n", rdIP, rdPort, testDst, testPort)
		}
	case <-time.After(4 * time.Second):
		fmt.Println("    -> FAIL: listener never accepted (rdr did NOT capture host-local traffic)")
		fmt.Println("       => 印证猜测④: 本机自产出向流量不经入接口, pf rdr 抓不到;")
		fmt.Println("          方案一对本机代理不实用, 应退回 route-to([P]) 或直接用 TUN。")
	}
}

// pfctlLoad 加载一段 pf 规则(启用 pf 并覆盖当前规则集)。
// pf 已被前面场景启用时(-ef 报 "pf already enabled"), 降级为 -f 仅加载规则。
func pfctlLoad(rules string) (bool, string) {
	f, err := os.CreateTemp("", "anyproxy-pfload-*.conf")
	if err != nil {
		return false, err.Error()
	}
	path := f.Name()
	_, _ = f.WriteString(rules)
	_ = f.Close()
	defer os.Remove(path)

	out, err := exec.Command("pfctl", "-ef", path).CombinedOutput()
	if err == nil {
		return true, strings.TrimSpace(string(out))
	}
	if strings.Contains(string(out), "already enabled") {
		// pf 已启用(前面场景启用过): 降级 -f 仅加载规则覆盖当前规则集
		out2, err2 := exec.Command("pfctl", "-f", path).CombinedOutput()
		return err2 == nil, strings.TrimSpace(string(out2))
	}
	return false, strings.TrimSpace(string(out))
}

// pfRestore 清空 pf 规则并重载系统默认 /etc/pf.conf。
func pfRestore() {
	_ = exec.Command("pfctl", "-F", "all").Run()
	_ = exec.Command("pfctl", "-f", "/etc/pf.conf").Run()
}

// --- DIOCNATLOOK: 向 /dev/pf 查询 rdr/NAT 状态, 取回原始目的地址 ---
//
// macOS 的 pf(Apple 移植自 OpenBSD 4.x)其 pfioc_natlook 与 OpenBSD 版不同:
// 端口字段是 4 字节的 union pf_state_xport(含 u_int32_t spi), 且多一个 proto_variant,
// 整个结构体共 84 字节。这里按 Apple 版布局填充。

type pfAddr [16]byte  // union pf_addr, IPv4 放前 4 字节
type pfXport [4]byte  // union pf_state_xport, port 放前 2 字节(网络序)

type pfiocNatlook struct {
	saddr        pfAddr
	daddr        pfAddr
	rsaddr       pfAddr
	rdaddr       pfAddr
	sxport       pfXport
	dxport       pfXport
	rsxport      pfXport
	rdxport      pfXport
	af           uint8
	proto        uint8
	protoVariant uint8
	direction    uint8
}

const (
	pfDirOut    = 2 // PF_OUT
	afInet      = 2 // AF_INET
	ipprotoTCP6 = 6 // IPPROTO_TCP
)

func setPfAddr(a *pfAddr, ip net.IP) {
	if v4 := ip.To4(); v4 != nil {
		copy(a[:4], v4)
	}
}
func setPfPort(x *pfXport, port int) {
	x[0] = byte(port >> 8)
	x[1] = byte(port)
}
func getPfPort(x pfXport) int { return int(x[0])<<8 | int(x[1]) }

// iowr 复算 BSD 的 _IOWR(group, num, size) ioctl 号。用运行时 sizeof 计算长度,
// 避免手算结构体大小出错导致 ioctl 号不匹配。
func iowr(group byte, num uint8, size uintptr) uint {
	const iocInout = 0xC0000000
	const iocparmMask = 0x1fff
	return iocInout | (uint(size&iocparmMask) << 16) | (uint(group) << 8) | uint(num)
}

// pfNatLook 用 (client 源, 本地目的, PF_OUT) 查询 pf 状态表, 返回 rdr 之前的原始目的。
func pfNatLook(clientIP net.IP, clientPort int, localIP net.IP, localPort int) (net.IP, int, error) {
	fd, err := unix.Open("/dev/pf", unix.O_RDWR, 0)
	if err != nil {
		return nil, 0, fmt.Errorf("open /dev/pf: %w", err)
	}
	defer unix.Close(fd)

	var nl pfiocNatlook
	setPfAddr(&nl.saddr, clientIP)
	setPfAddr(&nl.daddr, localIP)
	setPfPort(&nl.sxport, clientPort)
	setPfPort(&nl.dxport, localPort)
	nl.af = afInet
	nl.proto = ipprotoTCP6
	nl.direction = pfDirOut

	num := iowr('D', 23, unsafe.Sizeof(nl)) // _IOWR('D', 23, struct pfioc_natlook)
	if _, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(fd), uintptr(num), uintptr(unsafe.Pointer(&nl))); errno != 0 {
		return nil, 0, fmt.Errorf("ioctl DIOCNATLOOK: %v", errno)
	}
	return net.IP(nl.rdaddr[:4]).To4(), getPfPort(nl.rdxport), nil
}

// [F] 方案 5: fake-ip 分流式 TUN。
// 原理: TUN 只接管 fake-ip 网段(198.18.0.0/15), 不加 0/1 全量路由; 真实 IP
// 流量走默认路由(物理网卡)。anyproxy 自身出向目标永远是真 IP → 天然逃逸,
// 不需要任何逃逸机制。
// 验证: F-a 真实 IP 拨号 → 不在接管集 → 走物理网卡成功(天然逃逸);
//       F-b fake-ip 网段拨号 → 命中接管集 → 被 TUN 捕获超时。
func probeFakeIP() {
	fmt.Println("\n######## [F] fake-ip style: TUN only takes 198.18.0.0/15 ########")

	d, err := tun.New("", 1500)
	if err != nil {
		fmt.Printf("    (create tun: %v)\n", err)
		return
	}
	defer d.Close()
	if err := d.SetupAddr("10.9.0.1/24"); err != nil {
		fmt.Printf("    (setup addr: %v)\n", err)
		return
	}
	if err := routeCmd("-n", "add", "-net", "198.18.0.0/15", "-interface", d.Name()); err != nil {
		fmt.Printf("    (add 198.18/15 route: %v)\n", err)
		return
	}
	defer func() { _ = routeCmd("-n", "delete", "-net", "198.18.0.0/15") }()

	fmt.Println("[F-a] real-IP dial 1.1.1.1:443 (outside fake-ip range -> default route, natural escape)")
	printDial(plainDial("1.1.1.1:443", 3*time.Second))

	fmt.Println("[F-b] fake-ip dial 198.18.0.1:443 (inside fake-ip range -> captured by TUN)")
	printDial(plainDial("198.18.0.1:443", 3*time.Second))
}

// probeUDPDNS 对照验证 UDP 逃逸:
//   U-a 普通 UDP(无绑定)          —— 预期超时(被 0/1 吸进 utun)
//   U-b 绑源 IP + IP_BOUND_IF(旧 listenUDP) —— 预期失败(IP_BOUND_IF 压不过 0/1)
//   U-c 加 /32 例外后普通 UDP      —— 预期收到 DNS 响应(修复验证)
func probeUDPDNS(gw, phyIP string, ifIdx int) {
	const dnsIP = "1.1.1.1"
	const dnsPort = "53"

	fmt.Println("[U-a] UDP DNS query, plain (no bind)")
	if _, err := udpDNSQuery(dnsIP, dnsPort, 3*time.Second); err != nil {
		fmt.Printf("    -> FAIL (as expected without exception): %v\n", err)
	} else {
		fmt.Println("    -> OK?! (unexpected without exception)")
	}

	fmt.Printf("[U-d] UDP DNS query, bind src %s only (no IP_BOUND_IF)\n", phyIP)
	if n, err := udpBoundQuery(phyIP, -1, dnsIP, dnsPort, 3*time.Second); err != nil {
		fmt.Printf("    -> FAIL (bind src only loses to 0/1, as expected): %v\n", err)
	} else {
		fmt.Printf("    -> OK?! (unexpected, got %d bytes)\n", n)
	}

	fmt.Printf("[U-b] UDP DNS query, bind src %s + IP_BOUND_IF ifIndex=%d (old listenUDP)\n", phyIP, ifIdx)
	if n, err := udpBoundQuery(phyIP, ifIdx, dnsIP, dnsPort, 3*time.Second); err != nil {
		fmt.Printf("    -> FAIL (IP_BOUND_IF loses to 0/1, as expected): %v\n", err)
	} else {
		fmt.Printf("    -> OK?! (unexpected, got %d bytes)\n", n)
	}

	fmt.Printf("[U-c] add /32 %s via %s, then plain UDP DNS query\n", dnsIP, gw)
	if err := routeCmd("-n", "add", "-net", dnsIP+"/32", gw); err != nil {
		fmt.Printf("    (add /32 failed: %v)\n", err)
		return
	}
	if n, err := udpDNSQuery(dnsIP, dnsPort, 3*time.Second); err != nil {
		fmt.Printf("    -> FAIL: %v\n", err)
	} else {
		fmt.Printf("    -> OK: got %d-byte DNS reply (UDP escape fixed)\n", n)
	}
	_ = routeCmd("-n", "delete", "-net", dnsIP+"/32")
}

// udpBoundQuery 用「未连接 UDP socket + 绑物理 IP + IP_BOUND_IF」(旧 listenUDP 方式)
// 发 DNS 查询, 返回响应字节数。用于对照验证 IP_BOUND_IF 对 UDP 同样失效。
func udpBoundQuery(phyIP string, ifIdx int, dnsIP, dnsPort string, timeout time.Duration) (int, error) {
	lc := &net.ListenConfig{}
	if ifIdx > 0 {
		lc.Control = func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, ifIdx)
			}); err != nil {
				return err
			}
			return serr
		}
	}
	pc, err := lc.ListenPacket(context.Background(), "udp4", net.JoinHostPort(phyIP, "0"))
	if err != nil {
		return 0, err
	}
	conn := pc.(*net.UDPConn)
	defer conn.Close()
	raddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(dnsIP, dnsPort))
	if err != nil {
		return 0, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.WriteToUDP(dnsQueryBytes(), raddr); err != nil {
		return 0, err
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// udpDNSQuery 发一个最小 DNS A 查询, 返回收到的响应字节数。
func udpDNSQuery(dnsIP, dnsPort string, timeout time.Duration) (int, error) {
	raddr, err := net.ResolveUDPAddr("udp4", net.JoinHostPort(dnsIP, dnsPort))
	if err != nil {
		return 0, err
	}
	conn, err := net.DialUDP("udp4", nil, raddr)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(dnsQueryBytes()); err != nil {
		return 0, err
	}
	buf := make([]byte, 512)
	n, err := conn.Read(buf)
	if err != nil {
		return 0, err
	}
	return n, nil
}

// dnsQueryBytes 最小 DNS 查询: ID=0x1234, RD, QDCOUNT=1, qname "abc" A IN
func dnsQueryBytes() []byte {
	return []byte{
		0x12, 0x34, 0x01, 0x00,
		0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x01, 'a', 0x01, 'b', 0x01, 'c', 0x00,
		0x00, 0x01, 0x00, 0x01,
	}
}

func printDial(conn net.Conn, err error) {
	if err != nil {
		fmt.Printf("    -> FAIL: %v\n", err)
		return
	}
	defer conn.Close()
	fmt.Printf("    -> OK: connected, local=%v\n", conn.LocalAddr())
}

func plainDial(target string, timeout time.Duration) (net.Conn, error) {
	return net.DialTimeout("tcp", target, timeout)
}

// boundDial 绑源 IP, idx>0 时额外设 IP_BOUND_IF(模拟 proto/dialer_darwin.go 的 tunDial)
func boundDial(target, srcIP string, idx int, timeout time.Duration) (net.Conn, error) {
	d := &net.Dialer{Timeout: timeout, LocalAddr: &net.TCPAddr{IP: net.ParseIP(srcIP)}}
	if idx > 0 {
		d.Control = func(_, _ string, c syscall.RawConn) error {
			var serr error
			if err := c.Control(func(fd uintptr) {
				serr = unix.SetsockoptInt(int(fd), unix.IPPROTO_IP, unix.IP_BOUND_IF, idx)
			}); err != nil {
				return err
			}
			return serr
		}
	}
	return d.Dial("tcp", target)
}

func host(addrport string) string {
	h, _, err := net.SplitHostPort(addrport)
	if err != nil {
		return strings.Trim(addrport, "[]")
	}
	return h
}

// defaultRoute 解析 `route -n get default` 的 gateway/interface
func defaultRoute() (gw, dev string) {
	out, err := exec.Command("route", "-n", "get", "default").Output()
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(out), "\n") {
		f := strings.Fields(line)
		if len(f) < 2 {
			continue
		}
		switch f[0] {
		case "gateway:":
			gw = f[1]
		case "interface:":
			dev = f[1]
		}
	}
	return
}

func ifaceIPv4(name string) string {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return ""
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	for _, a := range addrs {
		if ipnet, ok := a.(*net.IPNet); ok {
			if ip4 := ipnet.IP.To4(); ip4 != nil {
				return ip4.String()
			}
		}
	}
	return ""
}

func ifaceIndex(name string) int {
	iface, err := net.InterfaceByName(name)
	if err != nil {
		return -1
	}
	return iface.Index
}

func routeCmd(args ...string) error {
	out, err := exec.Command("route", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("route %v: %v: %s", args, err, strings.TrimSpace(string(out)))
	}
	return nil
}

func routeAdd32(ip, gw string) error { return routeCmd("-n", "add", "-net", ip+"/32", gw) }
func routeDel32(ip, gw string) error { return routeCmd("-n", "delete", "-net", ip+"/32", gw) }

// routeExists 检查 netstat 路由表里是否还存在该 /32。
func routeExists(ip string) bool {
	out, err := exec.Command("netstat", "-rn").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), ip+"/32")
}

// establishedIPv4s 收集当前 ESTABLISHED TCP 连接的对端 IPv4。
// macOS netstat 输出形如: tcp4 0 0 192.168.1.10.50000 20.205.243.166.443 ESTABLISHED
func establishedIPv4s() []string {
	out, err := exec.Command("netstat", "-an", "-p", "tcp").Output()
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	var ips []string
	for _, line := range strings.Split(string(out), "\n") {
		if !strings.Contains(line, "ESTABLISHED") {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		foreign := f[len(f)-2] // 倒数第二列是 Foreign Address
		if i := strings.LastIndex(foreign, "."); i > 0 {
			ip := net.ParseIP(foreign[:i])
			if ip == nil || ip.To4() == nil {
				continue
			}
			s := ip.String()
			if !seen[s] {
				seen[s] = true
				ips = append(ips, s)
			}
		}
	}
	return ips
}
