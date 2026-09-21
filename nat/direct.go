package nat

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/keminar/anyproxy/config"
	"github.com/keminar/anyproxy/utils/conf"
	quic "github.com/quic-go/quic-go"
)

const (
	// directOfferWait 等服务端回 offer 的上限。信令走已建立的 websocket, 正常是毫秒级。
	directOfferWait = 10 * time.Second
	// directDialWait QUIC 拨号上限。要盖住"C 收到 punch -> 打洞包出去 -> 防火墙开洞"这段,
	// 但不能太长: 直连失败时按约定直接失败, 拖着只会让入口连接干等。
	directDialWait = 8 * time.Second
	// directPunchCount / directPunchGap 朝每个候选连发几个打洞包、发包间隔。
	// 间隔只是 pacing(覆盖突发丢包), 不是等待窗口 —— 等待窗口是 directPunchWait。
	directPunchCount = 6
	directPunchGap   = 150 * time.Millisecond
	// directPunchWait 单个候选打洞的总等待预算。必须明显大于链路 RTT: pong 要走完
	// 去程+回程。早期版本按 150ms/包做等待窗, 在 RTT>150ms 的链路上(跨省/跨境的
	// 常态)每个 pong 都会迟到几毫秒, 打洞在数学上永远失败 —— 实测 RTT 153ms 的
	// 国际链路, 6 轮全部差 3~6ms 超时, 而 tcpdump 显示双向包都健康到达。
	// 取 3s: 覆盖 RTT ~1s 的链路, 并给 order Y 下"接受方等 nudge/兜底后才打"留出重叠余量
	// (发起方的打洞窗口要盖住接受方开打的那一刻)。成功路径不受影响(健康链路 pong 毫秒级
	// 就到, 早早返回)。
	directPunchWait = 3 * time.Second
	// directPunchSettle 打洞择优的**收敛窗**: 第一条候选回包之后, 再留这么久让其它候选把
	// 结果报回来, 然后只在"此刻已有结论"的范围里择优拨号, 不再等剩下的候选等满 directPunchWait。
	//
	// 为什么必须这样: 候选里只要有一条从头到尾不回包(中继的多个 E 端点里常有不可达的),
	// "等齐"就意味着明明第一条路十几毫秒就通了, 还要为那条死路把 3s 预算等满 —— 实测这
	// 3s 是整次连接 5.3s 里最长的一段。收敛窗给"稍慢但更优"的路(同网段/回环候选)留出补
	// 上的机会, 代价只是这么短的延迟; 窗满仍没结论的候选按 pending 跳过, 其探测继续在
	// 后台跑完(见 direct_reflect.go 的 punchRun)。取 200ms: 明显大于健康链路的 RTT
	// (跨省几十毫秒), 又不足以让已经通了的那条路白等太久。
	directPunchSettle = 200 * time.Millisecond
	// directPunchFirstDelay 对端(发起方)声明了 directPunchFirst、要求先打时, 接受方
	// 推迟自己打洞的**兜底**时长。正常情况下接受方是收到发起方经 B 转来的 d_punching
	// nudge(发起方一开打就发)才打, 那是确定性的、不靠猜延迟; 这个固定延迟只在 nudge
	// 丢失(B 抖动/对端没发)时兜底, 到点也打, 退化成"固定延迟"的老行为。取 5s: 盖住
	// "本侧回 d_ready -> 经 B 转 d_offer -> 发起方开打并把 nudge 发回来"这一小段, 留出
	// 比早先 2s 更充分的余量, B 特别卡可再调大。详见 docs/direct-punch-order.md。
	//
	// 中继(direct_relay.go)同样不靠这个常量: VPS 朝某条腿主动发包只由那条腿的 nudge 触发,
	// **没有**兜底定时器 —— 定时器一踩空就会在居民真正打洞之前把包打过去、毒化它的 CGNAT
	// 映射(这正是早先踩过的坑), 所以宁可等不到就不发。见 registerRelayLeg/punchLeg 的注释。
	directPunchFirstDelay = 5 * time.Second
	// udpReadBufferSize debug 模式下 socket 被包装成 observeConn, quic-go 检测不到
	// *net.UDPConn 就不会替我们设收包缓冲, 只能自己来。与 quic-go 期望的 7MB 对齐。
	udpReadBufferSize = 7 << 20
	// directTokenTTL 一次性凭证的有效期, 覆盖 punch 到 A 真正拨号之间的间隔。
	directTokenTTL = 30 * time.Second
	// directStreamHeadMax 流首部最大长度, 防止对端用超长首部撑爆内存。
	directStreamHeadMax = 4 * 1024
	// directALPN QUIC 的应用层协议标识, 两侧必须一致。
	directALPN = "anyproxy-direct"
	// directMaxStreams 同一对端的并发会话数上限(每条入口连接占一条 stream)。
	// 256 对 SSH/RDP 这类用法足够, 又不会让单条连接的流控缓冲占太多内存。
	directMaxStreams = 256
	// directSessionIdle 一条 QUIC 连接上所有会话都结束后, 空闲多久就主动关掉。
	//
	// 不留着长期复用: 留着省下的只是下次那一两秒建连, 代价却是每 20 秒一个保活包
	// 无限期发下去, 而且多台 A 连过同一个 C 时 C 会永久累积连接。跨过地址轮换的
	// 连接本来也已经是死的, "复用"在最需要它的时候恰恰不可靠。
	directSessionIdle = 90 * time.Second
	// directReapEvery 空闲回收的检查间隔。
	directReapEvery = 30 * time.Second

	// directRelayIdle VPS 盲转发中继绑定的空闲回收阈值: 专用 socket 上这么久没有任何
	// 转发流量就关掉它和它的读循环。取值明显大于 QUIC 的 KeepAlivePeriod(20s), 好让
	// 活着的中继(A<->C 的 e2e QUIC 每 20s 有保活包过 socket)永不被误判空闲; 只有 e2e
	// QUIC 真死了才在这之后被回收。与直连的 directSessionIdle 同一套思路, 但中继上没有
	// "连接引用计数"可依赖, 只能纯看有没有流量, 所以阈值取得更宽松。
	directRelayIdle = 30 * time.Minute

	// directListenRetryWindow / directListenRetryInterval: kill -HUP 平滑重启时新旧
	// 进程有一段重叠期, 旧进程的入口监听要等它整个进程退出才会释放端口(grace 模式下
	// 旧进程收到 SIGTERM 后还要等 TermTimeout 排空连接才退出)。新进程起入口监听若
	// 在这段重叠期内撞上"address already in use", 以前是直接放弃、这条入口永久起
	// 不来, 得靠用户再发一次 HUP 才能碰巧在端口空出来后再起一次。这里改成在窗口内
	// 重试, 窗口需明显盖过 TermTimeout 默认值(10s)。
	directListenRetryWindow   = 15 * time.Second
	directListenRetryInterval = 500 * time.Millisecond
)

// directRelayNudgeGaps 中继腿 nudge 的**重发间隔**: 第一次在打洞回调里同步发出(见
// punchOnlyThen/punchAllThen), 之后按这些间隔各补发一次, 共 3 次。
//
// 为什么必须重发: nudge 是"这条腿已经打过了"的唯一凭据, 而 VPS 侧**没有**兜底定时器
// (见 directPunchFirstDelay 与 direct_relay.go 的注释)—— 丢一个包, VPS 就永远不朝这条腿
// 发包, 它的防火墙不打开, 整条中继废掉。丢一个控制面小报文的代价远大于多发两个。
// 为什么敢重发: VPS 侧按腿 once 幂等(fireRelayLeg 只 close 一次 fire 通道), 重复到达的
// nudge 直接被忽略; nudge 走已鉴权的 websocket, 也不存在放大或伪造问题。
var directRelayNudgeGaps = []time.Duration{600 * time.Millisecond, 1200 * time.Millisecond}

// directPeer 一条 websocket 连接对应的直连运行时。挂在 wsClientConn 上(不是 Client),
// 因为 TCP 入口监听与 QUIC 监听只能起一次, 不能随 websocket 重连反复创建; 而 Client
// 每次重连都会新建。发信令时通过 curClient 取当前那个 Client。
type directPeer struct {
	tag     string
	cfg     conf.WsClient
	forward map[string]string // C 侧: tag->内网目标, 与 websocket 转发路径共用同一张白名单

	curClient atomic.Value // *Client, 当前活跃的 websocket 连接; 断线期间可能为陈旧值

	// 收发两侧共用同一个 UDP socket, 由一个 quic.Transport 统一持有。
	//
	// 必须共用: 打洞包要和 QUIC 报文走同一个源端口, 对端防火墙上开出来的状态才对得上
	// (状态按 本地ip:port <-> 对端ip:port 记, 换个 socket 就是另一条状态)。
	// 必须经 Transport: quic-go 明确规定一个 PacketConn 只能交给一个 Transport, 交出去
	// 之后不能再自己 ReadFrom/WriteTo —— 所以打洞包走 Transport.WriteTo, 收到的非 QUIC
	// 包用 ReadNonQUICPacket 排掉。
	transportMu sync.Mutex
	udpConn     *net.UDPConn
	transport   *quic.Transport

	// 在飞的探测。按 nonce 关联而不是按来源地址: 现在是多条路并行探测(v4 反射器、
	// v6 反射器、对端的若干候选), 同一时刻好几个包在飞, 来源地址区分不开, 回包也
	// 未必按发出顺序回来。drainNonQUIC 收到回包后按 nonce 投递。
	probeMu sync.Mutex
	waiters map[string]*probeWaiter
	myCands []directCandidate // 最近一次收集到的本机候选, 仅用于日志

	// C 侧(directAccept)。监听是按需起的: 收到服务端转来的 punch 才起, 没有活跃连接
	// 且空闲一段后由 reapAccept 关掉并释放 socket, 所以这些字段会反复置起/置空。
	acceptMu    sync.Mutex // 串行化 ensureAccept / stopAccept
	listener    atomic.Pointer[quic.Listener]
	acceptConns atomic.Int64 // 当前活跃的入向 QUIC 连接数
	acceptUse   atomic.Int64 // 最近一次使用时间(unix nano)
	fingerprint string
	tokens      *directTokenStore

	// pendingPunch C 侧 order Y(对端设了 directPunchFirst、要求先打)时用: 收到 d_punch
	// 先不打, 把打洞按 token 停在这里, 等对端的 d_punching nudge(发起方一开打就发,经 B
	// 转来)再打; nudge 丢了则 directPunchFirstDelay 到点兜底打(见 parkPunch/onPunching)。
	punchMu      sync.Mutex
	pendingPunch map[string]*parkedPunch

	// relays VPS 盲转发中继(directRelay)侧: 按 token 索引的活跃中继绑定, 每个绑定持有
	// 一个专用 UDP socket, 在 A、C 两个居民地址之间盲转发不透明 UDP 包(见 direct_relay.go)。
	// 只有开了 directRelay 的机器会往里放东西。
	relayMu sync.Mutex
	relays  map[string]*relayBinding

	// crypto 打洞会话的加密上下文, 按 token 索引。A、C 两种角色共用同一份: 打洞发生
	// 在 QUIC 连接建立之前, 此时还没有 directSession 可以挂; 且一个 directPeer 上
	// 可能同时有多个并发的打洞会话(不同 email/port 的 direct[] 规则, 或同时被多个
	// A 打洞), 按 token 分表天然支持并发隔离。见 nat/direct_crypto.go。
	crypto *directCryptoTable

	// A 侧(direct[] 入口)
	mu       sync.Mutex
	offers   map[uint]chan DirectOffer // 按请求ID等待服务端回 offer
	sessions map[string]*directSession // listen + email + forward.tag + via -> 复用的 QUIC 连接
	reqInc   uint32                    // 请求ID采番, 与数据面的 ID 空间无关(仅用于匹配 offer)

	// quiet 一次性的前台命令(-send/-recv)置 true: 打洞过程那一串日志(候选、路径选择、
	// QUIC 连上了没)降级成只在 -debug 时才打。
	//
	// 常驻 daemon 不置: 那些行是排查"直连为什么不通"的唯一依据, 平时又没人盯着看,
	// 丢了就没了。前台命令正相反 —— 屏幕上应该只有进度和结果, 打洞细节夹在中间反而
	// 让人看不清文件到底传成没有; 而且真失败时原因会**作为错误**打出来(见
	// ensureSession 的返回值), 不依赖这些日志。
	quiet bool
}

// ensureTransport 建好(或复用)本地 udp6 socket 与其 Transport。A 侧拨号、C 侧监听、
// 两侧打洞全都经它, 保证共用同一个源端口。
func (d *directPeer) ensureTransport() (*quic.Transport, error) {
	d.transportMu.Lock()
	defer d.transportMu.Unlock()
	if d.transport != nil {
		return d.transport, nil
	}
	// 双栈: IPv4 与 IPv6 候选要在**同一个 socket、同一个源端口**上并行竞争。分两个
	// socket 的话两族各有各的端口, 打洞在对端防火墙上开出来的状态也就对不上。
	//
	// 早先这里写死 udp6, 是因为当时只有 IPv6 那条路通; 现在多条路并行, 没有理由再把
	// IPv4 排除在外 —— 它通不通交给探测去回答, 而不是提前替它决定。
	conn, err := net.ListenUDP("udp", &net.UDPAddr{})
	if err != nil {
		return nil, fmt.Errorf("listen udp: %w", err)
	}
	var pc net.PacketConn = conn
	// 两种情况都会让 quic-go 探测不到底下是 *net.UDPConn, 从而放弃它给真实 UDPConn
	// 走的那条批量收发/ECN 快速路径, 退回最朴素的逐包 ReadFrom/WriteTo:
	//   - debug 级别: 包一层收包观察者, 进程收到的每个 datagram 都打一行(限速),
	//     用来回答"对端的 punch 到底有没有到本进程"——被 quic-go 当 QUIC 吞掉的包
	//     drainNonQUIC 看不见, 只能在 socket 层看。
	//   - directPlainUDP(d.cfg): 见 config.DirectPlainUDP 的注释——在部分机器上
	//     (实测至少一台 Windows)那条"快速路径"本身才是问题根源(丢包、拥塞窗口涨不
	//     起来), 关掉它反而更快更干净。跟 debug 的区别是不逐包打日志, 可以放心长期
	//     开着; 每条 websocket.client 各自的 direct.plainUdp 配置可以覆盖命令行的
	//     全局默认值(不是所有网卡/路径都会撞上这个问题)。
	// 两条都不触发时保持原生 *net.UDPConn, quic-go 的批量收发优化不受影响。
	switch {
	case config.DebugLevel >= config.LevelDebug:
		// quic-go 无法在被包装的 conn 上设置收包缓冲(它只认 *net.UDPConn), 这里自己
		// 补设, 否则运行在 OS 默认小缓冲上, 高 BDP 链路(如 RTT 160ms 的国际链路)
		// 容易在收包侧丢包。大小与 quic-go 的期望值对齐, 超限由 OS 裁剪。
		if err := conn.SetReadBuffer(udpReadBufferSize); err != nil {
			d.logf("set udp read buffer: %v", err)
		}
		pc = &observeConn{PacketConn: conn, d: d}
	case directPlainUDP(d.cfg):
		if err := conn.SetReadBuffer(udpReadBufferSize); err != nil {
			d.logf("set udp read buffer: %v", err)
		}
		pc = &plainPacketConn{PacketConn: conn}
	}
	tr := &quic.Transport{Conn: pc}
	d.udpConn = conn
	d.transport = tr
	d.logf("local udp6 socket %s", conn.LocalAddr())
	// 反射器回包与对端打洞包在 quic-go 看来都是无法解析的 QUIC 报文, 会交给
	// ReadNonQUICPacket。不读就会一直堆在内部队列里。
	go d.drainNonQUIC(tr)
	return tr, nil
}

// directPlainUDP 解出这条 websocket.client 连接是否该绕开 quic-go 的 UDP 快速路径
// (见 config.DirectPlainUDP 的注释)。cfg.Direct.PlainUDP 显式配置优先, 不配(nil)才
// 落到命令行 -direct-plain-udp 的全局默认值——单条连接遇到问题不该拖累其它路径。
func directPlainUDP(cfg conf.WsClient) bool {
	if cfg.Direct.PlainUDP != nil {
		return *cfg.Direct.PlainUDP
	}
	return config.DirectPlainUDP
}

// setMyCandidates 记下最近一次收集到的本机候选。
func (d *directPeer) setMyCandidates(cands []directCandidate) {
	d.probeMu.Lock()
	d.myCands = cands
	d.probeMu.Unlock()
}

// myCandidates 取上次收集到的本机候选; 没收集过时返回 nil。
func (d *directPeer) myCandidates() []directCandidate {
	d.probeMu.Lock()
	defer d.probeMu.Unlock()
	return d.myCands
}

// localUDPPort 返回本地 QUIC socket 绑定的端口。候选地址要用它拼本机接口地址。
//
// 不能拿它当对端可用的端点: 外网端口由路径上的 NAT / 端口映射决定, 与本地端口不一定
// 相同, 而且映射老化重建后还会变 —— 跟地址一样, 只能靠反射器探测(见 direct_reflect.go)。
func (d *directPeer) localUDPPort() uint16 {
	d.transportMu.Lock()
	defer d.transportMu.Unlock()
	if d.udpConn == nil {
		return 0
	}
	return uint16(d.udpConn.LocalAddr().(*net.UDPAddr).Port)
}

// directSession A 侧到某个 email 的 QUIC 连接。多条入口 TCP 连接复用同一条 QUIC 连接,
// 各自开独立的 stream —— QUIC 的 stream 之间互不阻塞, 不会像单条 TCP 复用那样队头阻塞。
// UDP 入口则共用这条连接的 datagram 通道, 按端口分发回包。
type directSession struct {
	conn *quic.Conn
	addr string
	// streamReady 表示对端支持数据流 ready ACK。复用一条 QUIC 连接时，ACK 能证明流首部
	// 真正穿过当前路径并且 C 已成功连上落地目标；只在本地 OpenStream 成功并不能证明
	// 中继 VPS 重启后那条旧路径还活着。
	streamReady atomic.Bool

	// stats 这条连接的 QUIC 收发统计(丢包/RTT/拥塞窗口), 仅拨号侧有, 用来判断
	// "传得慢"是链路丢包还是我们自己的问题, 见 nat/direct_stats.go。
	stats *directStats

	// 空闲回收用: refs 为进行中的会话数(每条入口连接 +1), lastUse 为最近一次使用时间。
	// 两者都为"闲"时由 reapSessions 关掉这条 QUIC 连接。
	//
	// 为什么不能光靠 QUIC 自己的空闲超时: 我们开着 keep-alive(活跃会话期间要靠它焐住
	// IPv6 有状态防火墙的洞, RDP 有大段没数据的时候), 而 keep-alive 会一直把空闲超时
	// 顶回去, 连接于是永远不死。多台 A 连过同一个 C 时, C 这边会永久累积连接。
	refs    atomic.Int64
	lastUse atomic.Int64 // unix nano

	// udpMu 保护 boundUDPEntry。一条 directSession 严格 1:1 对应一条 ClientDirect 规则
	// (route 里连 listen 都算进了 session key, 见 sessionRouteForRule), 所以一条
	// 连接上最多只会绑一个 UDP 入口, 不需要按 tag/端口索引的 map。
	udpMu         sync.Mutex
	boundUDPEntry *directUDPEntry // 用于把回程 datagram 投递回去, 见 bindUDPEntry/udpEntry
}

// acquire 标记一条会话开始使用。
func (s *directSession) acquire() {
	s.refs.Add(1)
	s.touch()
}

// release 标记一条会话结束。
func (s *directSession) release() {
	s.refs.Add(-1)
	s.touch()
}

// touch 刷新最近使用时间。UDP 没有"连接"概念, 靠每个包来刷。
func (s *directSession) touch() {
	s.lastUse.Store(time.Now().UnixNano())
}

// idleFor 返回空闲时长; 仍有进行中的会话时返回 0。
//
// 两类"在用"要分别判断, 缺一不可:
//   - TCP: 每条入口连接 acquire/release, refs>0 即在用 —— 连接开着但长时间没数据
//     (RDP 静默、SSH 挂着不动)也算在用。
//   - UDP: 没有"连接"可计数, 只能看它自己的会话表里还有没有活着的会话。光看
//     lastUse 会误杀: UDP 图形通道(如 RDP 8+ 的 Enhanced RDP)在用户不操作时可能
//     很久没包, 但会话并没有结束, 把 QUIC 连接关掉会让画面恢复时直接断开。
func (s *directSession) idleFor() time.Duration {
	if s.refs.Load() > 0 {
		return 0
	}
	if s.hasActiveUDP() {
		return 0
	}
	return time.Since(time.Unix(0, s.lastUse.Load()))
}

// hasActiveUDP 该连接上是否还有活着的 UDP 会话(绑定的入口的任一用户源地址在自己的
// 空闲窗口内有过流量)。
func (s *directSession) hasActiveUDP() bool {
	s.udpMu.Lock()
	e := s.boundUDPEntry
	s.udpMu.Unlock()
	return e != nil && e.hasActiveSessions()
}

// acceptListener 取当前的 QUIC 监听; 未起或已释放时返回 nil。
func (d *directPeer) acceptListener() *quic.Listener {
	return d.listener.Load()
}

// touchAccept / lastAcceptUse 记录 C 侧监听最近一次被用到的时间, 供空闲释放判断。
func (d *directPeer) touchAccept() {
	d.acceptUse.Store(time.Now().UnixNano())
}

func (d *directPeer) lastAcceptUse() time.Time {
	return time.Unix(0, d.acceptUse.Load())
}

// closeTransport 关掉并丢弃当前的 socket/Transport, 下次 ensureTransport 会重建一个。
//
// 必须能重建: socket 可能因为网卡下线、IPv6 地址被撤等原因失效, 一直抱着一个坏的
// transport 会让直连永久不可用。端口因此改变也没关系 —— 对端用的端点每次都是当场
// 探测后经服务端转交的, 没有谁攥着旧端口。
func (d *directPeer) closeTransport() {
	d.transportMu.Lock()
	tr, conn := d.transport, d.udpConn
	d.transport, d.udpConn = nil, nil
	d.transportMu.Unlock()
	if tr != nil {
		_ = tr.Close()
	}
	if conn != nil {
		_ = conn.Close()
	}
}

// bindUDPEntry 登记这条连接绑定的入口, 使其能收到回程 datagram。
func (s *directSession) bindUDPEntry(e *directUDPEntry) {
	s.udpMu.Lock()
	s.boundUDPEntry = e
	s.udpMu.Unlock()
}

func (s *directSession) udpEntry() *directUDPEntry {
	s.udpMu.Lock()
	defer s.udpMu.Unlock()
	return s.boundUDPEntry
}

func newDirectPeer(tag string, cfg conf.WsClient, forward map[string]string) *directPeer {
	return &directPeer{
		tag:      tag,
		cfg:      cfg,
		forward:  forward,
		tokens:   newDirectTokenStore(),
		crypto:   newDirectCryptoTable(),
		offers:   make(map[uint]chan DirectOffer),
		sessions: make(map[string]*directSession),
		relays:   make(map[string]*relayBinding),
	}
}

func (d *directPeer) logf(format string, args ...interface{}) {
	if d.quiet && config.DebugLevel < config.LevelDebug {
		return
	}
	log.Printf("[%s] nat direct: %s", d.tag, fmt.Sprintf(format, args...))
}

// setClient 每次 websocket 认证成功后更新当前连接, 供入口监听与 QUIC 监听发信令使用。
func (d *directPeer) setClient(c *Client) {
	d.curClient.Store(c)
}

// client 取当前 websocket 连接; 断线期间返回的可能是已失效的连接, 发送会失败, 由调用方处理。
func (d *directPeer) client() *Client {
	c, _ := d.curClient.Load().(*Client)
	return c
}

// send 经 websocket 发一条直连信令。
func (d *directPeer) send(method string, id uint, payload interface{}) error {
	c := d.client()
	if c == nil {
		return errors.New("websocket not connected")
	}
	body, err := encodeDirect(payload)
	if err != nil {
		return err
	}
	// 与数据面共用 hub.broadcast: 它是无缓冲通道且不会被关闭, 直接写 client.send 会与
	// close 竞争(见 Hub.run 注释)。
	c.hub.broadcast <- &CMessage{client: c, message: &Message{ID: id, Type: ConnTCP, Method: method, Body: body}}
	return nil
}

// handleDirectClient 订阅方侧处理服务端下发的直连信令。返回 true 表示消息已消费。
func handleDirectClient(c *Client, msg *Message) bool {
	if !isDirectMethod(msg.Method) {
		return false
	}
	d := c.directPeerOf()
	if d == nil {
		log.Printf("nat direct: got %s but direct is not enabled on this connection", msg.Method)
		return true
	}
	switch msg.Method {
	case METHOD_DIRECT_PUNCH:
		d.onPunch(msg)
	case METHOD_DIRECT_PUNCHING:
		d.onPunching(msg)
	case METHOD_DIRECT_OFFER:
		d.onOffer(msg)
	case METHOD_DIRECT_RELAY_OPEN:
		d.onRelayOpen(msg)
	default:
		d.logf("unexpected %s from server", msg.Method)
	}
	return true
}

// directTokenStore C 侧待验证的一次性凭证。A 出示的 token 必须由服务端经 punch 提前
// 交给过 C, 且未过期、未用过 —— 这样 QUIC 端口即使被扫到, 也无法被任意来源利用。
type directTokenStore struct {
	mu     sync.Mutex
	tokens map[string]directTokenEntry
}

type directTokenEntry struct {
	tag     string
	expires time.Time

	// relay 为 true 表示这条连接是经 VPS 盲转发来的: VPS 不可信, 光有 token 不够, 进数据面
	// 前还要在 e2e QUIC 流里做一次 uuid 挑战-应答(见 direct_relay_auth.go)。email 是 B 认证
	// 过的发起方 A 的 email, C 据此去 receive.allow 查该用哪个 uuid 验(不采信 A 自报)。
	relay bool
	email string
}

func newDirectTokenStore() *directTokenStore {
	return &directTokenStore{tokens: make(map[string]directTokenEntry)}
}

func (s *directTokenStore) put(token string, tag string) {
	s.putEntry(token, directTokenEntry{tag: tag})
}

// putRelay 登记一条中继连接的凭证: 除 tag 外还记下"需 uuid 挑战-应答"及发起方 email。
func (s *directTokenStore) putRelay(token string, tag string, email string) {
	s.putEntry(token, directTokenEntry{tag: tag, relay: true, email: email})
}

func (s *directTokenStore) putEntry(token string, e directTokenEntry) {
	now := time.Now()
	e.expires = now.Add(directTokenTTL)
	s.mu.Lock()
	defer s.mu.Unlock()
	// 顺带清掉过期项: 凭证只在 punch 到拨号这段短时间内有用, 不清会随连接数无限增长。
	for t, old := range s.tokens {
		if now.After(old.expires) {
			delete(s.tokens, t)
		}
	}
	s.tokens[token] = e
}

// take 校验并消费一个凭证, 一次性: 取走即删, 重放无效。
func (s *directTokenStore) take(token string) (directTokenEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.tokens[token]
	if !ok {
		return directTokenEntry{}, false
	}
	delete(s.tokens, token)
	if time.Now().After(e.expires) {
		return directTokenEntry{}, false
	}
	return e, true
}

// 流首部的 Kind: 纯鉴权流只认证连接、不落地; 数据流承载一条入口 TCP 连接。
const (
	directStreamAuth  = "auth"
	directStreamData  = "data"
	directAuthACK     = byte(1)
	directCapReadyACK = byte(1)
	// directRejectACK 数据流被 C 明确拒绝(比如 tag 没有 forward 映射), 不是连接坏了。
	// 与 directAuthACK 区分开, 好让 A 不把这种配置问题误判成 session 损坏去重建。
	directRejectACK = byte(2)
)

// directStreamReject 紧跟在 directRejectACK 后面的拒绝原因, 用 writeFrame/readFrame 传输。
// 只有 head.Ready 的对端(有能力等 ready ACK)才会收到它; 老版本对端读不到这个字节,
// 反正也不等 ack, 直接看到流关闭。
type directStreamReject struct {
	Reason string `json:"reason"`
}

// directStreamPull 取件流: 与 directStreamFile 同一套身份校验和端口(directFileTag),
// 只是字节流向相反 —— 发起方在流上说要什么, 对端把文件推回来(见 nat/file_pull.go)。
const directStreamPull = "pull"

// directStreamHead A 打开 QUIC stream 后写的首部。
//
// Kind=auth 用于只走 UDP 的场景: datagram 没法逐包握手, 而凭证又必须有地方出示, 所以
// 先开一条纯鉴权流认证整条连接(C 校验后回一个字节确认), 之后 datagram 才被接受。
// Kind=data 是承载数据的流; 连接已认证时 Token 可为空。
type directStreamHead struct {
	Kind  string `json:"kind"`
	Token string `json:"token"`
	Tag   string `json:"tag"`
	Ready bool   `json:"ready,omitempty"` // 请求 C 在落地目标连通后回一个 ready ACK
}

func writeStreamHead(w io.Writer, h directStreamHead) error {
	return writeFrame(w, h)
}

func readStreamHead(r io.Reader) (directStreamHead, error) {
	var h directStreamHead
	err := readFrame(r, &h, directStreamHeadMax)
	return h, err
}

// writeFrame 写一个"2 字节长度 + JSON"的控制帧。流首部、文件首部/尾部/结果都用它。
func writeFrame(w io.Writer, v interface{}) error {
	body, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if len(body) > 0xFFFF {
		return errors.New("frame too large")
	}
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(body)))
	// 一次写出去而不是分两次: 分两次会在网络上产生两个小包, 也让对端更容易读到半个帧。
	buf := append(size[:], body...)
	_, err = w.Write(buf)
	return err
}

// readFrame 读一个控制帧。max 限制帧体大小, 免得对端用超长长度撑爆内存。
func readFrame(r io.Reader, v interface{}, max int) error {
	var size [2]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return err
	}
	n := int(binary.BigEndian.Uint16(size[:]))
	if n > max {
		return fmt.Errorf("frame too large: %d > %d", n, max)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

// directCopy 在 QUIC stream 与普通连接之间双向搬字节, 返回两个方向的字节数。
func directCopy(a io.ReadWriteCloser, b io.ReadWriteCloser) (aToB, bToA int64) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		aToB, _ = io.Copy(b, a)
		// 关掉写方向即可, 让对端读到 EOF 后把自己那半也收干净; 直接 Close 会把还没
		// 读完的另一方向一起砍掉。QUIC stream 与 TCP 都支持半关。
		closeWrite(b)
	}()
	go func() {
		defer wg.Done()
		bToA, _ = io.Copy(a, b)
		closeWrite(a)
	}()
	wg.Wait()
	return
}

// closeWrite 尽量只关写方向; 类型不支持半关时退回整体关闭。
func closeWrite(c io.Closer) {
	type writeCloser interface{ CloseWrite() error }
	if wc, ok := c.(writeCloser); ok {
		_ = wc.CloseWrite()
		return
	}
	_ = c.Close()
}
