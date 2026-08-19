package proto

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/keminar/anyproxy/proto/stats"

	"github.com/keminar/anyproxy/config"
	"github.com/keminar/anyproxy/crypto"
	"github.com/keminar/anyproxy/proto/tcp"
	"github.com/keminar/anyproxy/utils/cache"
	"github.com/keminar/anyproxy/utils/conf"
	"github.com/keminar/anyproxy/utils/tools"
	"github.com/keminar/anyproxy/utils/trace"
	"golang.org/x/net/proxy"
)

const (
	stateNew int = iota
	stateActive
	stateClosed
	stateIdle
)

const protoTCP = "tcp"
const protoHTTP = "http"
const protoHTTPS = "https"

// autoDirectFailTTL 是 auto 模式下「直连失败」的缓存时长: 有效期内后续请求跳过直连、
// 直接走代理, 只为省掉一次页面并发请求里的重复直连。刻意取短(而非缓存很久), 避免一次偶发
// 直连失败就把该域名长时间钉死在代理上; 过期后会再尝试直连以便及时恢复。
const autoDirectFailTTL = 20 * time.Second

// autoDirectSec 是 auto 模式先本地直连的超时(秒), 也是「连不通的目标」首个请求的等待延迟。
// 正常可达 TCP 握手多在几百毫秒内、跨境也少超过 1s; 被静默丢包的目标(如被墙站点)才会等满。
// 取 2s: 既容忍慢握手不误判, 又尽快把连不通目标切去代理(之后由 autoDirectFailTTL 兜住)。
// 复用连接不重连, 成功即用这条; 单列常量避免动到 s.dail 默认 5s(那用于真实直连/代理连接)。
const autoDirectSec = 2

// 上行统计
var inbound *stats.Manager

// 下行统计
var outbound *stats.Manager

func init() {
	inbound = stats.NewManager()
	outbound = stats.NewManager()
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			//log.Println("ticker...")
			inbound.UnregisterCounter()
			outbound.UnregisterCounter()
		}
	}()
}

// 转发实体
type tunnel struct {
	req      *Request
	conn     *net.TCPConn // 后端服务
	curState int

	inboundIP string // 来源IP

	inbountCounter  *stats.Counter
	outbountCounter *stats.Counter

	readSize  int64
	writeSize int64

	clientUnRead int

	buf []byte

	guardKey string // loopguard 目标键(host:port), handshake 通过后设置, 供 transfer 计数
}

// newTunnel 实例
func newTunnel(req *Request) *tunnel {
	s := &tunnel{
		req: req,
	}

	s.inboundIP = tools.GetRemoteIp(req.conn.RemoteAddr().String())
	return s
}

// copyBuffer 传输数据
func (s *tunnel) copyBuffer(dst io.Writer, src *tcp.Reader, srcname string) (written int64, err error) {
	//如果设置过大会耗内存高，4k比较合理
	size := 4 * 1024
	buf := make([]byte, size)
	i := 0
	for {
		i++
		if config.DebugLevel >= config.LevelDebug {
			log.Printf("%s receive from %s, n=%d\n", trace.ID(s.req.ID), srcname, i)
		}
		nr, er := src.Read(buf)
		if nr > 0 {
			// 如果为HTTP/1.1的Keep-alive情况下
			if srcname == "request" && s.clientUnRead >= 0 {
				// 之前已读完，说明要建新链接 或是 升级为长链接
				if s.clientUnRead == 0 {
					// 如果包是http协议则认为http复用
					if isKeepAliveHttp(s.req.ctx, s.req.conn, buf[0:nr]) {
						// 关闭与旧的服务器的连接的写
						s.conn.CloseWrite()
						// 状态变成已空闲，不能为关闭，会导致下面逻辑的Client也被关闭
						s.curState = stateIdle

						//todo 如果域名不同跳出交换数据, 因为这个逻辑会出现N次，应该在http.go实现
						//fmt.Println(string(buf[0:nr]))
						s.buf = make([]byte, nr)
						copy(s.buf, buf[0:nr])
						break
					} else {
						//可能是http upgrade为websocket, 保持交换数据
						//比如经过nginx proxy -> 本程序 -> 旧版本的centrifugo
						s.clientUnRead = -1
					}
				} else {
					// 未读完
					s.clientUnRead -= nr
				}
			}
			if config.DebugLevel >= config.LevelDebugBody {
				log.Printf("%s receive from %s, n=%d, data len: %d\n", trace.ID(s.req.ID), srcname, i, nr)
				fmt.Println(trace.ID(s.req.ID), string(buf[0:nr]))
			}
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
				if srcname == "request" {
					s.inbountCounter.Add(s.req.ID, int64(nw))
				} else {
					s.outbountCounter.Add(s.req.ID, int64(nw))
				}
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
			} else {
				s.logCopyErr(srcname+" read", er)
				if srcname == "server" {
					// 技巧：keep-alive 复用连接时写，后端收到CloseWrite后响应EOF，当收到EOF时说明body都收完了。
					if s.curState == stateIdle {
						//可以开始复用了, 带上之前读过的缓存
						KeepHandler(s.req.ctx, s.req.conn, s.buf)
						break
					} else if s.curState != stateClosed {
						// 如果非客户端导致的服务端关闭，则关闭客户端读
						// Notice: 如果只是CloseRead(),当在windows上执行时，且是做为订阅端从服务器收到请求再转到charles
						//         等服务时,当请求的地址返回足够长的内容时会触发卡住问题。
						//         流程如 curl -> anyproxy(server) -> ws -> anyproxy(windows) -> charles
						//         用Close()可以解决卡住，不过客户端会收到use of closed network connection的错误提醒
						dst.(*net.TCPConn).Close()
					}
				}
			}

			if srcname == "request" {
				// 当客户端断开或出错了，服务端也不用再读了，可以关闭，解决读Server卡住不能到EOF的问题
				s.conn.CloseWrite()
				s.curState = stateClosed
			}
			break
		}
	}
	return written, err
}

// transfer 交换数据
func (s *tunnel) transfer(clientUnRead int) {
	if config.DebugLevel >= config.LevelLong {
		log.Println(trace.ID(s.req.ID), "transfer start")
	}
	// 计入 loopguard 在传连接, 结束时释放(key 为空则跳过, 如 tcpcopy)
	guard.enter(s.guardKey)
	defer guard.leave(s.guardKey)
	// 结束时补记残余字节, 避免同一分钟内快速完成的连接漏统计
	defer s.flushCounters()
	s.curState = stateActive
	s.clientUnRead = clientUnRead
	done := make(chan struct{})

	//发送请求
	go func() {
		defer func() {
			close(done)
		}()
		//不能和外层共用err
		var err error
		s.readSize, err = s.copyBuffer(s.conn, s.req.reader, "request")
		s.logCopyErr("request->server", err)
		if config.DebugLevel >= config.LevelLong {
			log.Println(trace.ID(s.req.ID), "request body size", s.readSize)
		}
	}()

	var err error
	//取返回结果
	s.writeSize, err = s.copyBuffer(s.req.conn, tcp.NewReader(s.conn), "server")
	s.logCopyErr("server->request", err)

	<-done
	// 不管是不是正常结束，只要server结束了，函数就会返回，然后底层会自动断开与client的连接
	if config.DebugLevel >= config.LevelLong {
		log.Println(trace.ID(s.req.ID), "transfer finished, response size", s.writeSize)
	}
}

// 上行写入
func (s *tunnel) Write(p []byte) (n int, err error) {
	n, err = s.conn.Write(p)
	if s.inbountCounter != nil {
		s.inbountCounter.Add(s.req.ID, int64(n))
	}
	return
}

func (s *tunnel) logCopyErr(name string, err error) {
	if err == nil {
		return
	}
	if config.DebugLevel >= config.LevelLong {
		log.Println(trace.ID(s.req.ID), name, err.Error())
	} else if err != io.EOF {
		log.Println(trace.ID(s.req.ID), name, err.Error())
	}
}

// dail tcp连接
func (s *tunnel) dail(network, connAddr string, second int64) error {
	if config.DebugLevel >= config.LevelLong {
		log.Printf("%s create new connection to server %s\n", trace.ID(s.req.ID), connAddr)
	}

	connTimeout := time.Duration(5) * time.Second
	if second > 0 {
		connTimeout = time.Duration(second) * time.Second
	}
	conn, err := tunDial(network, connAddr, connTimeout)
	if err != nil {
		return err
	}
	s.conn = conn.(*net.TCPConn)
	// 出向本地址(实际 egress)是排查 TUN 环路的关键证据: 若它落在 TUN 网段
	// (如 10.9.0.x)而非物理网卡 IP, 说明出向没能逃出 TUN, 就是环路根因。
	if config.DebugLevel >= config.LevelLong {
		log.Printf("%s dialed %s via local %s\n", trace.ID(s.req.ID), connAddr, s.conn.LocalAddr())
	}
	return nil
}

// 注册计数器, 日志地址优先使用域名
// registerCounter 按「来源IP × 目标地址 × 方向」注册上下行流量计数器。
// 统计始终以「最终目标」为主地址; 走上级代理时用 viaProxy 附上经由的代理地址
// (形如 "cloudme.io:80 via 192.168.122.1:10808"), 使日志既有真实目标又有中转代理。
// 直连时 viaProxy 传空。
func (s *tunnel) registerCounter(dstName, dstIP string, dstPort uint16, viaProxy string) {
	// 日志地址优先使用域名
	var logAddr string
	if dstName != "" {
		logAddr = fmt.Sprintf("%s:%d", dstName, dstPort)
	} else {
		if strings.Contains(dstIP, ":") {
			logAddr = fmt.Sprintf("[%s]:%d", dstIP, dstPort)
		} else {
			logAddr = fmt.Sprintf("%s:%d", dstIP, dstPort)
		}
	}
	if viaProxy != "" {
		logAddr = logAddr + " via " + viaProxy
	}
	uplink := fmt.Sprintf("inbound>>>%s>>>%s>>>uplink", s.inboundIP, logAddr)
	downlink := fmt.Sprintf("inbound>>>%s>>>%s>>>downlink", s.inboundIP, logAddr)
	s.inbountCounter = inbound.RegisterCounter(uplink)
	s.outbountCounter = outbound.RegisterCounter(downlink)
}

// flushCounters 在连接结束时把上/下行计数器里「还没到分钟翻转、尚未打印」的残余
// 字节立即补记进日志, 避免快速完成的连接漏统计(见 stats.Counter.Flush)。
func (s *tunnel) flushCounters() {
	if s.inbountCounter != nil {
		s.inbountCounter.Flush(s.req.ID)
	}
	if s.outbountCounter != nil {
		s.outbountCounter.Flush(s.req.ID)
	}
}

// 连接地址优先使用IP
func (s *tunnel) buildAddress(dstName, dstIP string, dstPort uint16, addCounter bool) (network string, connAddr string) {
	network = "tcp"
	if dstIP != "" {
		if strings.Contains(dstIP, ":") {
			network = "tcp6"
			connAddr = fmt.Sprintf("[%s]:%d", dstIP, dstPort)
		} else {
			connAddr = fmt.Sprintf("%s:%d", dstIP, dstPort)
		}
	} else if dstName != "" {
		connAddr = fmt.Sprintf("%s:%d", dstName, dstPort)
	}

	if addCounter && connAddr != "" {
		s.registerCounter(dstName, dstIP, dstPort, "")
	}
	return
}

// DNS解析
func (s *tunnel) lookup(dstName, dstIP string) (string, cache.DialState) {
	state := cache.StateNone
	if dstName != "" {
		dstIP, state = cache.ResolveLookup.Lookup(s.req.ID, dstName)
		if dstIP == "" {
			s1 := time.Now()
			upIPs, _ := net.LookupIP(dstName)
			if time.Since(s1).Seconds() > 1 && config.DebugLevel >= config.LevelLong {
				log.Println(trace.ID(s.req.ID), "dns look up costtime", time.Since(s1).Seconds())
			}
			if len(upIPs) > 0 {
				dstIP = upIPs[0].String()
				cache.ResolveLookup.Store(dstName, dstIP, cache.StateNew, time.Duration(10)*time.Minute)
				return dstIP, cache.StateNew
			}
		}
	}
	return dstIP, state
}

// defaultLocalPorts 是 localport 模式未配置 default.localPort 时的默认本地端口: ftp(21)/ssh(22)。
var defaultLocalPorts = []int{21, 22}

// isLocalTCPPort 判断端口在 localport 模式下是否走本地直连。
// 未配置 default.localPort 时用默认的 21/22；一旦配置则完全以配置为准(覆盖而非追加)。
func isLocalTCPPort(port uint16) bool {
	ports := conf.RouterConfig.Default.LocalPort
	if len(ports) == 0 {
		ports = defaultLocalPorts
	}
	for _, p := range ports {
		if p == int(port) {
			return true
		}
	}
	return false
}

// 查询配置
func findHost(dstName, dstIP string) conf.Host {
	defMatch := conf.RouterConfig.Default.Match
	for _, h := range conf.RouterConfig.Hosts {
		if h.Matched(dstName, defMatch) || h.Matched(dstIP, defMatch) {
			return h
		}
	}
	return conf.Host{}
}

// 取值，如为空取默认
func getString(val string, def string, def2 string) string {
	if val == "" {
		if def == "" {
			return def2
		}
		return def
	}
	return val
}

// handshake 和server握手
func (s *tunnel) handshake(proto string, dstName, dstIP string, dstPort uint16) (err error) {
	// 死循环兜底: 同机 A(TUN)+B(bypass, 仅Linux) 若 bypass 未生效, 句柄会堆积且都指向同一目标,
	// 全局在传连接冲高后某目标占比过大即判为环路, 拒绝其新连接以解开环路。
	// 正常应由 mode=bypass 根治, 此为最后防线。
	guardKey := dstName
	if guardKey == "" {
		guardKey = dstIP
	}
	guardKey = fmt.Sprintf("%s:%d", guardKey, dstPort)
	if ok, tripped, keyActive, total := guard.allow(guardKey); !ok {
		if tripped {
			log.Println(trace.ID(s.req.ID), fmt.Sprintf("loopguard: circuit open for %s (in-flight %d/%d, suspected proxy loop)", guardKey, keyActive, total))
		}
		return fmt.Errorf("loopguard: %s dominates in-flight connections", guardKey)
	}
	s.guardKey = guardKey

	var state cache.DialState
	// 先取下配置，再决定要不要走本地dns解析，否则未解析域名DNS解析再超时卡半天，又不会被缓存
	host := findHost(dstName, dstIP)
	// TUN 流量来自本机虚拟网卡，属受信任的本地流量，跳过 allowIP 检查
	if !s.req.TUN {
		if ip, ok := s.isAllowed(host.AllowIP); !ok {
			err = fmt.Errorf("%s is not allowed", ip)
			return err
		}
	}
	var confTarget string
	if proto == protoTCP {
		confTarget = getString(host.Target, conf.RouterConfig.Default.TCPTarget, "auto")
	} else {
		confTarget = getString(host.Target, conf.RouterConfig.Default.Target, "auto")
	}
	// localport: 命中的端口走本地直连，其余走代理。内置 21/22/3306(ftp/ssh/mysql)，可在配置追加。
	if confTarget == "localport" {
		if isLocalTCPPort(dstPort) {
			confTarget = "local"
		} else {
			confTarget = "remote"
		}
	}
	confDNS := getString(host.DNS, conf.RouterConfig.Default.DNS, "local")

	// tcp 请求，如果是解析的IP被禁（代理端也无法telnet），不知道域名又无法使用远程dns解析，只能手动换ip
	// 如golang.org 解析为180.97.235.30 不通，配置改为 216.239.37.1就行
	if host.IP != "" {
		dstIP = host.IP
	} else if dstName != "" && confDNS != "remote" && !s.req.TUN {
		// http请求的dns解析；TUN 连接的目标 IP 已由内核路由确定，无需重新解析
		dstIP, state = s.lookup(dstName, dstIP)
	}

	// 检查是否要换端口
	for _, p := range host.Port {
		if p.From == dstPort {
			dstPort = p.To
			break
		}
	}

	if confTarget == "deny" {
		err = fmt.Errorf("deny visit %s (%s)", dstName, dstIP)
		return
	}

	// target=auto: 本地优先, 先做一次「真正的直连」(非静默探测, 成功即复用该连接)。
	// 直连成功即结束, 完全不碰代理; 直连失败才降级为 remote 走代理, 并强制远程 DNS。
	// 记 autoDirectFailed: 直连既已失败, 后面即便代理也挂了也不再重试同一直连(直接失败)。
	autoDirectFailed := false
	if confTarget == "auto" {
		if state == cache.StateFail {
			// 近期直连已失败(短缓存内): 跳过重复直连, 直接走代理; 且标记直连不可用
			autoDirectFailed = true
		} else {
			network, connAddr := s.buildAddress(dstName, dstIP, dstPort, true)
			if connAddr != "" {
				forName := ""
				if dstName != "" {
					forName = " for " + dstName
				}
				if e := s.dail(network, connAddr, autoDirectSec); e == nil {
					log.Println(trace.ID(s.req.ID), fmt.Sprintf("auto to %s%s", connAddr, forName))
					s.curState = stateNew
					return
				} else {
					log.Println(trace.ID(s.req.ID), fmt.Sprintf("auto direct %s%s fail: %v, fallback to proxy", connAddr, forName, e))
					autoDirectFailed = true
					if dstName != "" && dstIP != "" {
						cache.ResolveLookup.Store(dstName, dstIP, cache.StateFail, autoDirectFailTTL)
					}
				}
			}
		}
		// 直连不通 -> 降级为 remote 走代理。有一种 ip 能 dail 通但收不到数据的情况 auto 判断不了,
		// 需在规则里显式写 remote。
		confTarget = "remote"
		confDNS = "remote"
	}

	proxyScheme := config.ProxyScheme
	var proxyServer string
	var proxyPort uint16
	// target=local 不需要代理, 跳过整个代理解析: 既省去无谓探测, 也避免被全局代理的 deny 后缀
	// 误伤(local 应始终直连)。proxyServer 保持空, 下方走 else 分支直连。
	if confTarget != "local" {
		// 全局代理实时取值以支持热加载: 命令行 -p(固定) 优先于配置 default.proxy(可热改)。
		globalSpec := config.IfEmptyThen(config.ProxyCmdline, conf.RouterConfig.Default.Proxy, "")
		proxyConfigured := host.Proxy != "" || globalSpec != ""
		// localFallback: 链路上出现过 " local" 后缀, 代理都不通时「显式允许」走本地直连。
		localFallback := false
		// useGlobal 惰性解析全局代理, 仅在「无单域名代理」或「单域名代理都不可用且无 local/deny 后缀」
		// 时作为回退调用——保证 host.proxy 先于全局代理尝试, 且 host.proxy 命中时不白探测全局。
		// 返回 true 表示全局代理带 deny 后缀且都不可用, 应拒绝请求。
		useGlobal := func() (denied bool) {
			if globalSpec == "" {
				return false
			}
			if sc, sv, pt, opName, ok := resolveGlobalProxy(s.req.ID, globalSpec); ok {
				proxyScheme, proxyServer, proxyPort = sc, sv, pt
			} else if opName == "local" {
				localFallback = true
			} else if opName == "deny" {
				return true
			}
			return false
		}
		// 优先单域名 host.proxy; 失败再按后缀决定本地直连/拒绝/回退全局代理。
		if host.Proxy != "" {
			if sc, sv, pt, opName, ok := resolveProxySpec(s.req.ID, host.Proxy); ok {
				proxyScheme, proxyServer, proxyPort = sc, sv, pt
			} else if opName == "local" { //host 代理带 local 后缀且都不可用, 允许走本地直连
				localFallback = true
			} else if opName == "deny" { //host 代理都不可用, 拒绝请求
				err = fmt.Errorf("all proxy dail fail %s", host.Proxy)
				return
			} else if useGlobal() { //无后缀且都不可用: 回退全局代理
				err = fmt.Errorf("all proxy dail fail %s", globalSpec)
				return
			}
		} else if useGlobal() { //无单域名代理: 用全局代理
			err = fmt.Errorf("all proxy dail fail %s", globalSpec)
			return
		}
		// 配了代理但都不可用, 又没有 local 后缀允许直连: 本次要求走代理(remote/proxy, auto 也已
		// 降级为 remote), 不能静默直连出去, 报错。
		if proxyServer == "" && proxyConfigured && !localFallback {
			err = fmt.Errorf("all proxy unavailable and no local fallback for %s", dstName)
			return
		}
		// auto 场景: 直连已经失败过, 才降级来走代理; 若代理也都不可用而想靠 local 后缀退回直连,
		// 那是重试同一个刚失败的直连, 没有意义, 直接判失败(避免多等一次 5s 超时)。
		if proxyServer == "" && localFallback && autoDirectFailed {
			err = fmt.Errorf("auto: direct and all proxy failed for %s", dstName)
			return
		}
	}
	// 上游代理若指向本进程自己的监听地址(回环/本机IP + 监听端口), 代理请求会打回自己
	// 的监听器被再次转发, 形成应用层死循环(现象: PROXY 127.0.0.1:<监听端口> 反复出现)。
	// 当作无代理处理, 走直连(TUN 模式下由出向 socket 的 IP_UNICAST_IF 逃出), 避免空转; 并限流告警提示改配置。
	if proxyServer != "" && proxyPort > 0 && isSelfProxy(proxyServer, proxyPort) {
		logSelfProxy(s.req.ID, proxyServer, proxyPort)
		proxyServer, proxyPort = "", 0
	}
	if proxyServer != "" && proxyPort > 0 && confTarget != "local" {
		// remote 请求(auto 的直连探测已在前面完成, 到这里说明要走代理)
		var targetAddr string
		var targetNet string
		if confDNS == "remote" {
			if dstName == "" {
				dstName = dstIP
			}
			targetNet, targetAddr = s.buildAddress(dstName, "", dstPort, false)
		} else {
			targetNet, targetAddr = s.buildAddress("", dstIP, dstPort, false)
		}
		if targetAddr == "" || targetAddr[0] == ':' {
			err = errors.New("target host is empty")
			return
		}

		network, connAddr := s.buildAddress(proxyServer, "", proxyPort, false)
		// 统计以最终目标为主, 附带经由的上级代理(而非只记代理地址), 便于识别真实下载地址
		s.registerCounter(dstName, dstIP, dstPort, fmt.Sprintf("%s:%d", proxyServer, proxyPort))
		switch proxyScheme {
		case "socks5":
			log.Println(trace.ID(s.req.ID), fmt.Sprintf("PROXY %s for %s", connAddr, targetAddr))
			err = s.socks5(network, connAddr, targetNet, targetAddr)
		case "tunnel":
			log.Println(trace.ID(s.req.ID), fmt.Sprintf("PROXY %s for %s", connAddr, targetAddr))
			err = s.httpConnect(network, connAddr, targetAddr, true)
		case "http":
			// 直发原始请求这条分支要求请求已被 http.go 解析改写成绝对形式(absolute-form)，
			// 仅适用于监听入口的 HTTP 流。TUN 是原始字节转发(origin-form: GET /path)，
			// http 代理不认，故 TUN 的 http 也必须用 CONNECT 隧道。
			if proto == protoHTTP && !s.req.TUN { //可避免转发到charles显示2次域名，且部分电脑请求出错
				log.Println(trace.ID(s.req.ID), fmt.Sprintf("PROXY %s", connAddr))
				err = s.dail(network, connAddr, 0)
			} else {
				log.Println(trace.ID(s.req.ID), fmt.Sprintf("PROXY %s for %s", connAddr, targetAddr))
				err = s.httpConnect(network, connAddr, targetAddr, false)
			}
		default:
			err = fmt.Errorf("proxy scheme %s is error", proxyScheme)
			return
		}
	} else {
		network, connAddr := s.buildAddress(dstName, dstIP, dstPort, true)
		if connAddr != "" {
			if dstName == "" {
				log.Println(trace.ID(s.req.ID), fmt.Sprintf("direct to %s", connAddr))
			} else {
				log.Println(trace.ID(s.req.ID), fmt.Sprintf("direct to %s for %s", connAddr, dstName))
			}
			err = s.dail(network, connAddr, 0)
		} else {
			err = errors.New("dstName && dstIP is empty")
		}
	}
	if err != nil {
		return
	}
	s.curState = stateNew
	return
}

// isSelfProxy 判断配置的上游代理是否就是本进程自己的监听地址(回环/本机IP + 监听端口)。
// 是则代理请求会打回自己的监听器、被再次转发, 形成应用层死循环。
func isSelfProxy(server string, port uint16) bool {
	if config.ListenPort == 0 || port != config.ListenPort {
		return false
	}
	ip := net.ParseIP(server)
	if ip == nil {
		// 域名形式只挡最常见的 localhost
		return strings.EqualFold(server, "localhost")
	}
	if ip.IsLoopback() {
		return true
	}
	// 指向本机物理网卡 IP / TUN 自身 IP + 监听端口, 同样会回到自己的监听器
	return server == config.TUNBypassIP || server == config.TUNSelfIP
}

// 自代理告警限流: 每秒最多一条, 附被抑制条数, 避免每连接刷屏。
var (
	selfProxyMu   sync.Mutex
	selfProxyLast time.Time
	selfProxySkip int
)

func logSelfProxy(id uint, server string, port uint16) {
	selfProxyMu.Lock()
	now := time.Now()
	if !selfProxyLast.IsZero() && now.Sub(selfProxyLast) < time.Second {
		selfProxySkip++
		selfProxyMu.Unlock()
		return
	}
	skipped := selfProxySkip
	selfProxySkip = 0
	selfProxyLast = now
	selfProxyMu.Unlock()
	log.Println(trace.ID(id), fmt.Sprintf("proxy %s:%d is my own listen address; ignoring to avoid self-loop, going direct. Set a real upstream proxy (+%d suppressed)", server, port, skipped))
}

// resolveProxySpec 解析支持「逗号分隔多代理 + 末尾 local/deny 后缀」的代理配置,
// 单域名 host.proxy 与全局 default.proxy 共用同一套逻辑。
// 依次对每个代理做连通性探测(getProxyServer 内含 300ms 拨号), 返回第一个能连通的;
// 都不可用时 ok=false, opName 指示兜底动作:
//
//	"local": 忽略代理走本地直连(调用方把 proxyServer 置空)
//	"deny" : 拒绝请求
//	""     : 无后缀, 由调用方决定(host 情况回退全局代理)
func resolveProxySpec(id uint, spec string) (scheme, server string, port uint16, opName string, ok bool) {
	switch {
	case strings.HasSuffix(spec, " local"):
		opName = "local"
		spec = strings.TrimSpace(strings.TrimSuffix(spec, " local"))
	case strings.HasSuffix(spec, " deny"):
		opName = "deny"
		spec = strings.TrimSpace(strings.TrimSuffix(spec, " deny"))
	}
	for _, one := range strings.Split(spec, ",") {
		one = strings.TrimSpace(one)
		if one == "" {
			continue
		}
		sc, sv, pt, err := getProxyServer(one)
		if err != nil {
			// 该代理不可用, 记录后尝试下一个
			log.Println(trace.ID(id), "proxy err", err)
			continue
		}
		return sc, sv, pt, "", true
	}
	return "", "", 0, opName, false
}

// isMultiProxySpec 判断代理配置是否为「多代理或带 local/deny 后缀」,
// 需要按请求逐个探测挑选; 否则是简单单代理, 走无探测快路径。
func isMultiProxySpec(spec string) bool {
	return strings.Contains(spec, ",") ||
		strings.HasSuffix(spec, " local") ||
		strings.HasSuffix(spec, " deny")
}

// resolveGlobalProxy 解析全局代理(default.proxy / -p)。
// 简单单代理直接解析、不做连通性探测(保持快路径, 不给每个请求加 300ms);
// 多代理/带后缀则复用 resolveProxySpec 逐个探测挑选并返回 local/deny 兜底。
func resolveGlobalProxy(id uint, spec string) (scheme, server string, port uint16, opName string, ok bool) {
	if isMultiProxySpec(spec) {
		return resolveProxySpec(id, spec)
	}
	sc, sv, pt, err := parseProxyServer(spec)
	if err != nil {
		log.Println(trace.ID(id), "global proxy err", err)
		return "", "", 0, "", false
	}
	return sc, sv, pt, "", true
}

// parseProxyServer 仅解析 scheme/host/port, 不做连通性探测。
func parseProxyServer(proxySpec string) (scheme, server string, port uint16, err error) {
	if proxySpec == "" {
		return "", "", 0, errors.New("proxy 长度为空")
	}
	scheme = "tunnel"
	// 先检查协议
	if tmp := strings.SplitN(proxySpec, "://", 2); len(tmp) == 2 {
		scheme = tmp[0]
		proxySpec = tmp[1]
	}
	// 检查端口，和上面的顺序不能反
	tmp := strings.SplitN(proxySpec, ":", 2)
	if len(tmp) != 2 {
		return "", "", 0, errors.New("proxy 格式不对")
	}
	portInt, err := strconv.Atoi(tmp[1])
	if err != nil {
		return "", "", 0, err
	}
	return scheme, tmp[0], uint16(portInt), nil
}

// getProxyServer 解析代理并做连通性探测(含不可用缓存), 供多代理挑选用。
func getProxyServer(proxySpec string) (string, string, uint16, error) {
	proxyScheme, proxyServer, proxyPort, err := parseProxyServer(proxySpec)
	if err != nil {
		return "", "", 0, err
	}
	key := fmt.Sprintf("%s:%d", proxyServer, proxyPort)
	// 不缓存「不可用」状态: 每次都实拨探测。否则上级代理重启恢复后, 仍会在旧失败缓存
	// 有效期内被判死、导致请求无响应。探测很轻量(200ms 内建连即返回)。
	connTimeout := time.Duration(200) * time.Millisecond
	conn, err := tunDial("tcp", key, connTimeout)
	if err != nil {
		return "", "", 0, err
	}
	conn.Close()
	return proxyScheme, proxyServer, proxyPort, nil
}

// tunProxyDialer 实现 proxy.Dialer，用 tunDial 建连以绕过 TUN 路由。
type tunProxyDialer struct{}

func (tunProxyDialer) Dial(network, addr string) (net.Conn, error) {
	return tunDial(network, addr, 5*time.Second)
}

// socket5代理
func (s *tunnel) socks5(network, connAddr string, targetNet, targetAddr string) (err error) {
	var dialProxy proxy.Dialer
	dialProxy, err = proxy.SOCKS5(network, connAddr, nil, tunProxyDialer{})
	if err != nil {
		log.Println(trace.ID(s.req.ID), "socket5 err", err.Error())
		return
	}

	var conn net.Conn
	conn, err = dialProxy.Dial(targetNet, targetAddr)
	if err != nil {
		log.Println(trace.ID(s.req.ID), "dail err", err.Error())
		return
	}
	s.conn = conn.(*net.TCPConn)
	return
}

// http代理
func (s *tunnel) httpConnect(network, connAddr string, target string, encrypt bool) (err error) {
	err = s.dail(network, connAddr, 0)
	if err != nil {
		log.Println(trace.ID(s.req.ID), "dail err", err.Error())
		return
	}
	var connectString string
	if encrypt {
		key := []byte(getToken())
		var x1 []byte
		x1, err = crypto.EncryptAES([]byte(target), key)
		if err != nil {
			log.Println(trace.ID(s.req.ID), "encrypt err", err.Error())
			return
		}
		// CONNECT实现的加密
		connectString = fmt.Sprintf("CONNECT %s HTTP/1.1\r\n\r\n", base64.StdEncoding.EncodeToString(x1))
	} else {
		connectString = fmt.Sprintf("CONNECT %s HTTP/1.1\r\n\r\n", target)
	}
	fmt.Fprint(s.conn, connectString)
	var status string
	status, err = bufio.NewReader(s.conn).ReadString('\n')
	if err != nil {
		log.Printf("%s PROXY ERR: Could not find response to CONNECT: err=%v", trace.ID(s.req.ID), err)
		return
	}
	// 检查是不是200返回
	if strings.Contains(status, "200") == false {
		log.Printf("%s PROXY ERR: Proxy response to CONNECT was: %s.\n", trace.ID(s.req.ID), strconv.Quote(status))
		err = fmt.Errorf("Proxy response was: %s", strconv.Quote(status))
	}
	return
}

// IP限制
func (s *tunnel) isAllowed(allows []string) (string, bool) {
	// 本机流量默认放行，无需列入 allowIP:
	//   - 回环地址(127.0.0.1/::1): 一定来自本机
	//   - TUN 网卡自身 IP: 本机经 TUN 出来的流量(如 iptables 把 TUN 流量重定向回监听端口)
	if ip := net.ParseIP(s.inboundIP); ip != nil && ip.IsLoopback() {
		return "", true
	}
	if config.TUNSelfIP != "" && s.inboundIP == config.TUNSelfIP {
		return "", true
	}

	allows = append(allows, conf.RouterConfig.AllowIP...)
	if len(allows) == 0 {
		return "", true
	}

	userIP := net.ParseIP(s.inboundIP)
	for _, p := range allows {
		if iPInCIDR(userIP, p) {
			return "", true
		}
	}
	return s.inboundIP, false
}

// iPInCIDR 判断IP地址是否在指定的CIDR范围内,支持ipv4和ipv6
// cidr 示例 "192.168.1.0/24" "2001:db8:1234:5678::/64"
func iPInCIDR(ip net.IP, cidr string) bool {
	_, ipNet, err := net.ParseCIDR(cidr)
	if err != nil {
		// 可能cidr是一个单ip的情况
		return ip.String() == cidr
	}
	return ipNet.Contains(ip)
}
