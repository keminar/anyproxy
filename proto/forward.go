package proto

import (
	"context"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"github.com/keminar/anyproxy/config"
	"github.com/keminar/anyproxy/utils/cache"
	"github.com/keminar/anyproxy/utils/trace"
)

// sniffTimeout 非 HTTP/HTTPS 端口首包嗅探域名的最长等待时间。
// 对"服务端先说话"的协议(SSH/SMTP/MySQL等)会在此超时后回退为按IP转发，
// 必须短，否则会卡住这些协议的握手。
const sniffTimeout = 200 * time.Millisecond

// sniffTimeoutHTTP 是 80/443 端口的嗅探等待上限。
// 这两个端口一定是客户端先说话(HTTP 请求 / TLS ClientHello)，可以放心久等，
// 以覆盖浏览器预连接(preconnect)——TCP 建好后先静默，真正导航时才发请求。
// 正常连接一发数据就立即返回，不会真等到上限；只有静默连接才等满。
// 客户端若在此期间放弃预连接(关闭)，Read 立即返回错误，上层据此提前结束。
const sniffTimeoutHTTP = 5 * time.Second

// ForwardTCP 处理来自TUN虚拟网卡(用户态协议栈)的原始TCP流量。
// 目标地址已由用户态协议栈解析得到，这里直接复用 tunnel 的路由/代理逻辑
// (direct/tunnel/socks5/host规则) 进行转发，逻辑上等价于 tcpStream 的原始转发路径，
// 只是入口连接来自协议栈(net.Conn)而非监听socket。
//
//	clientConn 用户态协议栈产生的连接(如 gvisor gonet.TCPConn)
//	srcIP      来源IP(TUN子网内的地址)，用于白名单和统计
//	dstIP      真实目标IP    dstPort 真实目标端口
func ForwardTCP(ctx context.Context, id uint, clientConn net.Conn, srcIP, dstIP string, dstPort uint16) error {
	req := &Request{
		ctx:     ctx,
		ID:      id,
		Proto:   protoTCP,
		DstIP:   dstIP,
		DstPort: dstPort,
		TUN:     true,
		Raw:     true, // 原始字节透传, http 上级代理须走 CONNECT 隧道
	}
	s := &tunnel{req: req}
	// 不走 newTunnel，来源IP由协议栈提供
	s.inboundIP = srcIP

	// 嗅探首包域名(TLS SNI / HTTP Host)，使配置文件中按域名匹配的代理规则生效。
	// head 为已从客户端读走的首包字节，需在握手后补发给服务端。
	head, dstName, closed := sniffClientHead(clientConn, dstPort)
	if closed {
		// 客户端未发数据即关闭(如浏览器放弃的预连接)，无需拨后端
		return nil
	}
	// 级联场景: 首包是 "CONNECT host:port HTTP/1.1" 说明客机把 dstIP:dstPort 当成了
	// 上级 http 代理(如客机 anyproxy 配了 http://192.168.1.7:3227)。此时 dstIP:dstPort
	// 就是客机精心选定的下一跳。尊重客机意图，本机只做透明管道: 直连该代理地址、原样透传
	// 全部字节(含 CONNECT 头)，由上级代理去处理内层 CONNECT。不消费、不回200、不按内层
	// 域名走本机自己的路由规则(否则会越过客机意图改道到别的代理)。
	if connectHost, connectPort, ok := connectTarget(head); ok {
		// 日志带上内层真实目标(CONNECT行): 客机想访问 connectHost:connectPort，
		// 经由它指定的上级代理 dstIP:dstPort 透传出去。
		log.Println(trace.ID(id), fmt.Sprintf("TUN connect passthrough %s -> %s:%d via %s:%d",
			srcIP, connectHost, connectPort, dstIP, dstPort))
		network, connAddr := s.buildAddress("", dstIP, dstPort, true)
		if err := s.dail(network, connAddr, 0); err != nil {
			log.Println(trace.ID(id), "tun connect passthrough dail err", err.Error())
			return err
		}
		defer s.conn.Close()
		if len(head) > 0 {
			if _, err := s.Write(head); err != nil {
				log.Println(trace.ID(id), "tun connect passthrough write head err", err.Error())
				return err
			}
		}
		s.transferConn(clientConn)
		return nil
	}

	// 仍未拿到域名(服务器先说话协议、或非 80/443 端口超时)时，
	// 按目标 IP 从 DNS 劫持记录还原客户端实际解析过的真实域名，避免误走全局代理。
	if dstName == "" {
		dstName = cache.SniffName.Lookup(dstIP)
	}
	req.DstName = dstName

	// 从首包内容分类协议(https/http/tcp)，使 TUN 也能按 default.target 及
	// 单域名的 http 规则处理，而非一律当 tcp。分不出(无首包)时保持 tcp。
	proto := sniffProto(head)
	req.Proto = proto

	if dstName != "" {
		log.Println(trace.ID(id), fmt.Sprintf("TUN %s %s -> %s (%s:%d)", proto, srcIP, dstName, dstIP, dstPort))
	} else if len(head) > 0 {
		// 首包非空但嗅探不到域名(如SSH服务端banner/MySQL握手等)，截取首行便于识别协议
		headHint := headPreview(head)
		log.Println(trace.ID(id), fmt.Sprintf("TUN %s %s -> %s:%d head=%s", proto, srcIP, dstIP, dstPort, headHint))
	} else {
		log.Println(trace.ID(id), fmt.Sprintf("TUN %s %s -> %s:%d (no head)", proto, srcIP, dstIP, dstPort))
	}

	err := s.handshake(proto, dstName, dstIP, dstPort)
	if err != nil {
		log.Println(trace.ID(id), "tun handshake err", err.Error())
		return err
	}
	defer s.conn.Close()

	// 先把嗅探时读走的首包补发给服务端，保持字节顺序
	if len(head) > 0 {
		if _, err = s.Write(head); err != nil {
			log.Println(trace.ID(id), "tun write head err", err.Error())
			return err
		}
	}

	s.transferConn(clientConn)
	return nil
}

// sniffClientHead 在超时内读取客户端首包并嗅探目标域名。
// 80/443 用长超时等待客户端首包(覆盖浏览器预连接)，其它端口用短超时快速回退。
// 返回: 读到的首包字节(需补发给服务端)、解析到的域名(可能为空)、
// 以及 closed(客户端未发数据即关闭连接，如放弃的预连接，上层可直接结束)。
func sniffClientHead(clientConn net.Conn, dstPort uint16) (head []byte, dstName string, closed bool) {
	timeout := sniffTimeout
	if dstPort == 80 || dstPort == 443 {
		timeout = sniffTimeoutHTTP
	}
	_ = clientConn.SetReadDeadline(time.Now().Add(timeout))
	// 4K 足以容纳绝大多数含PQ密钥交换的 TLS ClientHello
	buf := make([]byte, 4096)
	n, err := clientConn.Read(buf)
	// 清除读超时，恢复正常读
	_ = clientConn.SetReadDeadline(time.Time{})
	if n > 0 {
		head = buf[:n]
		dstName = sniffDomain(head)
		return head, dstName, false
	}
	// 未读到数据: 超时(静默连接/服务器先说话)按无域名继续；
	// 其它错误(EOF/RST 等)说明连接已被客户端关闭，通知上层无需再拨后端
	if err != nil {
		if ne, ok := err.(net.Error); ok && ne.Timeout() {
			return nil, "", false
		}
		return nil, "", true
	}
	return
}

// transferConn 在客户端连接(协议栈)与后端连接之间做双向拷贝。
// 与 tunnel.transfer 不同，这里客户端是 net.Conn(而非 *net.TCPConn)，
// 且不需要 HTTP keep-alive 复用判断，属于纯原始TCP转发。
func (s *tunnel) transferConn(client net.Conn) {
	// 计入 loopguard 在传连接, 结束时释放(key 为空则跳过)
	guard.enter(s.guardKey)
	defer guard.leave(s.guardKey)
	// 结束时补记残余字节, 避免同一分钟内快速完成的连接漏统计
	defer s.flushCounters()
	s.curState = stateActive
	var wg sync.WaitGroup
	wg.Add(2)

	// 请求方向: client -> server
	go func() {
		defer wg.Done()
		var err error
		s.readSize, err = s.copyConn(s.conn, client, "request")
		s.logCopyErr("request->server", err)
		// 请求读完，通知后端不再有上行数据
		s.closeWrite()
	}()

	// 响应方向: server -> client
	go func() {
		defer wg.Done()
		var err error
		s.writeSize, err = s.copyConn(client, s.conn, "server")
		s.logCopyErr("server->request", err)
		// 后端读完，关闭客户端写方向让协议栈发出FIN
		if cw, ok := client.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		} else {
			client.Close()
		}
	}()

	wg.Wait()
	if config.DebugLevel >= config.LevelLong {
		log.Println(trace.ID(s.req.ID), "tun transfer finished, up", s.readSize, "down", s.writeSize)
	}
}

// headPreview 截取首包作为日志预览，便于识别协议类型。
// 文本协议(SSH/HTTP/SMTP等)显示可读字符串；二进制协议显示 hex。
func headPreview(head []byte) string {
	if len(head) == 0 {
		return ""
	}
	// 先扫描一段(最多 64 字节)判断是否为文本行协议: 逐字节看, 遇到行结束符(\r/\n)即为
	// 首行结束、按文本返回; 遇到控制/不可打印字节(含 \t 除外)即判为二进制, 返回 unknown。
	// 关键是「二进制判定」要先于「按行截断」——否则二进制首包里若有早到的 \n 会被截成短前缀
	// 而误判成文本(如 TLS ClientHello、MySQL 握手), 把乱码打进日志。
	end := len(head)
	if end > 64 {
		end = 64
	}
	for i := 0; i < end; i++ {
		b := head[i]
		if b == '\r' || b == '\n' { //首行结束, 前面都是可打印文本
			return string(head[:i])
		}
		if b == '\t' {
			continue
		}
		if b < 32 || b >= 127 { //控制/不可打印字节 -> 二进制
			return "unknown"
		}
	}
	return string(head[:end])
}

// copyConn 单向拷贝并按方向累加上下行流量统计
func (s *tunnel) copyConn(dst io.Writer, src io.Reader, srcname string) (written int64, err error) {
	buf := make([]byte, 4*1024)
	for {
		nr, er := src.Read(buf)
		if nr > 0 {
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
				if srcname == "request" {
					if s.inbountCounter != nil {
						s.inbountCounter.Add(s.req.ID, int64(nw))
					}
				} else {
					if s.outbountCounter != nil {
						s.outbountCounter.Add(s.req.ID, int64(nw))
					}
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
			}
			break
		}
	}
	return written, err
}
