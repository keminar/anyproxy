package nat

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	quic "github.com/quic-go/quic-go"
)

// 直连用的 UDP 反射器。
//
// 为什么非要有它: websocket 是 TCP, 服务端从这条连接上看到的源地址是订阅方**TCP
// socket** 的地址; 而 QUIC 走的是另一个 UDP socket。IPv6 虽然通常没有 NAT, 但一台机器
// 常同时持有多个全局地址(稳定地址 + 会轮换的隐私临时地址), 内核按 RFC 6724 **按目的地
// 分别选源** —— 去 B 的 TCP 用哪个地址, 不代表去 A 的 UDP 也用同一个; 隐私地址还会轮换,
// 通告出去的地址可能已经作废。
//
// 所以端点只能由订阅方**用 QUIC 那个 socket 本身**去问反射器要, 拿反射器观测到的
// 地址+端口, 再经 websocket 通告。这跟 examples/nat-punch 的结论是同一条: 本机自报的
// 地址不可靠, 只有对端观测到的才作数。

const (
	// directPacketMagic 是我们自己那些非 QUIC 报文(探测/回包/打洞包)的首字节。
	//
	// 不能随便取值: 这些包与 QUIC 报文共用同一个 socket, quic-go 只把**首字节前两位
	// 都为 0**(即 <= 0x3F)的报文交给 ReadNonQUICPacket, 其余一律按 QUIC 报文处理并丢弃。
	// 直接用 "WHOAMI"/"PUNCH" 这类可见字符开头('W'=0x57, 'a'=0x61)第二位是 1, 会被
	// quic-go 吞掉, 探测永远收不到回包。
	directPacketMagic = 0x00
	// directWhoami 探测包内容(前面还要加 directPacketMagic), 反射器回观测到的地址。
	directWhoami = "ANYPROXY-DIRECT-WHOAMI"
	// directPunchPayload 打洞包内容。内容本身无意义, 作用只是"让这个包发出去",
	// 从而在本机这侧的有状态防火墙上开出允许对端回包的状态。
	directPunchPayload = "ANYPROXY-DIRECT-PUNCH"
	// directProbeWait 单次探测等待回包的上限。
	directProbeWait = 3 * time.Second
	// directProbeTries 探测重试次数: UDP 会丢包, 一次没回不代表反射器不可用。
	directProbeTries = 3
)

// directPacket 给自定义报文加上 magic 前缀。
func directPacket(payload string) []byte {
	b := make([]byte, 0, len(payload)+1)
	b = append(b, directPacketMagic)
	return append(b, payload...)
}

// directPayload 剥掉 magic 前缀; 不是我们的包则返回 false。
func directPayload(b []byte) (string, bool) {
	if len(b) < 1 || b[0] != directPacketMagic {
		return "", false
	}
	return string(b[1:]), true
}

// StartDirectReflector 在服务端起 UDP 反射器。绑在与 websocket 相同的端口号上
// (TCP/UDP 互不冲突), 订阅方据此可直接从 websocket 的连接地址推出反射器地址, 不用额外配置。
func StartDirectReflector(wsListen string) {
	_, port, err := net.SplitHostPort(wsListen)
	if err != nil {
		log.Printf("nat direct reflector: bad websocket listen address %s: %v", wsListen, err)
		return
	}
	// 绑双栈通配地址: IPv4 接入的订阅方也能问, 只是问到的会是 IPv4 地址, 直连那步会
	// 明确失败(不静默回落)。
	addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort("", port))
	if err != nil {
		log.Printf("nat direct reflector: resolve :%s: %v", port, err)
		return
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Printf("nat direct reflector: listen udp :%s: %v (direct endpoint discovery unavailable)", port, err)
		return
	}
	log.Printf("nat direct reflector listening on udp %s", conn.LocalAddr())
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := conn.ReadFromUDP(buf)
			if err != nil {
				log.Printf("nat direct reflector read: %v", err)
				return
			}
			payload, ok := directPayload(buf[:n])
			if !ok || payload != directWhoami {
				continue
			}
			// 与 websocket 接入、裸TCP转发入口同一套来源白名单。不做限制的话, 这里
			// 就成了一个人人可用的地址反射服务(响应比请求略大, 可被拿来做反射放大)。
			if !serverIPAllowed(from.IP.String()) {
				continue
			}
			// 回包也要带 magic: 对端是用 QUIC 的那个 socket 收的, 不带前缀会被
			// quic-go 当成 QUIC 报文丢掉。
			if _, err := conn.WriteToUDP(directPacket(from.String()), from); err != nil {
				log.Printf("nat direct reflector reply to %s: %v", from, err)
			}
		}
	}()
}

// reflectorAddr 由 websocket 的连接地址推出反射器地址: 同主机、同端口号、UDP。
// 强制解析为 udp6 —— 直连以 IPv6 为前提, 这里就把"其实没有 IPv6"暴露出来, 而不是
// 拖到拨号阶段。
func reflectorAddr(wsConnect string) (*net.UDPAddr, error) {
	host, port, err := net.SplitHostPort(wsConnect)
	if err != nil {
		return nil, fmt.Errorf("bad websocket connect address %s: %w", wsConnect, err)
	}
	addr, err := net.ResolveUDPAddr("udp6", net.JoinHostPort(host, port))
	if err != nil {
		return nil, fmt.Errorf("resolve %s as udp6 (does the server have an IPv6 address?): %w", wsConnect, err)
	}
	return addr, nil
}

// probeEndpoint 用 QUIC 那个 socket 去问反射器"我在你眼里是什么地址", 返回观测到的
// 端点。必须用同一个 socket: 换个 socket 问出来的端口就不是 QUIC 实际用的那个了。
func (d *directPeer) probeEndpoint() (string, error) {
	tr, err := d.ensureTransport()
	if err != nil {
		return "", err
	}
	raddr, err := reflectorAddr(d.cfg.Connect)
	if err != nil {
		return "", err
	}

	reply := make(chan string, 1)
	d.probeMu.Lock()
	d.probeWait = reply
	d.probeFrom = raddr.String()
	d.probeMu.Unlock()
	defer func() {
		d.probeMu.Lock()
		d.probeWait = nil
		d.probeMu.Unlock()
	}()

	var lastErr error
	for i := 0; i < directProbeTries; i++ {
		if _, err := tr.WriteTo(directPacket(directWhoami), raddr); err != nil {
			lastErr = fmt.Errorf("send probe to %s: %w", raddr, err)
			continue
		}
		select {
		case seen := <-reply:
			return seen, nil
		case <-time.After(directProbeWait):
			lastErr = fmt.Errorf("no reply from reflector %s", raddr)
		}
	}
	if lastErr == nil {
		lastErr = errors.New("endpoint probe failed")
	}
	return "", lastErr
}

// drainNonQUIC 收 QUIC socket 上的非 QUIC 报文: 反射器的回包送给等待中的探测, 其余
// (对端的打洞包)只记一行日志。不读的话这些包会一直堆在 quic-go 的内部队列里。
func (d *directPeer) drainNonQUIC(tr *quic.Transport) {
	buf := make([]byte, 1500)
	for {
		n, addr, err := tr.ReadNonQUICPacket(context.Background(), buf)
		if err != nil {
			return
		}
		payload, ok := directPayload(buf[:n])
		if !ok {
			continue // 不是我们的包
		}
		d.probeMu.Lock()
		ch, from := d.probeWait, d.probeFrom
		d.probeMu.Unlock()
		if ch != nil && addr != nil && addr.String() == from && looksLikeEndpoint(payload) {
			select {
			case ch <- payload:
			default:
			}
			continue
		}
		// 收到对端的打洞包说明它确实朝我们发过包了, 记一行有助于排查"到底哪边没打洞"。
		d.logf("got punch packet from %s", addr)
	}
}

// looksLikeEndpoint 粗筛反射器回包: 必须能拆成 host:port, 免得把打洞包当成回包。
func looksLikeEndpoint(s string) bool {
	if len(s) == 0 || len(s) > 128 || strings.Contains(s, " ") {
		return false
	}
	_, _, err := net.SplitHostPort(s)
	return err == nil
}
