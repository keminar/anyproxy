package nat

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"
)

// 端口映射: 主动让家用路由器把一个外网端口转到本机的 QUIC 端口, 得到第三类候选。
//
// 它和反射器探测互补。反射器告诉你"NAT 已经给你开的那个洞在哪", 前提是那个洞存在且
// 对第三方也开放(端点无关映射); 端口映射则是直接要一个洞, 对付的是**对称 NAT** ——
// 那种给每个目的地都换一个外网端口的 NAT, 反射器问到的端口对第三方根本没用。
//
// 三种协议都试, 谁先成谁算数:
//
//	PCP     (RFC 6887) 较新, 同时覆盖 IPv4 NAT 与 IPv6 防火墙开洞
//	NAT-PMP (RFC 6886) PCP 的前身, 老设备只认它; 与 PCP 同用 UDP 5351
//	UPnP IGD            最普及, 但要 SSDP 发现 + SOAP, 步骤最重
//
// 都失败很正常, 只是少一个候选。尤其是运营商级 NAT(CGNAT)下: 路由器上映射成功了,
// 拿到的也只是运营商内网地址, 外面依旧进不来 —— 除非 ISP 自己支持 PCP, 而这在国内
// 基本没有。所以别指望它救 CGNAT, 它救的是"有公网 IPv4 但 NAT 是对称型"那种情况。

const (
	// portmapLifetime 申请的映射时长。短了要频繁续租, 长了路由器上会攒一堆废映射。
	portmapLifetime = 2 * time.Hour
	// portmapWait 单个协议的整体超时。三种协议是并行试的, 所以这不叠加。
	portmapWait = 2 * time.Second
	// pcpPort PCP 与 NAT-PMP 共用的服务端口。
	pcpPort = 5351
	// ssdpPort UPnP 的 SSDP 发现端口。
	ssdpPort = 1900
)

// errNoPortmap 三种协议都没成。
var errNoPortmap = errors.New("no port mapping protocol answered (upnp/pcp/nat-pmp)")

// mapPort 试着把 localPort 映射到网关的一个外网端口, 返回 "外网IP:外网端口"。
//
// 三种协议并行发起, 取最先成功的那个 —— 串行的话老设备上 PCP 要等满超时才轮到
// NAT-PMP, 而整个候选收集是有时限的。
func mapPort(localPort uint16) (string, error) {
	if localPort == 0 {
		return "", errors.New("local socket is not bound yet")
	}
	gw, err := defaultGateway()
	if err != nil {
		return "", err
	}

	type res struct {
		ep  string
		err error
	}
	out := make(chan res, 3)
	var wg sync.WaitGroup
	for _, fn := range []func(net.IP, uint16) (string, error){pcpMap, natpmpMap, upnpMap} {
		wg.Add(1)
		go func(f func(net.IP, uint16) (string, error)) {
			defer wg.Done()
			ep, err := f(gw, localPort)
			out <- res{ep, err}
		}(fn)
	}
	go func() { wg.Wait(); close(out) }()

	var errs []string
	for r := range out {
		if r.err == nil && r.ep != "" {
			return r.ep, nil
		}
		if r.err != nil {
			errs = append(errs, r.err.Error())
		}
	}
	if len(errs) > 0 {
		return "", fmt.Errorf("%w: %s", errNoPortmap, strings.Join(errs, "; "))
	}
	return "", errNoPortmap
}

// defaultGateway 猜默认网关: 取本机第一个私有 IPv4 所在网段的 .1。
//
// 这是个猜测, 不是查路由表。查路由表要按平台各写一套(Linux 读 /proc/net/route,
// Windows 调 GetBestRoute, macOS 走 sysctl), 而网关不是 .1 的家用网络很少见; 猜错的
// 代价也只是三个协议都收不到回应, 少一个候选而已, 不值得为它背三套平台代码。
func defaultGateway() (net.IP, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return nil, err
	}
	for _, a := range addrs {
		ipnet, ok := a.(*net.IPNet)
		if !ok {
			continue
		}
		v4 := ipnet.IP.To4()
		if v4 == nil || !ipnet.IP.IsPrivate() {
			continue
		}
		gw := make(net.IP, 4)
		copy(gw, v4.Mask(ipnet.Mask))
		gw[3] |= 1
		if !gw.Equal(v4) {
			return gw, nil
		}
	}
	return nil, errors.New("no private IPv4 interface, cannot guess a gateway")
}

// pcpMap 走 PCP (RFC 6887) 申请一个 MAP 映射。
//
// 请求是定长二进制: 24 字节公共头 + 36 字节 MAP 操作码字段。
func pcpMap(gw net.IP, localPort uint16) (string, error) {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: gw, Port: pcpPort})
	if err != nil {
		return "", fmt.Errorf("pcp dial: %w", err)
	}
	defer conn.Close()

	// 客户端地址要填本机在这条路上的地址, 用 Dial 之后的本地地址即可。
	local := conn.LocalAddr().(*net.UDPAddr).IP.To16()

	req := make([]byte, 60)
	req[0] = 2 // version
	req[1] = 1 // opcode MAP, R=0 表示请求
	binary.BigEndian.PutUint32(req[4:8], uint32(portmapLifetime.Seconds()))
	copy(req[8:24], local)
	// nonce: 12 字节, 用于把响应与请求对上, 也防止别人改我们的映射。
	nonce := make([]byte, 12)
	copy(nonce, newNonce())
	copy(req[24:36], nonce)
	req[36] = 17 // protocol = UDP
	binary.BigEndian.PutUint16(req[40:42], localPort)
	binary.BigEndian.PutUint16(req[42:44], localPort) // 建议的外网端口, 网关可改
	// 44:60 是建议的外网地址, 留全 0 让网关自己定。

	if _, err := conn.Write(req); err != nil {
		return "", fmt.Errorf("pcp write: %w", err)
	}
	conn.SetReadDeadline(time.Now().Add(portmapWait))
	resp := make([]byte, 1100)
	n, err := conn.Read(resp)
	if err != nil {
		return "", fmt.Errorf("pcp: no reply: %w", err)
	}
	if n < 60 {
		return "", fmt.Errorf("pcp: short reply (%d bytes)", n)
	}
	if resp[0] != 2 || resp[1] != 0x81 { // 0x80|1: MAP 的响应
		return "", fmt.Errorf("pcp: unexpected reply version/opcode %d/%#x", resp[0], resp[1])
	}
	if code := resp[3]; code != 0 {
		return "", fmt.Errorf("pcp: gateway refused, result code %d", code)
	}
	extPort := binary.BigEndian.Uint16(resp[42:44])
	extIP := net.IP(resp[44:60])
	if v4 := extIP.To4(); v4 != nil {
		extIP = v4
	}
	if extIP.IsUnspecified() || extPort == 0 {
		return "", errors.New("pcp: gateway returned an empty mapping")
	}
	return net.JoinHostPort(extIP.String(), fmt.Sprint(extPort)), nil
}

// natpmpMap 走 NAT-PMP (RFC 6886): 先问外网地址, 再申请映射。两步都要, 因为映射响应
// 里只有端口没有地址。
func natpmpMap(gw net.IP, localPort uint16) (string, error) {
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: gw, Port: pcpPort})
	if err != nil {
		return "", fmt.Errorf("nat-pmp dial: %w", err)
	}
	defer conn.Close()

	ask := func(req []byte, wantOp byte, minLen int) ([]byte, error) {
		if _, err := conn.Write(req); err != nil {
			return nil, err
		}
		conn.SetReadDeadline(time.Now().Add(portmapWait))
		buf := make([]byte, 64)
		n, err := conn.Read(buf)
		if err != nil {
			return nil, err
		}
		if n < minLen {
			return nil, fmt.Errorf("short reply (%d bytes)", n)
		}
		if buf[0] != 0 || buf[1] != wantOp {
			return nil, fmt.Errorf("unexpected reply version/opcode %d/%d", buf[0], buf[1])
		}
		if code := binary.BigEndian.Uint16(buf[2:4]); code != 0 {
			return nil, fmt.Errorf("gateway refused, result code %d", code)
		}
		return buf[:n], nil
	}

	// 操作 0: 取外网地址。
	ext, err := ask([]byte{0, 0}, 128, 12)
	if err != nil {
		return "", fmt.Errorf("nat-pmp external address: %w", err)
	}
	extIP := net.IPv4(ext[8], ext[9], ext[10], ext[11])
	if extIP.IsUnspecified() {
		return "", errors.New("nat-pmp: gateway has no external address")
	}

	// 操作 1: 申请 UDP 映射。
	req := make([]byte, 12)
	req[1] = 1 // UDP
	binary.BigEndian.PutUint16(req[4:6], localPort)
	binary.BigEndian.PutUint16(req[6:8], localPort)
	binary.BigEndian.PutUint32(req[8:12], uint32(portmapLifetime.Seconds()))
	resp, err := ask(req, 129, 16)
	if err != nil {
		return "", fmt.Errorf("nat-pmp map: %w", err)
	}
	extPort := binary.BigEndian.Uint16(resp[10:12])
	if extPort == 0 {
		return "", errors.New("nat-pmp: gateway returned port 0")
	}
	return net.JoinHostPort(extIP.String(), fmt.Sprint(extPort)), nil
}
