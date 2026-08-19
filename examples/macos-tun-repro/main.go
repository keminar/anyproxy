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
