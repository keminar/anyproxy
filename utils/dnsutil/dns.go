// Package dnsutil 提供与平台无关的 DNS 报文解析/构造与 hosts 规则匹配。
//
// 这些逻辑原先内嵌在 tun/dns.go(仅 gVisor 路径使用)，抽出为独立包后可被
// 两条链路共用: 非 Windows 的 gVisor UDP 转发(tun/udp.go 的 handleDNS)，
// 以及 Windows 的 WinDivert 捕获引擎(tun/wdengine)。函数均为纯逻辑，只读取
// conf.RouterConfig，不依赖任何平台特有类型。
package dnsutil

import (
	"encoding/binary"
	"strings"

	"github.com/keminar/anyproxy/utils/conf"
)

// Port 是 DNS 使用的 UDP 端口。
const Port = 53

// defaultBlackholeIP 是黑洞哨兵 IP 的默认值。192.0.0.0 属 IANA 特殊用途(IETF Protocol
// Assignments), 不会是真实业务目标, 不可路由, 适合作"本地拦截、经代理才可达"的哨兵。
const defaultBlackholeIP = "192.0.0.0"

// BlackholeIP 返回配置的黑洞哨兵 IP(default.blackholeIP)。不配默认 192.0.0.0;
// 显式配 off/none/disable 则返回空串(功能关闭)。
func BlackholeIP() string {
	s := ""
	if conf.RouterConfig != nil {
		s = strings.TrimSpace(conf.RouterConfig.Default.BlackholeIP)
	}
	switch strings.ToLower(s) {
	case "":
		return defaultBlackholeIP
	case "off", "none", "disable":
		return ""
	default:
		return s
	}
}

// IsBlackholeIP 判断给定 IP 是否为当前生效的黑洞哨兵 IP。
func IsBlackholeIP(ip string) bool {
	if ip == "" {
		return false
	}
	bh := BlackholeIP()
	return bh != "" && ip == bh
}

// DNS 查询类型
const (
	TypeA    = 1  // IPv4 地址记录
	TypeAAAA = 28 // IPv6 地址记录
)

// ParseQuery 从 DNS 查询报文中提取查询的域名和查询类型。解析失败返回空串。
func ParseQuery(data []byte) (domain string, qtype uint16) {
	// DNS 报文最小长度: 12字节头 + 5字节最短Question
	if len(data) < 17 {
		return
	}
	// header: id(2) flags(2) qdcount(2) ancount(2) nscount(2) arcount(2)
	qdcount := int(binary.BigEndian.Uint16(data[4:6]))
	if qdcount == 0 {
		return
	}
	p := 12
	var labels []string
	for {
		if p >= len(data) {
			return "", 0
		}
		l := int(data[p])
		if l == 0 {
			p++
			break
		}
		if p+1+l > len(data) {
			return "", 0
		}
		labels = append(labels, string(data[p+1:p+1+l]))
		p += 1 + l
	}
	if len(labels) == 0 {
		return
	}
	domain = strings.Join(labels, ".")
	// 读 qtype(2) + qclass(2)
	if p+4 > len(data) {
		return "", 0
	}
	qtype = binary.BigEndian.Uint16(data[p : p+2])
	return
}

// BuildResponse 构造一个 DNS A 记录响应报文。
// query 为原始查询报文(含 header)，answerIP 为要返回的 IPv4 地址。
func BuildResponse(query []byte, domain string, answerIP string) []byte {
	if len(query) < 12 {
		return nil
	}
	ipParts := strings.Split(answerIP, ".")
	if len(ipParts) != 4 {
		return nil
	}

	// 计算 question 段结束位置
	qEnd := 12
	qdcount := int(binary.BigEndian.Uint16(query[4:6]))
	for i := 0; i < qdcount; i++ {
		for qEnd < len(query) {
			l := int(query[qEnd])
			if l == 0 {
				qEnd++
				break
			}
			qEnd += 1 + l
		}
		qEnd += 4 // qtype(2) + qclass(2)
	}

	// 响应 = 原始header(修改flags) + 原始question + answer
	resp := make([]byte, qEnd)
	copy(resp, query[:qEnd])

	// 修改 flags: QR=1(响应), RD=1(复制), RA=1(递归可用), RCODE=0(无错误)
	// byte0: QR(1bit) Opcode(4bit) AA(1bit) TC(1bit) RD(1bit) => 0x81
	// byte1: RA(1bit) Z(3bit) RCODE(4bit) => 0x80
	resp[2] = 0x81
	resp[3] = 0x80

	// ancount = 1
	binary.BigEndian.PutUint16(resp[6:8], 1)

	// Answer 段
	// 使用指针压缩引用 question 中的域名: 0xC00C -> 指向偏移12
	answer := make([]byte, 16)                      // name(2) + type(2) + class(2) + ttl(4) + rdlength(2) + rdata(4)
	binary.BigEndian.PutUint16(answer[0:2], 0xC00C) // name 指针
	binary.BigEndian.PutUint16(answer[2:4], 1)      // type = A
	binary.BigEndian.PutUint16(answer[4:6], 1)      // class = IN
	binary.BigEndian.PutUint32(answer[6:10], 60)    // TTL = 60s
	binary.BigEndian.PutUint16(answer[10:12], 4)    // rdlength = 4
	answer[12] = atob(ipParts[0])
	answer[13] = atob(ipParts[1])
	answer[14] = atob(ipParts[2])
	answer[15] = atob(ipParts[3])

	resp = append(resp, answer...)
	return resp
}

// BuildNXDomain 构造一个 NXDOMAIN 响应(RCODE=3)，用于 hosts 中 target=deny 的域名。
func BuildNXDomain(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	resp := make([]byte, 12)
	copy(resp, query[:12])
	resp[2] = 0x81 // QR=1, RD=1
	resp[3] = 0x83 // RA=1, RCODE=3(NXDOMAIN)
	// ancount=0, nscount=0, arcount=0 (已经是0)
	return resp
}

// BuildEmpty 构造一个 NOERROR 空应答(RCODE=0, ANCOUNT=0)，回显原始 question。
// 语义为"域名存在但无该类型记录"，用于对已配置 IPv4 的域名回应 AAAA 查询，
// 让浏览器干净地回退到 A 记录，避免转发真实 DNS 拿到 NXDOMAIN 污染整个域名解析。
func BuildEmpty(query []byte) []byte {
	if len(query) < 12 {
		return nil
	}
	// 计算 question 段结束位置
	qEnd := 12
	qdcount := int(binary.BigEndian.Uint16(query[4:6]))
	for i := 0; i < qdcount; i++ {
		for qEnd < len(query) {
			l := int(query[qEnd])
			if l == 0 {
				qEnd++
				break
			}
			qEnd += 1 + l
		}
		qEnd += 4 // qtype(2) + qclass(2)
	}
	if qEnd > len(query) {
		return nil
	}
	resp := make([]byte, qEnd)
	copy(resp, query[:qEnd])
	resp[2] = 0x81                           // QR=1, RD=1
	resp[3] = 0x80                           // RA=1, RCODE=0(NOERROR)
	binary.BigEndian.PutUint16(resp[6:8], 0) // ancount=0
	return resp
}

// MatchHostDNS 在 hosts 配置中查找域名的 IP 映射。
// 返回: IP(如匹配到ip配置), deny(如target为deny), matched(是否匹配到任何规则)。
func MatchHostDNS(domain string) (ip string, deny bool, matched bool) {
	if conf.RouterConfig == nil {
		return
	}
	defMatch := conf.RouterConfig.Default.Match
	for _, h := range conf.RouterConfig.Hosts {
		if h.Matched(domain, defMatch) {
			return h.IP, h.Target == "deny", true
		}
	}
	return
}

// HostBlocksUDP 判断目标 IP 是否属于「hosts 中配了 ip 的域名」。
// 这类域名的 DNS 已被本地劫持成配置的 ip，但 QUIC(UDP443) 会拿着该劫持 ip 直接
// 出网、绕过应生效的 TCP+SNI 代理路径。命中则由调用方 drop 该 UDP 包，逼客户端
// 回退 TCP 443 走代理链。
//
// 只用 dstIP 精确等于某个 host.ip 判定(确定性、唯一)。不做 IP->域名反查:
// 一个 IP 可对应多个域名(CDN/共用IP)，反查不唯一、不能作为安全判定依据。
// deny 域名在 DNS 层已返回 NXDOMAIN、客户端拿不到 IP，天然发不出 QUIC，无需在此处理。
func HostBlocksUDP(dstIP string) bool {
	if conf.RouterConfig == nil {
		return false
	}
	for _, h := range conf.RouterConfig.Hosts {
		if h.IP != "" && h.IP == dstIP {
			return true
		}
	}
	return false
}

// BlockQUICEnabled 返回是否启用 QUIC(UDP443) 阻断, 不配置默认 true。
func BlockQUICEnabled() bool {
	if conf.RouterConfig == nil {
		return false
	}
	b := conf.RouterConfig.Tun.BlockQUIC
	return b == nil || *b
}

func atob(s string) byte {
	var n byte
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			break
		}
		n = n*10 + (s[i] - '0')
	}
	return n
}
