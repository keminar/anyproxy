//go:build !windows
// +build !windows

package tun

import "github.com/keminar/anyproxy/utils/dnsutil"

// DNS 报文解析/构造与 hosts 匹配的纯逻辑已抽到跨平台包 utils/dnsutil，
// 供 gVisor 路径(本文件, 非 Windows)与 WinDivert 引擎(tun/wdengine, Windows)共用。
// 本文件保留包内常量与薄封装，使 tun/udp.go、tun/udp_dns_relay.go 无需改动。
// Windows 构建不含本文件——那条链路直接调用 dnsutil。

// dnsPort 是 DNS 使用的 UDP 端口。
const dnsPort = dnsutil.Port

// httpsPort 是 HTTPS/QUIC 使用的端口(TCP 走 TLS, UDP 走 QUIC/HTTP3)。
const httpsPort = 443

// DNS 查询类型
const (
	dnsTypeA    = dnsutil.TypeA
	dnsTypeAAAA = dnsutil.TypeAAAA
)

func parseDNSQuery(data []byte) (string, uint16) { return dnsutil.ParseQuery(data) }
func buildDNSResponse(query []byte, domain, ip string) []byte {
	return dnsutil.BuildResponse(query, domain, ip)
}
func buildDNSNXDomain(query []byte) []byte            { return dnsutil.BuildNXDomain(query) }
func buildDNSEmpty(query []byte) []byte               { return dnsutil.BuildEmpty(query) }
func matchHostDNS(domain string) (string, bool, bool) { return dnsutil.MatchHostDNS(domain) }
func hostBlocksUDP(dstIP string) bool                 { return dnsutil.HostBlocksUDP(dstIP) }
func blockQUICEnabled() bool                          { return dnsutil.BlockQUICEnabled() }
