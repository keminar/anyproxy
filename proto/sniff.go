package proto

import (
	"bytes"
	"net"
	"strconv"
	"strings"
)

// sniffProto 从首包内容判断应用层协议: https(TLS)/http/tcp。
// data 为空(未读到首包，如服务器先说话或超时)返回 tcp。
// 注意: 能分类的前提是客户端已发数据，属"事后确认"，不能用来事前决定是否等待。
func sniffProto(data []byte) string {
	if len(data) == 0 {
		return protoTCP
	}
	// TLS handshake record 首字节为 0x16
	if data[0] == 0x16 {
		return protoHTTPS
	}
	if isHTTPRequestLine(data) {
		return protoHTTP
	}
	return protoTCP
}

// isHTTPRequestLine 判断首包是否以 HTTP 请求行开头(方法 空格 路径 空格 HTTP/x)。
func isHTTPRequestLine(data []byte) bool {
	end := bytes.IndexByte(data, '\n')
	if end < 0 {
		end = len(data)
	}
	firstLine := data[:end]
	// 请求行须含 "HTTP/" 且有方法与路径之间的空格
	return bytes.Contains(firstLine, []byte("HTTP/")) && bytes.IndexByte(firstLine, ' ') > 0
}

// sniffDomain 从连接首包中嗅探目标域名。
// TUN/透明代理只拿得到目标IP，域名是客户端在本地DNS解析后才连接的，
// 因此要让配置文件里按域名(hosts.name)匹配的代理规则生效，需要从流量里还原域名:
//   - HTTPS/TLS: 解析 ClientHello 的 SNI 扩展
//   - HTTP:      解析请求头里的 Host
//
// 解析不出则返回空串，调用方回退为按IP匹配。
func sniffDomain(data []byte) string {
	if len(data) == 0 {
		return ""
	}
	// TLS handshake record 首字节为 0x16
	if data[0] == 0x16 {
		if name := sniffTLSServerName(data); name != "" {
			return name
		}
		return ""
	}
	// HTTP 明文请求
	return sniffHTTPHost(data)
}

// sniffHTTPHost 从HTTP请求头中取 Host(去掉端口)
func sniffHTTPHost(data []byte) string {
	// 提取请求行(首行)。用整个 data 找首个换行，避免像 CONNECT 这种只有请求行、
	// 紧跟 \r\n\r\n 的报文，被 \r\n\r\n 截断后 head 里反而不含换行符。
	firstLineEnd := bytes.IndexByte(data, '\n')
	if firstLineEnd < 0 {
		return ""
	}
	firstLine := bytes.TrimRight(data[:firstLineEnd], "\r")
	// 必须像一个请求行(方法 空格 路径 空格 HTTP/)
	if !bytes.Contains(firstLine, []byte("HTTP/")) {
		return ""
	}
	// CONNECT 请求(隧道，含级联 http 代理转发的 CONNECT)通常不带 Host 头，
	// 域名就在请求行的 authority 位置: "CONNECT host:port HTTP/1.1"，直接取。
	// 若 authority 是纯 IP(非域名)则不返回，交由上层按 IP 处理。
	if bytes.HasPrefix(firstLine, []byte("CONNECT ")) {
		fields := bytes.Fields(firstLine)
		if len(fields) >= 2 {
			authority := stripPort(string(fields[1]))
			if net.ParseIP(authority) == nil {
				return authority
			}
			return ""
		}
	}
	// 从 Host 头获取域名。同时也尝试从请求行的绝对 URL 中提取，防止首包只读到请求行、
	// Host 头尚未出现在嗅探缓冲区的情况(如 TCP 分段导致 Read 只返回前半部分)。
	hostFromHeader := sniffHostHeader(data)
	if hostFromHeader != "" {
		return hostFromHeader
	}
	return sniffHostFromURL(firstLine)
}

// sniffHostHeader 从 HTTP 请求头中提取 Host 字段的值(去端口)。
func sniffHostHeader(data []byte) string {
	head := data
	if end := bytes.Index(data, []byte("\r\n\r\n")); end >= 0 {
		head = data[:end]
	}
	for _, line := range bytes.Split(head, []byte("\r\n")) {
		i := bytes.IndexByte(line, ':')
		if i < 0 {
			continue
		}
		if strings.EqualFold(string(bytes.TrimSpace(line[:i])), "host") {
			host := strings.TrimSpace(string(line[i+1:]))
			return stripPort(host)
		}
	}
	return ""
}

// sniffHostFromURL 从请求行的绝对 URL 中提取域名(如 "GET http://example.com/path HTTP/1.1")。
// 仅当 URL 是完整绝对路径(含 scheme://)时才提取，否则返回空。
// 用于首包只读到请求行、Host 头尚未进入嗅探缓冲区的场景。
func sniffHostFromURL(firstLine []byte) string {
	fields := bytes.Fields(firstLine)
	if len(fields) < 2 {
		return ""
	}
	// 跳过 CONNECT，它已在 sniffHTTPHost 中单独处理
	if bytes.Equal(fields[0], []byte("CONNECT")) {
		return ""
	}
	urlBytes := fields[1]
	schemeEnd := bytes.Index(urlBytes, []byte("://"))
	if schemeEnd < 0 {
		return ""
	}
	hostStart := schemeEnd + 3
	hostPart := urlBytes[hostStart:]
	// 截取到 / 或 :
	hostEnd := bytes.IndexByte(hostPart, '/')
	if hostEnd < 0 {
		hostEnd = bytes.IndexByte(hostPart, ':')
	}
	if hostEnd < 0 {
		hostEnd = len(hostPart)
	}
	host := string(hostPart[:hostEnd])
	if net.ParseIP(host) != nil {
		return ""
	}
	return host
}

// stripPort 去掉 host 中的端口部分, 兼容IPv6字面量
func stripPort(host string) string {
	if host == "" {
		return ""
	}
	if strings.HasPrefix(host, "[") { // [::1]:80
		if j := strings.Index(host, "]"); j >= 0 {
			return host[1:j]
		}
		return host
	}
	if i := strings.LastIndex(host, ":"); i >= 0 {
		return host[:i]
	}
	return host
}

// connectTarget 从 CONNECT 请求行解析真实目标 host 和 port。
// 形如 "CONNECT www.example.com:443 HTTP/1.1"，返回 host="www.example.com", port=443。
// 非 CONNECT 或解析失败返回 ok=false。TUN 级联到 http 代理时，真实目标端口在
// CONNECT 行里(而非 TCP 连接的目标端口，那是代理端口)，必须从这里取。
func connectTarget(data []byte) (host string, port uint16, ok bool) {
	nl := bytes.IndexByte(data, '\n')
	if nl < 0 {
		return "", 0, false
	}
	firstLine := bytes.TrimRight(data[:nl], "\r")
	if !bytes.HasPrefix(firstLine, []byte("CONNECT ")) {
		return "", 0, false
	}
	fields := bytes.Fields(firstLine)
	if len(fields) < 2 {
		return "", 0, false
	}
	authority := string(fields[1]) // host:port
	h, p, err := net.SplitHostPort(authority)
	if err != nil || h == "" || p == "" {
		return "", 0, false
	}
	pn, err := strconv.Atoi(p)
	if err != nil || pn <= 0 || pn > 65535 {
		return "", 0, false
	}
	return h, uint16(pn), true
}

// sniffTLSServerName 解析 TLS ClientHello 的 SNI(server_name)扩展。
// 全程做边界检查，任何异常返回空串。
func sniffTLSServerName(b []byte) string {
	// TLS record: type(1) version(2) length(2) => 5 字节头
	if len(b) < 5 || b[0] != 0x16 {
		return ""
	}
	recLen := int(b[3])<<8 | int(b[4])
	msg := b[5:]
	if len(msg) < recLen {
		// 首包可能未收全，仅用已有部分尽力解析
		recLen = len(msg)
	}
	msg = msg[:recLen]

	// Handshake: type(1)=ClientHello(0x01) length(3)
	if len(msg) < 4 || msg[0] != 0x01 {
		return ""
	}
	hsLen := int(msg[1])<<16 | int(msg[2])<<8 | int(msg[3])
	body := msg[4:]
	if len(body) > hsLen {
		body = body[:hsLen]
	}

	// client_version(2) + random(32)
	if len(body) < 34 {
		return ""
	}
	p := body[34:]

	// session_id
	if len(p) < 1 {
		return ""
	}
	sidLen := int(p[0])
	p = p[1:]
	if len(p) < sidLen {
		return ""
	}
	p = p[sidLen:]

	// cipher_suites
	if len(p) < 2 {
		return ""
	}
	csLen := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) < csLen {
		return ""
	}
	p = p[csLen:]

	// compression_methods
	if len(p) < 1 {
		return ""
	}
	cmLen := int(p[0])
	p = p[1:]
	if len(p) < cmLen {
		return ""
	}
	p = p[cmLen:]

	// extensions
	if len(p) < 2 {
		return ""
	}
	extTotal := int(p[0])<<8 | int(p[1])
	p = p[2:]
	if len(p) > extTotal {
		p = p[:extTotal]
	}

	for len(p) >= 4 {
		extType := int(p[0])<<8 | int(p[1])
		extLen := int(p[2])<<8 | int(p[3])
		p = p[4:]
		if len(p) < extLen {
			return ""
		}
		ext := p[:extLen]
		p = p[extLen:]

		if extType != 0x0000 { // server_name
			continue
		}
		// server_name_list: list_length(2) 之后是若干 (type(1) len(2) name)
		if len(ext) < 2 {
			return ""
		}
		listLen := int(ext[0])<<8 | int(ext[1])
		list := ext[2:]
		if len(list) > listLen {
			list = list[:listLen]
		}
		for len(list) >= 3 {
			nameType := list[0]
			nameLen := int(list[1])<<8 | int(list[2])
			list = list[3:]
			if len(list) < nameLen {
				return ""
			}
			name := list[:nameLen]
			list = list[nameLen:]
			if nameType == 0x00 { // host_name
				return string(name)
			}
		}
		return ""
	}
	return ""
}
