package dnsutil

import (
	"encoding/binary"
	"testing"
)

// buildQuery 拼一个最小的合法 DNS 查询: 12 字节头 + question(labels + qtype + qclass)。
func buildQuery(qdcount uint16, labels []string, withTrailer bool) []byte {
	q := make([]byte, 12)
	binary.BigEndian.PutUint16(q[0:2], 0x1234) // ID
	binary.BigEndian.PutUint16(q[2:4], 0x0100) // RD=1
	binary.BigEndian.PutUint16(q[4:6], qdcount)
	for _, l := range labels {
		q = append(q, byte(len(l)))
		q = append(q, []byte(l)...)
	}
	q = append(q, 0x00) // 根标签, question 结束
	if withTrailer {
		q = append(q, 0x00, 0x01, 0x00, 0x01) // qtype=A, qclass=IN
	}
	return q
}

// TestBuildResponseMalformedQuery 畸形/截断的查询不能让 BuildResponse panic。
//
// 这条路径在 TUN 的 DNS 拦截里, 每个到 53 端口的 UDP 包都会过, 而且**不在**
// grace/conn.go 那个 per-connection recover 的保护范围内: 一个畸形包 panic 掀掉的是
// 整个 TUN 处理循环, 不是一条连接。所以这里宁可返回 nil(让上层照常转给真实 DNS),
// 也不能算出一个越界的 qEnd。
//
// 触发点: question 段内层循环是靠 qEnd >= len(query) 退出的, 不是靠读到 0 长度标签,
// 走到末尾后那句 qEnd += 4 就越过了缓冲区。BuildEmpty 一直有这道检查, BuildResponse
// 漏了 —— 这组用例把三个 Build* 放在一起比, 免得以后再改出同样的不一致。
func TestBuildResponseMalformedQuery(t *testing.T) {
	cases := []struct {
		name  string
		query []byte
	}{
		// question 说有一条, 但标签没写完就结束了(没有 0 根标签、没有 qtype/qclass)。
		{"truncated question", buildQuery(1, []string{"example"}, false)[:16]},
		// 标签长度字段声称 200 字节, 报文里根本没那么多。
		{"label length overruns packet", append(buildQuery(1, nil, false)[:12], 200, 'a', 'b')},
		// 有根标签但缺 qtype/qclass 那 4 字节 —— 正是 qEnd += 4 越界的那一格。
		{"missing qtype/qclass", buildQuery(1, []string{"a"}, false)},
		// qdcount 谎报成 5, 实际只有一条 question。
		{"qdcount larger than actual", buildQuery(5, []string{"a"}, true)},
		// 只有头, 没有 question。
		{"header only", buildQuery(1, nil, false)[:12]},
		// 比一个 DNS 头还短。
		{"shorter than header", []byte{0x12, 0x34}},
		{"empty", nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// 三个都不能 panic。用例失败时 go test 会把 panic 算作失败并打出栈,
			// 不需要自己 recover。
			BuildResponse(c.query, "example.com", "10.0.0.1")
			BuildEmpty(c.query)
			BuildNXDomain(c.query)
		})
	}
}

// TestBuildResponseWellFormed 修了边界之后, 正常查询仍要能正确应答 —— 别把 A 记录应答
// 一起堵死了。
func TestBuildResponseWellFormed(t *testing.T) {
	query := buildQuery(1, []string{"example", "com"}, true)
	resp := BuildResponse(query, "example.com", "10.1.2.3")
	if resp == nil {
		t.Fatal("a well-formed query must get an answer")
	}
	if got := binary.BigEndian.Uint16(resp[0:2]); got != 0x1234 {
		t.Errorf("transaction ID = %#x, want 0x1234", got)
	}
	if resp[2] != 0x81 || resp[3] != 0x80 {
		t.Errorf("flags = %#x %#x, want 0x81 0x80 (QR=1 RD=1 RA=1 RCODE=0)", resp[2], resp[3])
	}
	if got := binary.BigEndian.Uint16(resp[6:8]); got != 1 {
		t.Errorf("ancount = %d, want 1", got)
	}
	// 末 4 字节是 rdata, 即应答的 IPv4。
	if ip := resp[len(resp)-4:]; ip[0] != 10 || ip[1] != 1 || ip[2] != 2 || ip[3] != 3 {
		t.Errorf("rdata = %v, want 10.1.2.3", ip)
	}
	// 空应答走同一段 question 解析, 顺带确认它没被影响。
	if BuildEmpty(query) == nil {
		t.Error("BuildEmpty must answer a well-formed query")
	}
}
