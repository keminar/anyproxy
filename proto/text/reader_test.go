package text

import (
	"io"
	"strings"
	"testing"

	"github.com/keminar/anyproxy/proto/tcp"
)

// endlessReader 无限吐同一个字节, 永远不给换行符 —— 模拟"只管发、不结行"的对端。
// 不用 strings.Repeat 造一个大字符串: 那样测试自己就先分配了几百 MB, 而这条用例要证
// 的恰恰是"对端不需要真的发那么多, 也能让服务端一直 append 下去"。
type endlessReader struct {
	b byte
	n int64 // 已吐出的字节数, 用来确认上限确实是提前生效的
}

func (e *endlessReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = e.b
	}
	e.n += int64(len(p))
	return len(p), nil
}

// TestReadLineRejectsEndlessLine 一条永不结束的行必须在上限处被拒, 而不是一直 append
// 到把内存吃光。这是 slowloris 的变体: 对端不需要发很多数据, 只要不发 \n。
func TestReadLineRejectsEndlessLine(t *testing.T) {
	src := &endlessReader{b: 'a'}
	r := NewReader(tcp.NewReader(src))

	_, err := r.ReadLine(true)
	if err != ErrLineTooLong {
		t.Fatalf("got err %v, want ErrLineTooLong", err)
	}
	// 上限是 1MB, 底层按 4096 一片读, 所以读进来的量应该在 1MB 上下而不是无限。
	// 给一片的余量(判定发生在 append 之前, 最后那一片已经读进来了)。
	if max := int64(maxLineBytes + 8192); src.n > max {
		t.Errorf("read %d bytes before giving up, want <= %d", src.n, max)
	}
}

// TestReadLineAcceptsNormalLine 限额不能误伤正常请求行。
func TestReadLineAcceptsNormalLine(t *testing.T) {
	const want = "GET /some/path?q=1 HTTP/1.1"
	r := NewReader(tcp.NewReader(strings.NewReader(want + "\r\nrest")))
	got, err := r.ReadLine(true)
	if err != nil {
		t.Fatalf("ReadLine: %v", err)
	}
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// TestReadLineAcceptsLongButBoundedLine 跨底层 buf(4096)的长行仍要能正常拼起来 ——
// 加限额不能顺手把"长但合法"的行一起毙了(带很多参数的 URL、长 Cookie 都会超 4096)。
func TestReadLineAcceptsLongButBoundedLine(t *testing.T) {
	want := "GET /" + strings.Repeat("x", 10000) + " HTTP/1.1"
	r := NewReader(tcp.NewReader(strings.NewReader(want + "\r\n")))
	got, err := r.ReadLine(true)
	if err != nil {
		t.Fatalf("ReadLine: %v", err)
	}
	if got != want {
		t.Fatalf("got %d bytes, want %d", len(got), len(want))
	}
}

// TestReadHeaderRejectsTooManyHeaders 单行合法但条数无限, 同样能把 http.Header 撑爆。
func TestReadHeaderRejectsTooManyHeaders(t *testing.T) {
	var sb strings.Builder
	for i := 0; i < maxHeaderCounts+100; i++ {
		sb.WriteString("X-Pad-")
		sb.WriteString(strings.Repeat("a", 3))
		// 每条 key 要不同, 否则都并进同一个 key 的 value 列表里, 撑的是 slice 不是 map。
		sb.WriteString(itoa(i))
		sb.WriteString(": v\r\n")
	}
	sb.WriteString("\r\n")
	r := NewReader(tcp.NewReader(strings.NewReader(sb.String())))
	if _, err := r.ReadHeader(); err != ErrHeaderTooLarge {
		t.Fatalf("got err %v, want ErrHeaderTooLarge", err)
	}
}

// TestReadHeaderAcceptsNormalHeaders 正常头部不受影响。
func TestReadHeaderAcceptsNormalHeaders(t *testing.T) {
	raw := "Host: example.com\r\nUser-Agent: curl/8.0\r\nAccept: */*\r\n\r\n"
	r := NewReader(tcp.NewReader(strings.NewReader(raw)))
	h, err := r.ReadHeader()
	if err != nil && err != io.EOF {
		t.Fatalf("ReadHeader: %v", err)
	}
	if got := h.Get("Host"); got != "example.com" {
		t.Errorf("Host = %q, want example.com", got)
	}
	if got := h.Get("User-Agent"); got != "curl/8.0" {
		t.Errorf("User-Agent = %q, want curl/8.0", got)
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}
