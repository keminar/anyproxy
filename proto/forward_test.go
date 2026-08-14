package proto

import "testing"

func TestHeadPreview(t *testing.T) {
	cases := []struct {
		name string
		head []byte
		want string
	}{
		{"empty", nil, ""},
		{"http request line", []byte("GET / HTTP/1.1\r\nHost: a.com\r\n"), "GET / HTTP/1.1"},
		{"ssh banner", []byte("SSH-2.0-OpenSSH_8.9\r\n"), "SSH-2.0-OpenSSH_8.9"},
		// TLS ClientHello: 首字节 0x16(不可打印), 应判为 unknown 而非乱码
		{"tls clienthello", []byte{0x16, 0x03, 0x01, 0x02, 0x00, 0x01, 'a', 'b'}, "unknown"},
		// 首行是干净可打印文本、之后才是二进制: 只输出干净首行"ab"(不含任何乱码字节), 可接受
		{"printable line then binary", []byte{'a', 'b', '\n', 0x00, 0x01, 0xff}, "ab"},
		// 首行内即出现不可打印字节(无早期换行): 判为二进制 unknown(用户遇到的乱码场景)
		{"binary before newline", []byte{'a', 0x00, 0x01, 0xff, '\n'}, "unknown"},
		// 纯不可打印
		{"pure binary", []byte{0x00, 0x01, 0x02, 0x03}, "unknown"},
		{"with tab", []byte("a\tb\r\n"), "a\tb"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := headPreview(c.head); got != c.want {
				t.Fatalf("headPreview(%q) = %q, want %q", c.head, got, c.want)
			}
		})
	}
}
