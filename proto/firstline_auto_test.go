package proto

import (
	"net/url"
	"testing"

	"github.com/keminar/anyproxy/utils/conf"
)

func TestParseStatusCode(t *testing.T) {
	cases := []struct {
		name string
		peek string
		want int
	}{
		{"308", "HTTP/1.1 308 Permanent Redirect\r\n", 308},
		{"200", "HTTP/1.1 200 OK\r\n", 200},
		{"shortest possible line", "HTTP/1.1 204 X\r\n", 204},
		{"truncated before code ends", "HTTP/1.1 30", 0},
		{"no space", "garbage", 0},
		{"empty", "", 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := parseStatusCode([]byte(c.peek)); got != c.want {
				t.Fatalf("parseStatusCode(%q) = %d, want %d", c.peek, got, c.want)
			}
		})
	}
}

func TestIsRedirectStatus(t *testing.T) {
	for _, code := range []int{301, 302, 303, 307, 308} {
		if !isRedirectStatus(code) {
			t.Fatalf("isRedirectStatus(%d) = false, want true", code)
		}
	}
	for _, code := range []int{0, 200, 204, 400, 404, 500} {
		if isRedirectStatus(code) {
			t.Fatalf("isRedirectStatus(%d) = true, want false", code)
		}
	}
}

func TestFindLocationHeader(t *testing.T) {
	cases := []struct {
		name string
		peek string
		want string
	}{
		{
			"typical redirect",
			"HTTP/1.1 308 Permanent Redirect\r\nlocation: http://dev.dog.com:5000/\r\nRefresh: 0;url=http://dev.dog.com:5000/\r\n\r\n",
			"http://dev.dog.com:5000/",
		},
		{
			"case insensitive key with extra spaces",
			"HTTP/1.1 301 Moved\r\nLocation:   /foo  \r\n\r\n",
			"/foo",
		},
		{
			"no location header",
			"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n",
			"",
		},
		{
			"truncated before headers finish, no location seen yet",
			"HTTP/1.1 308 Permanent Redirect\r\nX-Foo: bar",
			"",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := findLocationHeader([]byte(c.peek)); got != c.want {
				t.Fatalf("findLocationHeader(%q) = %q, want %q", c.peek, got, c.want)
			}
		})
	}
}

func TestSameSelfRedirectTarget(t *testing.T) {
	base, err := url.Parse("http://dev.dog.com:5000/")
	if err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		loc  string
		want bool
	}{
		{"identical url is a self-redirect", "http://dev.dog.com:5000/", true},
		{"different path is not", "http://dev.dog.com:5000/login", false},
		{"scheme upgrade to https is not", "https://dev.dog.com:5000/", false},
		{"different host is not", "http://other.dog.com:5000/", false},
		{"different query is not", "http://dev.dog.com:5000/?x=1", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			locURL, err := url.Parse(c.loc)
			if err != nil {
				t.Fatal(err)
			}
			resolved := base.ResolveReference(locURL)
			if got := sameSelfRedirectTarget(resolved, base); got != c.want {
				t.Fatalf("sameSelfRedirectTarget(%q, %q) = %v, want %v", c.loc, base, got, c.want)
			}
		})
	}
}

// checkSelfRedirect 是接在 copyBuffer 里的钩子, 传入的是服务端响应"第一个数据块"的原始字节
// (即用户 curl -I dev.dog.com:5000 时后端真实吐出来的那种 308+Location 响应)。
// 命中时必须学到 off, 且 key 要按 firstLineHost 的规则把 host 里的冒号换成点, 否则学到的
// 记录和 firstLineHost 查询时用的 key 对不上，等于白学。
func TestCheckSelfRedirectLearnsFromResponseChunk(t *testing.T) {
	oldLearned := firstLineLearned
	firstLineLearned = map[string]bool{}
	t.Cleanup(func() { firstLineLearned = oldLearned })

	reqURL, err := url.Parse("http://dev.dog.com:5000/")
	if err != nil {
		t.Fatal(err)
	}
	s := &tunnel{
		req:             &Request{ID: 397},
		selfRedirectURL: reqURL,
	}
	chunk := []byte("HTTP/1.1 308 Permanent Redirect\r\n" +
		"location: http://dev.dog.com:5000/\r\n" +
		"Refresh: 0;url=http://dev.dog.com:5000/\r\n\r\n")

	s.checkSelfRedirect(chunk)

	if !isFirstLineLearnedOff("dev.dog.com.5000") {
		t.Fatal("checkSelfRedirect did not learn dev.dog.com.5000 as off after a matching self-redirect")
	}
}

// 普通 200 响应、或跳到不同地址的 3xx，都不该被误判成自重定向死循环。
func TestCheckSelfRedirectIgnoresNonMatches(t *testing.T) {
	oldLearned := firstLineLearned
	firstLineLearned = map[string]bool{}
	t.Cleanup(func() { firstLineLearned = oldLearned })

	reqURL, _ := url.Parse("http://dev.dog.com:5000/")
	cases := map[string][]byte{
		"plain 200":               []byte("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"),
		"redirect to other path":  []byte("HTTP/1.1 302 Found\r\nLocation: /login\r\n\r\n"),
		"redirect with no header": []byte("HTTP/1.1 308 Permanent Redirect\r\n\r\n"),
	}
	for name, chunk := range cases {
		t.Run(name, func(t *testing.T) {
			s := &tunnel{req: &Request{ID: 1}, selfRedirectURL: reqURL}
			s.checkSelfRedirect(chunk)
			if isFirstLineLearnedOff("dev.dog.com.5000") {
				t.Fatalf("case %q should not have learned dev.dog.com.5000 as off", name)
			}
		})
	}
}

// firstLineHost 的优先级必须是: 显式配置(custom) > 自动学到的(learnFirstLineOff) > 全局默认。
// 否则一旦自动学错了, 用户在 router.yaml 里显式配成 on 也压不回来。
func TestFirstLineHostPrecedence(t *testing.T) {
	oldRouter := conf.RouterConfig()
	t.Cleanup(func() { conf.SetRouterConfig(oldRouter) })
	oldLearned := firstLineLearned
	firstLineLearned = map[string]bool{}
	t.Cleanup(func() { firstLineLearned = oldLearned })

	conf.SetRouterConfig(&conf.Router{})
	if got := firstLineHost("plain.example.80"); got != "on" {
		t.Fatalf("default with nothing configured = %q, want on", got)
	}

	learnFirstLineOff(0, "learned.example.5000", "http://learned.example:5000/")
	if got := firstLineHost("learned.example:5000"); got != "off" {
		t.Fatalf("after learning off = %q, want off", got)
	}

	// 显式配成 on 必须能压过自动学到的 off。
	conf.SetRouterConfig(&conf.Router{})
	conf.RouterConfig().FirstLine.Custom = map[string]string{"learned.example.5000": "on"}
	if got := firstLineHost("learned.example:5000"); got != "on" {
		t.Fatalf("explicit custom=on should override auto-learned off, got %q", got)
	}
}
