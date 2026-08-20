package geo

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// ---- 测试内手工编码合成 .dat(与解析器对拍) ----

func tagB(num, wire int) []byte { return appendVarint(nil, uint64(num<<3|wire)) }
func fld2(num int, data []byte) []byte {
	b := tagB(num, 2)
	b = appendVarint(b, uint64(len(data)))
	return append(b, data...)
}
func fld0(num int, v uint64) []byte { return appendVarint(tagB(num, 0), v) }

func domainMsg(typ uint64, val string) []byte {
	var b []byte
	if typ != 0 { // Plain(0) 缺省省略字段, 与真实 .dat 一致
		b = append(b, fld0(1, typ)...)
	}
	return append(b, fld2(2, []byte(val))...)
}
func geoSiteMsg(code string, domains ...[]byte) []byte {
	b := fld2(1, []byte(code))
	for _, d := range domains {
		b = append(b, fld2(2, d)...)
	}
	return b
}
func cidrMsg(ip []byte, prefix uint64) []byte {
	return append(fld2(1, ip), fld0(2, prefix)...)
}
func geoIPMsg(code string, cidrs ...[]byte) []byte {
	b := fld2(1, []byte(code))
	for _, c := range cidrs {
		b = append(b, fld2(2, c)...)
	}
	return b
}
func list(entries ...[]byte) []byte {
	var b []byte
	for _, e := range entries {
		b = append(b, fld2(1, e)...)
	}
	return b
}

func reset() { mu.Lock(); ipM, siteM = nil, nil; mu.Unlock() }

func writeTmp(t *testing.T, name string, data []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, data, 0644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestGeoSiteDat(t *testing.T) {
	reset()
	data := list(
		geoSiteMsg("CN",
			domainMsg(2, "baidu.com"),      // Domain: 后缀
			domainMsg(3, "www.google.cn"),  // Full: 精确
			domainMsg(0, "ads"),            // Plain: 应丢弃
			domainMsg(1, ".*\\.evil\\.cn"), // Regex: 应丢弃
		),
		geoSiteMsg("US", domainMsg(2, "google.com")),
	)
	p := writeTmp(t, "geosite.dat", data)
	if err := LoadSite("cn", p); err != nil {
		t.Fatal(err)
	}
	if err := LoadSite("us", p); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		cat, dom string
		want     bool
	}{
		{"cn", "baidu.com", true},        // 后缀根域
		{"cn", "www.baidu.com", true},    // 后缀子域
		{"cn", "a.b.baidu.com", true},    // 多级子域
		{"cn", "baidu.com.cn", false},    // 不是子域
		{"cn", "notbaidu.com", false},    // 非子域
		{"cn", "www.google.cn", true},    // Full 精确
		{"cn", "x.www.google.cn", false}, // Full 不覆盖子域
		{"cn", "ads.example.com", false}, // Plain 已丢弃
		{"cn", "x.evil.cn", false},       // Regex 已丢弃
		{"CN", "baidu.com", true},        // 类别大小写不敏感
		{"us", "maps.google.com", true},  // 另一类别
		{"cn", "google.com", false},      // 跨类别不串
	}
	for _, c := range cases {
		if got := MatchSite(c.cat, c.dom); got != c.want {
			t.Errorf("MatchSite(%q,%q)=%v want %v", c.cat, c.dom, got, c.want)
		}
	}
	// 缺失类别报错
	if err := LoadSite("kr", p); err == nil {
		t.Error("加载不存在的类别应报错")
	}
}

func TestGeoIPDat(t *testing.T) {
	reset()
	data := list(
		geoIPMsg("CN", cidrMsg([]byte{1, 2, 0, 0}, 16), cidrMsg([]byte{114, 114, 114, 114}, 32)),
		geoIPMsg("US", cidrMsg([]byte{8, 8, 8, 0}, 24)),
	)
	p := writeTmp(t, "geoip.dat", data)
	if err := LoadIP("cn", p); err != nil {
		t.Fatal(err)
	}
	if err := LoadIP("us", p); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		cat, ip string
		want    bool
	}{
		{"cn", "1.2.0.0", true},     // 网络地址
		{"cn", "1.2.128.55", true},  // 段内
		{"cn", "1.2.255.255", true}, // 广播地址(边界)
		{"cn", "1.3.0.0", false},    // 段外
		{"cn", "114.114.114.114", true},
		{"cn", "8.8.8.8", false}, // 属 US
		{"us", "8.8.8.8", true},
		{"cn", "not-an-ip", false}, // 非 IP
	}
	for _, c := range cases {
		if got := MatchIP(c.cat, c.ip); got != c.want {
			t.Errorf("MatchIP(%q,%q)=%v want %v", c.cat, c.ip, got, c.want)
		}
	}
	if last := lastAddr(netip.MustParsePrefix("1.2.0.0/16")); last.String() != "1.2.255.255" {
		t.Errorf("lastAddr=%v want 1.2.255.255", last)
	}
}

// TestGeoIPv6 校验 IPv6 CIDR 匹配(文本列表与 .dat 两条路径, 以及 v4/v6 混存、跨族查询)。
func TestGeoIPv6(t *testing.T) {
	reset()
	// 文本列表: 同一类别混 v4 + v6
	txt := "1.2.0.0/16\n2001:db8::/32\n2402:4e00::/32\n"
	if err := LoadIP("cn", writeTmp(t, "cn-cidr.txt", []byte(txt))); err != nil {
		t.Fatal(err)
	}
	// .dat: v6 CIDR(16 字节 ip)
	v6 := netip.MustParseAddr("2001:db8::").As16()
	dat := writeTmp(t, "geoip.dat", list(geoIPMsg("V6", cidrMsg(v6[:], 32))))
	if err := LoadIP("v6", dat); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		cat, ip string
		want    bool
	}{
		{"cn", "2001:db8::1", true},           // v6 段内
		{"cn", "2001:db8:ffff:ffff::1", true}, // v6 段内(近广播)
		{"cn", "2001:db9::1", false},          // v6 段外
		{"cn", "2402:4e00::1234", true},       // 另一 v6 段
		{"cn", "1.2.3.4", true},               // 同类别 v4 仍命中(v4/v6 混存)
		{"cn", "3.4.5.6", false},              // v4 段外
		{"v6", "2001:db8::abcd", true},        // .dat 的 v6
		{"v6", "2001:db9::1", false},          // .dat v6 段外
		{"v6", "1.2.3.4", false},              // v4 查 v6-only 类别不命中
	}
	for _, c := range cases {
		if got := MatchIP(c.cat, c.ip); got != c.want {
			t.Errorf("MatchIP(%q,%q)=%v want %v", c.cat, c.ip, got, c.want)
		}
	}
	// lastAddr v6 边界
	if last := lastAddr(netip.MustParsePrefix("2001:db8::/32")); last.String() != "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff" {
		t.Errorf("lastAddr v6 = %v", last)
	}
}

// TestTextLists 校验域名文本列表(direct-list.txt 风格)与 CIDR 文本列表。
func TestTextLists(t *testing.T) {
	reset()
	site := "# comment\n" +
		"baidu.com\n" + // 无前缀 = domain 后缀
		"domain:qq.com\n" +
		"full:www.google.cn\n" +
		"keyword:ads\n" + // 丢弃
		"regexp:^.+\\.evil$\n" + // 丢弃
		"taobao.com @cn\n" + // 带属性
		"\n"
	sp := writeTmp(t, "direct-list.txt", []byte(site))
	if err := LoadSite("cn", sp); err != nil {
		t.Fatal(err)
	}
	ip := "# china cidr\n1.2.0.0/16\n114.114.114.114\n"
	ipp := writeTmp(t, "china-cidr.txt", []byte(ip))
	if err := LoadIP("cn", ipp); err != nil {
		t.Fatal(err)
	}
	siteCases := map[string]bool{
		"www.baidu.com": true, "baidu.com": true,
		"x.qq.com": true, "qq.com": true,
		"www.google.cn": true, "x.www.google.cn": false,
		"taobao.com": true, "www.taobao.com": true,
		"ads.com": false, "a.evil": false, "google.com": false,
	}
	for d, want := range siteCases {
		if got := MatchSite("cn", d); got != want {
			t.Errorf("text MatchSite(cn,%q)=%v want %v", d, got, want)
		}
	}
	if !MatchIP("cn", "1.2.3.4") || !MatchIP("cn", "114.114.114.114") || MatchIP("cn", "8.8.8.8") {
		t.Error("text geoip 匹配错误")
	}
}

// TestMergeCategory 校验同一类别可由多个文件(.dat + 文本)合并。
func TestMergeCategory(t *testing.T) {
	reset()
	dat := writeTmp(t, "geosite.dat", list(geoSiteMsg("CN", domainMsg(2, "baidu.com"))))
	txt := writeTmp(t, "extra.txt", []byte("qq.com\n"))
	if err := LoadSite("cn", dat); err != nil {
		t.Fatal(err)
	}
	if err := LoadSite("cn", txt); err != nil {
		t.Fatal(err)
	}
	if !MatchSite("cn", "www.baidu.com") || !MatchSite("cn", "www.qq.com") {
		t.Error("合并后两个来源都应命中")
	}
}

func TestExtractRoundTrip(t *testing.T) {
	reset()
	full := list(
		geoSiteMsg("CN", domainMsg(2, "baidu.com")),
		geoSiteMsg("US", domainMsg(2, "google.com")),
	)
	in := writeTmp(t, "geosite.dat", full)
	out := filepath.Join(t.TempDir(), "geosite-cn.dat")
	if err := Extract(in, []string{"cn"}, out); err != nil {
		t.Fatal(err)
	}
	if err := LoadSite("cn", out); err != nil {
		t.Fatal(err)
	}
	if !MatchSite("cn", "www.baidu.com") {
		t.Error("提取后 cn 应命中")
	}
	if err := LoadSite("us", out); err == nil {
		t.Error("提取后不应含 us")
	}
	if err := Extract(in, []string{"kr"}, out); err == nil {
		t.Error("提取不存在的类别应报错")
	}
}

// TestLoadIPFile 校验新写法: 一个 .dat 一次加载多类别; cats 留空=全部; 文本列表 cats 约束。
func TestLoadIPFile(t *testing.T) {
	reset()
	dat := writeTmp(t, "geoip.dat", list(
		geoIPMsg("CN", cidrMsg([]byte{1, 2, 0, 0}, 16)),
		geoIPMsg("US", cidrMsg([]byte{8, 8, 8, 0}, 24)),
		geoIPMsg("JP", cidrMsg([]byte{9, 9, 9, 0}, 24)),
	))
	// 一个文件一次取多个类别
	if err := LoadIPFile(dat, []string{"cn", "us"}); err != nil {
		t.Fatal(err)
	}
	if !MatchIP("cn", "1.2.3.4") || !MatchIP("us", "8.8.8.8") {
		t.Error("cn/us 应命中")
	}
	if MatchIP("jp", "9.9.9.9") {
		t.Error("未加载的 jp 不应命中")
	}
	if err := LoadIPFile(dat, []string{"kr"}); err == nil {
		t.Error("缺失类别应报错")
	}

	// cats 留空 = 加载全部类别
	reset()
	if err := LoadIPFile(dat, nil); err != nil {
		t.Fatal(err)
	}
	if !MatchIP("cn", "1.2.3.4") || !MatchIP("us", "8.8.8.8") || !MatchIP("jp", "9.9.9.9") {
		t.Error("cats 留空应加载全部类别")
	}
	if ic, _ := Stat(); ic != 3 {
		t.Errorf("应加载 3 个类别, 实际 %d", ic)
	}

	// 文本列表: cats 必须恰好一个
	reset()
	txt := writeTmp(t, "cn.txt", []byte("1.2.0.0/16\n"))
	if err := LoadIPFile(txt, nil); err == nil {
		t.Error("文本列表 cats 留空应报错")
	}
	if err := LoadIPFile(txt, []string{"a", "b"}); err == nil {
		t.Error("文本列表 cats 多个应报错")
	}
	if err := LoadIPFile(txt, []string{"cn"}); err != nil {
		t.Fatal(err)
	}
	if !MatchIP("cn", "1.2.3.4") {
		t.Error("文本列表单类别应命中")
	}
}

// TestLoadSiteFile 校验 geosite 新写法的多类别与 cats 留空=全部。
func TestLoadSiteFile(t *testing.T) {
	reset()
	dat := writeTmp(t, "geosite.dat", list(
		geoSiteMsg("CN", domainMsg(2, "baidu.com")),
		geoSiteMsg("GOOGLE", domainMsg(2, "google.com")),
	))
	if err := LoadSiteFile(dat, nil); err != nil {
		t.Fatal(err)
	}
	if !MatchSite("cn", "www.baidu.com") || !MatchSite("google", "www.google.com") {
		t.Error("cats 留空应加载全部 geosite 类别")
	}
}
