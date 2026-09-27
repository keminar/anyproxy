// Package geo 提供按类别的 IP / 域名匹配, 供 hosts 规则 name: geoip:xx / geosite:xx 使用。
//
// 数据来源支持两种(按「类别->文件」配置, 每类别一个文件):
//   - geoip.dat / geosite.dat(protobuf 数据集, 一个文件多类别): 取同名类别;
//   - 纯文本列表(每个文件一个类别): geoip 每行一个 CIDR/IP; geosite 每行一个域名,
//     支持 full:/domain:/keyword:/regexp: 前缀(无前缀默认 domain 后缀), # 注释。
//
// 文件按扩展名区分: .dat=protobuf, 其它=文本。
//
// .dat 用自写的最小 protobuf wire 解析器读取, 不引入 protobuf 依赖、不依赖任何第三方规则库代码。
// geosite 只保留后缀(domain)与精确(full)两种, 丢弃 keyword/regex(当国外域名处理)。
package geo

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
)

// ---- 最小 protobuf wire 解析 ----

func readVarint(b []byte, i int) (val uint64, ni int, ok bool) {
	var shift uint
	for i < len(b) {
		c := b[i]
		i++
		val |= uint64(c&0x7f) << shift
		if c&0x80 == 0 {
			return val, i, true
		}
		shift += 7
		if shift >= 64 {
			return 0, i, false
		}
	}
	return 0, i, false
}

type wireField struct {
	num  int
	wire int
	val  uint64 // wire 0/1/5
	data []byte // wire 2
}

func scanField(b []byte, i int) (f wireField, ni int, ok bool) {
	tag, i, ok := readVarint(b, i)
	if !ok {
		return f, i, false
	}
	f.num = int(tag >> 3)
	f.wire = int(tag & 7)
	switch f.wire {
	case 0:
		f.val, i, ok = readVarint(b, i)
		return f, i, ok
	case 1:
		if i+8 > len(b) {
			return f, i, false
		}
		return f, i + 8, true
	case 2:
		var n uint64
		n, i, ok = readVarint(b, i)
		if !ok || int(n) < 0 || i+int(n) > len(b) {
			return f, i, false
		}
		f.data = b[i : i+int(n)]
		return f, i + int(n), true
	case 5:
		if i+4 > len(b) {
			return f, i, false
		}
		return f, i + 4, true
	default:
		return f, i, false
	}
}

func eachField(b []byte, fn func(f wireField)) bool {
	i := 0
	for i < len(b) {
		f, ni, ok := scanField(b, i)
		if !ok {
			return false
		}
		fn(f)
		i = ni
	}
	return true
}

// wantSet 把类别名列表转为小写集合; cats 为空返回 nil, 表示不过滤(取全部类别)。
func wantSet(cats []string) map[string]bool {
	if len(cats) == 0 {
		return nil
	}
	m := make(map[string]bool, len(cats))
	for _, c := range cats {
		m[strings.ToLower(c)] = true
	}
	return m
}

// entryCode 取一个 Entry(GeoIP/GeoSite) 的 country_code(字段1, string)。
func entryCode(entry []byte) string {
	var code string
	eachField(entry, func(f wireField) {
		if f.num == 1 && f.wire == 2 && code == "" {
			code = string(f.data)
		}
	})
	return code
}

// ---- 数据结构与匹配 ----

type ipRange struct{ start, end netip.Addr }

type ipMatcher struct {
	cats map[string][]ipRange // 小写类别 -> 按 start 排序的区间
}

// siteCat 是解析阶段的临时结构, 加载完成后会被压缩进 compiledSite, 不会常驻内存。
type siteCat struct {
	suffix domainBuilder // 后缀(根域及其子域)
	full   domainBuilder // 精确
}

// domainEntry 是 domainIndex.buf 里一段域名字节的位置。
type domainEntry struct {
	off uint32
	len uint16
}

// domainIndex 把一批域名压缩存储: 所有域名字符拼成一块 buf(不重复分配 string),
// entries 按域名内容升序排列、记录每个域名在 buf 里的偏移, 查询用二分查找。
// 相比 map[string]struct{}(每个域名一份独立 string + hash 表槽位开销), 省去了
// 逐域名的固定开销, 只保留域名字符本身占用的内存。
type domainIndex struct {
	buf     []byte
	entries []domainEntry // 按 buf[off:off+len] 的字节内容升序
}

// compareBytesString 按字节比较 b 与 s, 不做任何内存分配。
func compareBytesString(b []byte, s string) int {
	n := len(b)
	if len(s) < n {
		n = len(s)
	}
	for i := 0; i < n; i++ {
		if b[i] != s[i] {
			if b[i] < s[i] {
				return -1
			}
			return 1
		}
	}
	switch {
	case len(b) < len(s):
		return -1
	case len(b) > len(s):
		return 1
	default:
		return 0
	}
}

// contains 二分查找 target 是否在索引中。
func (idx domainIndex) contains(target string) bool {
	lo, hi := 0, len(idx.entries)
	for lo < hi {
		mid := (lo + hi) / 2
		e := idx.entries[mid]
		c := compareBytesString(idx.buf[e.off:int(e.off)+int(e.len)], target)
		switch {
		case c < 0:
			lo = mid + 1
		case c > 0:
			hi = mid
		default:
			return true
		}
	}
	return false
}

// domainBuilder 增量拼接域名字节到一段连续 buf, 解析阶段直接写入目标存储形态,
// 不为每个域名单独分配 string/map 项。finish() 前 entries 未排序、可能含重复。
type domainBuilder struct {
	buf     []byte
	entries []domainEntry
}

func (b *domainBuilder) add(s string) {
	off := uint32(len(b.buf))
	b.buf = append(b.buf, s...)
	b.entries = append(b.entries, domainEntry{off: off, len: uint16(len(s))})
}

// finish 按 buf 中的字节内容排序+去重 entries, 复用同一个 buf(不拷贝), 返回可
// 直接查询的 domainIndex。去重后 buf 里可能残留少量被跳过的重复域名字节, 不回收
// (真实规则文件里类别内域名重复本就罕见, 这点浪费可忽略)。
func (b domainBuilder) finish() domainIndex {
	if len(b.entries) == 0 {
		return domainIndex{}
	}
	sort.Slice(b.entries, func(i, j int) bool {
		ei, ej := b.entries[i], b.entries[j]
		return bytes.Compare(b.buf[ei.off:int(ei.off)+int(ei.len)], b.buf[ej.off:int(ej.off)+int(ej.len)]) < 0
	})
	n := 0
	for i, e := range b.entries {
		if i > 0 {
			p := b.entries[n-1]
			if bytes.Equal(b.buf[e.off:int(e.off)+int(e.len)], b.buf[p.off:int(p.off)+int(p.len)]) {
				continue
			}
		}
		b.entries[n] = e
		n++
	}
	return domainIndex{buf: b.buf, entries: b.entries[:n]}
}

// mergeIndex 把 add(未排序/可能重复的解析结果)合入 old, 返回新的 domainIndex
// (old 不会被修改)。
func mergeIndex(old domainIndex, add domainBuilder) domainIndex {
	if len(add.entries) == 0 {
		return old
	}
	na := add.finish()
	if len(old.entries) == 0 {
		return na
	}
	buf := make([]byte, 0, len(old.buf)+len(na.buf))
	entries := make([]domainEntry, 0, len(old.entries)+len(na.entries))
	i, j := 0, 0
	for i < len(old.entries) && j < len(na.entries) {
		oe, ne := old.entries[i], na.entries[j]
		os := old.buf[oe.off : int(oe.off)+int(oe.len)]
		ns := na.buf[ne.off : int(ne.off)+int(ne.len)]
		switch bytes.Compare(os, ns) {
		case -1:
			off := uint32(len(buf))
			buf = append(buf, os...)
			entries = append(entries, domainEntry{off: off, len: oe.len})
			i++
		case 1:
			off := uint32(len(buf))
			buf = append(buf, ns...)
			entries = append(entries, domainEntry{off: off, len: ne.len})
			j++
		default:
			off := uint32(len(buf))
			buf = append(buf, os...)
			entries = append(entries, domainEntry{off: off, len: oe.len})
			i++
			j++
		}
	}
	for ; i < len(old.entries); i++ {
		oe := old.entries[i]
		os := old.buf[oe.off : int(oe.off)+int(oe.len)]
		off := uint32(len(buf))
		buf = append(buf, os...)
		entries = append(entries, domainEntry{off: off, len: oe.len})
	}
	for ; j < len(na.entries); j++ {
		ne := na.entries[j]
		ns := na.buf[ne.off : int(ne.off)+int(ne.len)]
		off := uint32(len(buf))
		buf = append(buf, ns...)
		entries = append(entries, domainEntry{off: off, len: ne.len})
	}
	return domainIndex{buf: buf, entries: entries}
}

// compiledSite 是最终常驻内存、供 match() 只读查询的结构。
type compiledSite struct {
	suffix domainIndex
	full   domainIndex
}

type siteMatcher struct {
	cats map[string]*compiledSite
}

func (m *ipMatcher) match(cat string, ip netip.Addr) bool {
	rs := m.cats[cat]
	if len(rs) == 0 {
		return false
	}
	ip = ip.Unmap()
	idx := sort.Search(len(rs), func(i int) bool { return rs[i].start.Compare(ip) > 0 }) - 1
	if idx < 0 {
		return false
	}
	return ip.Compare(rs[idx].start) >= 0 && ip.Compare(rs[idx].end) <= 0
}

func (m *siteMatcher) match(cat, domain string) bool {
	c := m.cats[cat]
	if c == nil {
		return false
	}
	domain = strings.ToLower(strings.TrimSuffix(domain, "."))
	if c.full.contains(domain) {
		return true
	}
	for s := domain; ; {
		if c.suffix.contains(s) {
			return true
		}
		i := strings.IndexByte(s, '.')
		if i < 0 {
			return false
		}
		s = s[i+1:]
	}
}

// lastAddr 返回前缀内最后一个地址(广播地址)。
func lastAddr(p netip.Prefix) netip.Addr {
	a := p.Addr()
	if a.Is4() {
		v := a.As4()
		u := binary.BigEndian.Uint32(v[:])
		if host := 32 - p.Bits(); host >= 32 {
			u = 0xffffffff
		} else if host > 0 {
			u |= (uint32(1) << host) - 1
		}
		binary.BigEndian.PutUint32(v[:], u)
		return netip.AddrFrom4(v)
	}
	v := a.As16()
	for bit := 0; bit < 128-p.Bits(); bit++ {
		v[15-bit/8] |= 1 << (bit % 8)
	}
	return netip.AddrFrom16(v)
}

func prefixRange(p netip.Prefix) ipRange {
	p = p.Masked()
	return ipRange{start: p.Addr(), end: lastAddr(p)}
}

// ---- .dat(protobuf) 解析 ----

// datIPCats 解析 GeoIPList -> 小写类别 -> CIDR 区间。
// cats 非空时只解码所需类别, 其余条目仅取 country_code 判断后跳过, 不展开其 IP 列表(节省内存)。
func datIPCats(data []byte, cats []string) (map[string][]ipRange, error) {
	want := wantSet(cats)
	out := map[string][]ipRange{}
	if !eachField(data, func(f wireField) {
		if f.num != 1 || f.wire != 2 {
			return
		}
		code := strings.ToLower(entryCode(f.data))
		if code == "" || (want != nil && !want[code]) {
			return
		}
		eachField(f.data, func(g wireField) {
			if g.num == 2 && g.wire == 2 {
				if r, ok := parseCIDR(g.data); ok {
					out[code] = append(out[code], r)
				}
			}
		})
	}) {
		return nil, fmt.Errorf("geoip: 解析失败(非法 protobuf)")
	}
	return out, nil
}

func parseCIDR(b []byte) (ipRange, bool) {
	var ipb []byte
	var prefix uint64
	eachField(b, func(f wireField) {
		switch {
		case f.num == 1 && f.wire == 2:
			ipb = f.data
		case f.num == 2 && f.wire == 0:
			prefix = f.val
		}
	})
	addr, ok := netip.AddrFromSlice(ipb)
	if !ok {
		return ipRange{}, false
	}
	p := netip.PrefixFrom(addr.Unmap(), int(prefix))
	if !p.IsValid() {
		return ipRange{}, false
	}
	return prefixRange(p), true
}

// datSiteCats 解析 GeoSiteList -> 小写类别 -> siteCat(只留 Domain/Full)。
// cats 非空时只解码所需类别, 其余条目仅取 country_code 判断后跳过, 不展开其域名列表(节省内存)。
func datSiteCats(data []byte, cats []string) (map[string]*siteCat, error) {
	want := wantSet(cats)
	out := map[string]*siteCat{}
	if !eachField(data, func(f wireField) {
		if f.num != 1 || f.wire != 2 {
			return
		}
		code := strings.ToLower(entryCode(f.data))
		if code == "" || (want != nil && !want[code]) {
			return
		}
		c := out[code]
		if c == nil {
			c = &siteCat{}
			out[code] = c
		}
		eachField(f.data, func(g wireField) {
			if g.num == 2 && g.wire == 2 {
				typ, val := parseDomain(g.data)
				val = normDomain(val)
				if val == "" {
					return
				}
				switch typ {
				case 2:
					c.suffix.add(val)
				case 3:
					c.full.add(val)
				}
			}
		})
	}) {
		return nil, fmt.Errorf("geosite: 解析失败(非法 protobuf)")
	}
	return out, nil
}

func parseDomain(b []byte) (typ uint64, value string) {
	eachField(b, func(f wireField) {
		switch {
		case f.num == 1 && f.wire == 0:
			typ = f.val
		case f.num == 2 && f.wire == 2:
			value = string(f.data)
		}
	})
	return
}

// ---- 文本列表解析 ----

// textIPRanges 解析 CIDR/IP 文本列表(每行一个, # 注释, 行内可带空格属性)。
func textIPRanges(data []byte) []ipRange {
	var out []ipRange
	forEachLine(data, func(line string) {
		if p, err := netip.ParsePrefix(line); err == nil {
			out = append(out, prefixRange(p))
		} else if a, err := netip.ParseAddr(line); err == nil {
			a = a.Unmap()
			out = append(out, ipRange{start: a, end: a})
		}
	})
	return out
}

// textSiteCat 解析域名文本列表: full:/domain:/keyword:/regexp: 前缀, 无前缀默认 domain(后缀)。
// keyword/regexp 丢弃(当国外域名)。
func textSiteCat(data []byte) *siteCat {
	c := &siteCat{}
	forEachLine(data, func(line string) {
		typ, val := "domain", line
		if k := strings.IndexByte(line, ':'); k >= 0 {
			typ, val = strings.ToLower(line[:k]), line[k+1:]
		}
		val = normDomain(val)
		if val == "" {
			return
		}
		switch typ {
		case "full":
			c.full.add(val)
		case "domain":
			c.suffix.add(val)
			// keyword / regexp: 丢弃
		}
	})
	return c
}

// forEachLine 去注释、去行内空格属性、去空行后回调每行。
func forEachLine(data []byte, fn func(line string)) {
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimSpace(raw)
		if i := strings.IndexByte(line, '#'); i >= 0 {
			line = strings.TrimSpace(line[:i])
		}
		if line == "" {
			continue
		}
		if i := strings.IndexAny(line, " \t"); i >= 0 { // 去掉如 " @cn" 的属性
			line = line[:i]
		}
		if line != "" {
			fn(line)
		}
	}
}

func normDomain(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

// ---- 全局注册与加载(按 类别->文件, 可多文件合并) ----

var (
	mu    sync.RWMutex
	ipM   *ipMatcher
	siteM *siteMatcher
)

func isDat(path string) bool { return strings.HasSuffix(strings.ToLower(path), ".dat") }

// LoadIPFile 读取 path 一次, 把其中类别加载/合并进 geoip(同一文件只解析一次)。
//   - .dat(protobuf, 一个文件多类别): cats 非空则按名取(缺失报错); cats 为空则加载文件内全部类别。
//   - 文本列表(非 .dat): 整个文件即一个类别, cats 必须恰好给一个类别名。
func LoadIPFile(path string, cats []string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	toMerge := map[string][]ipRange{}
	if isDat(path) {
		all, err := datIPCats(data, cats)
		if err != nil {
			return err
		}
		if len(cats) == 0 { // 全部类别
			for k, v := range all {
				toMerge[k] = v
			}
			if len(toMerge) == 0 {
				return fmt.Errorf("%s 中无任何 geoip 类别", path)
			}
		} else {
			for _, c := range cats {
				k := strings.ToLower(c)
				rs := all[k]
				if len(rs) == 0 {
					return fmt.Errorf("%s 中无 geoip 类别 %q", path, c)
				}
				toMerge[k] = rs
			}
		}
	} else {
		if len(cats) != 1 {
			return fmt.Errorf("%s 为文本列表, 需恰好一个类别名(cats), 实际 %d 个", path, len(cats))
		}
		rs := textIPRanges(data)
		if len(rs) == 0 {
			return fmt.Errorf("%s 未解析出任何 CIDR/IP", path)
		}
		toMerge[strings.ToLower(cats[0])] = rs
	}
	mu.Lock()
	defer mu.Unlock()
	if ipM == nil {
		ipM = &ipMatcher{cats: map[string][]ipRange{}}
	}
	for k, rs := range toMerge {
		ipM.cats[k] = append(ipM.cats[k], rs...)
		s := ipM.cats[k]
		sort.Slice(s, func(i, j int) bool { return s[i].start.Compare(s[j].start) < 0 })
	}
	return nil
}

// LoadSiteFile 读取 path 一次, 把其中类别加载/合并进 geosite(同一文件只解析一次)。
//   - .dat: cats 非空按名取(缺失报错); cats 为空则加载文件内全部类别。
//   - 文本列表: 整个文件即一个类别, cats 必须恰好给一个类别名。
func LoadSiteFile(path string, cats []string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	toMerge := map[string]*siteCat{}
	if isDat(path) {
		all, err := datSiteCats(data, cats)
		if err != nil {
			return err
		}
		if len(cats) == 0 { // 全部类别
			for k, v := range all {
				toMerge[k] = v
			}
			if len(toMerge) == 0 {
				return fmt.Errorf("%s 中无任何 geosite 类别", path)
			}
		} else {
			for _, c := range cats {
				k := strings.ToLower(c)
				sc := all[k]
				if sc == nil || (len(sc.suffix.entries) == 0 && len(sc.full.entries) == 0) {
					return fmt.Errorf("%s 中无 geosite 类别 %q", path, c)
				}
				toMerge[k] = sc
			}
		}
	} else {
		if len(cats) != 1 {
			return fmt.Errorf("%s 为文本列表, 需恰好一个类别名(cats), 实际 %d 个", path, len(cats))
		}
		sc := textSiteCat(data)
		if len(sc.suffix.entries) == 0 && len(sc.full.entries) == 0 {
			return fmt.Errorf("%s 未解析出任何域名", path)
		}
		toMerge[strings.ToLower(cats[0])] = sc
	}
	mu.Lock()
	defer mu.Unlock()
	if siteM == nil {
		siteM = &siteMatcher{cats: map[string]*compiledSite{}}
	}
	for k, sc := range toMerge {
		dst := siteM.cats[k]
		if dst == nil {
			dst = &compiledSite{}
			siteM.cats[k] = dst
		}
		dst.suffix = mergeIndex(dst.suffix, sc.suffix)
		dst.full = mergeIndex(dst.full, sc.full)
	}
	return nil
}

// LoadIP 把 path(.dat 取同名类别; 文本整文件)加载/合并到类别 cat 的 geoip。
// 单类别便捷封装, 等价 LoadIPFile(path, []string{cat})。
func LoadIP(cat, path string) error { return LoadIPFile(path, []string{cat}) }

// LoadSite 同 LoadIP, 作用于 geosite。
func LoadSite(cat, path string) error { return LoadSiteFile(path, []string{cat}) }

// HasIP / HasSite 报告对应数据是否已加载。
func HasIP() bool   { mu.RLock(); defer mu.RUnlock(); return ipM != nil && len(ipM.cats) > 0 }
func HasSite() bool { mu.RLock(); defer mu.RUnlock(); return siteM != nil && len(siteM.cats) > 0 }

// MatchIP 判断 host(IP 字面量)是否命中 geoip 类别 cat。非 IP 或未加载返回 false。
func MatchIP(cat, host string) bool {
	ip, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	mu.RLock()
	m := ipM
	mu.RUnlock()
	if m == nil {
		return false
	}
	return m.match(strings.ToLower(cat), ip)
}

// MatchSite 判断 domain 是否命中 geosite 类别 cat。未加载返回 false。
func MatchSite(cat, domain string) bool {
	mu.RLock()
	m := siteM
	mu.RUnlock()
	if m == nil || domain == "" {
		return false
	}
	return m.match(strings.ToLower(cat), domain)
}

// Stat 返回已加载的 geoip / geosite 类别数, 供启动日志。
func Stat() (ipCats, siteCats int) {
	mu.RLock()
	defer mu.RUnlock()
	if ipM != nil {
		ipCats = len(ipM.cats)
	}
	if siteM != nil {
		siteCats = len(siteM.cats)
	}
	return
}
