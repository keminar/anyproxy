package cache

import (
	"log"
	"sync"
	"time"

	"github.com/keminar/anyproxy/config"
	"github.com/keminar/anyproxy/utils/trace"
)

// ResolveLookup 解析缓存
var ResolveLookup *resolveLookupCache

// SniffName TUN DNS 劫持的 IP->域名 记录。
// 浏览器预连接(preconnect)不发数据，TCP 首包嗅探不到域名时，
// 按目标 IP 还原出客户端实际解析过的真实域名，供按域名匹配代理规则。
var SniffName *sniffNameCache

// ProxyDial 上游代理连通性缓存: 记录最近探测失败(不可用)的代理地址,
// 有效期内直接跳过 300ms 拨号探测, 避免每个请求都对已知挂掉的代理白等一次。
var ProxyDial *proxyDialCache

func init() {
	ResolveLookup = newResolveLookupCache()
	SniffName = newSniffNameCache()
	ProxyDial = newProxyDialCache()
}

// DialState 状态
type DialState int

const (
	//StateNew 新值，未dial失败值
	StateNew DialState = iota
	//StateFail ipv4地址 dial失败
	StateFail
	//StateNone 不存在的地址
	StateNone
)

type cacheEntry struct {
	ipv4    string    //ip v4地址
	state   DialState //是否可连通
	expires time.Time
}
type resolveLookupCache struct {
	ips  map[string]*cacheEntry
	keys []string
	next int
	mu   sync.Mutex
}

// newResolveLookupCache 初始化
func newResolveLookupCache() *resolveLookupCache {
	return &resolveLookupCache{
		ips:  make(map[string]*cacheEntry),
		keys: make([]string, 65536),
	}
}

// Lookup 查找
func (c *resolveLookupCache) Lookup(logID uint, host string) (string, DialState) {
	c.mu.Lock()
	defer c.mu.Unlock()
	hit := c.ips[host]
	if hit != nil {
		if hit.expires.After(time.Now()) {
			if config.DebugLevel >= config.LevelDebug {
				log.Println(trace.ID(logID), "lookup(): CACHE_HIT", hit.state)
			}
			return hit.ipv4, hit.state
		}
		if config.DebugLevel >= config.LevelDebug {
			log.Println(trace.ID(logID), "lookup(): CACHE_EXPIRED")
		}
		delete(c.ips, host)
	} else {
		if config.DebugLevel >= config.LevelDebug {
			log.Println(trace.ID(logID), "lookup(): CACHE_MISS")
		}
	}
	return "", StateNone
}

// Store 保存，只有65535个位置，删除之前的占用
func (c *resolveLookupCache) Store(host, ipv4 string, state DialState, d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	hit := c.ips[host]
	if hit != nil {
		hit.ipv4 = ipv4
		hit.state = state
		hit.expires = time.Now().Add(d)
		return
	}
	// 删除原位置内的值
	delete(c.ips, c.keys[c.next])
	c.keys[c.next] = host
	c.next = (c.next + 1) & 65535
	c.ips[host] = &cacheEntry{ipv4: ipv4, state: state, expires: time.Now().Add(d)}
}

type sniffNameEntry struct {
	name    string
	expires time.Time
}

// sniffNameCache 保存 TUN DNS 劫持的 IP->域名 映射。
// key 恒为配置 hosts.ip 的固定 IP，条数天然受配置规模约束(通常几十条)，
// 故用普通 map 自适应大小、按需增长，无需预分配环形缓冲，惰性删除过期项。
type sniffNameCache struct {
	m  map[string]*sniffNameEntry
	mu sync.Mutex
}

func newSniffNameCache() *sniffNameCache {
	return &sniffNameCache{
		m: make(map[string]*sniffNameEntry),
	}
}

// Store 记录 ip->域名，d 为有效期。
func (c *sniffNameCache) Store(ip, name string, d time.Duration) {
	if ip == "" || name == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if hit := c.m[ip]; hit != nil {
		hit.name = name
		hit.expires = time.Now().Add(d)
		return
	}
	c.m[ip] = &sniffNameEntry{name: name, expires: time.Now().Add(d)}
}

// Lookup 按 ip 还原域名，未命中或已过期返回空串(顺带删除过期项)。
func (c *sniffNameCache) Lookup(ip string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	hit := c.m[ip]
	if hit == nil {
		return ""
	}
	if !hit.expires.After(time.Now()) {
		delete(c.m, ip)
		return ""
	}
	return hit.name
}

// proxyDialCache 记录不可用代理地址(key 为 host:port)。
// 代理地址基数很小(通常几个), 故用普通 map 惰性删除过期项, 无需环形缓冲。
type proxyDialCache struct {
	m  map[string]time.Time //key -> 不可用状态过期时间
	mu sync.Mutex
}

func newProxyDialCache() *proxyDialCache {
	return &proxyDialCache{m: make(map[string]time.Time)}
}

// Bad 报告该代理是否处于「不可用」缓存有效期内(命中即可跳过拨号探测)。
// 顺带删除已过期项。
func (c *proxyDialCache) Bad(key string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	exp, ok := c.m[key]
	if !ok {
		return false
	}
	if !exp.After(time.Now()) {
		delete(c.m, key)
		return false
	}
	return true
}

// MarkBad 标记代理不可用, d 为有效期。探测失败时调用。
func (c *proxyDialCache) MarkBad(key string, d time.Duration) {
	if key == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.m[key] = time.Now().Add(d)
}

// Clear 清除代理的不可用标记。探测成功时调用, 让恢复的代理立即可用。
func (c *proxyDialCache) Clear(key string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	delete(c.m, key)
}
