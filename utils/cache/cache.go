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

func init() {
	ResolveLookup = newResolveLookupCache()
	SniffName = newSniffNameCache()
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
