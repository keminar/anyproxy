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

func init() {
	ResolveLookup = newResolveLookupCache()
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
