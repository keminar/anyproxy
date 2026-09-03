package stats

import (
	"log"
	"sync"
	"time"
)

type Manager struct {
	access   sync.RWMutex
	counters map[string]*Counter
	// ticker goroutine 只在第一次 RegisterCounter 时启动, 避免一次性进程
	// (例如 -send/-recv) 即便从不建立 tunnel 也会空转并打出
	// "stats links: 0" 噪音。
	startMu sync.Mutex
	started bool
}

func NewManager() *Manager {
	m := &Manager{
		counters: make(map[string]*Counter),
	}
	return m
}

func (m *Manager) RegisterCounter(name string) *Counter {
	m.access.Lock()
	if _, found := m.counters[name]; found {
		m.counters[name].active = time.Now().Unix()
		c := m.counters[name]
		m.access.Unlock()
		m.startTicker()
		return c
	}
	c := new(Counter)
	c.name = name
	m.counters[name] = c
	m.access.Unlock()

	m.startTicker()
	return c
}

// startTicker 在第一次被调用时起 1 分钟一次的回收 ticker, 之后是 no-op。
// 只清理掉长时间未活跃的计数器并打 "stats links: N"。若该 Manager 从未注册
// 任何计数器, ticker 永不启动, 自然也不会有空日志。
func (m *Manager) startTicker() {
	m.startMu.Lock()
	defer m.startMu.Unlock()
	if m.started {
		return
	}
	m.started = true
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			m.UnregisterCounter()
		}
	}()
}

func (m *Manager) UnregisterCounter() {
	m.access.Lock()
	defer m.access.Unlock()

	now := time.Now().Unix()

	for _, v := range m.counters {
		if now-v.active > 300 {
			// 回收前补记残余字节(兜底: 若连接结束时未 Flush, 避免漏统计)
			v.Flush(0)
			delete(m.counters, v.name)
		}
	}
	log.Println("stats links:", len(m.counters))
}
