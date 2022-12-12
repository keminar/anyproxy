package stats

import (
	"log"
	"sync"
	"time"
)

type Manager struct {
	access   sync.RWMutex
	counters map[string]*Counter
}

func NewManager() *Manager {
	m := &Manager{
		counters: make(map[string]*Counter),
	}
	return m
}

func (m *Manager) RegisterCounter(name string) *Counter {
	m.access.Lock()
	defer m.access.Unlock()

	if _, found := m.counters[name]; found {
		m.counters[name].active = time.Now().Unix()
		return m.counters[name]
	}
	c := new(Counter)
	c.name = name
	m.counters[name] = c
	return c
}

func (m *Manager) UnregisterCounter() {
	m.access.Lock()
	defer m.access.Unlock()

	now := time.Now().Unix()

	for _, v := range m.counters {
		if now-v.active > 300 {
			delete(m.counters, v.name)
		}
	}
	log.Println("stats links:", len(m.counters))
}
