//go:build windows

package wdengine

import (
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/sys/windows"
)

// procNames resolves a process id to its executable's base name (lowercased,
// e.g. "verge-mihomo.exe"), cached with a short TTL. PIDs are reused by the OS,
// so entries expire rather than living forever.
type procNames struct {
	mu    sync.Mutex
	cache map[uint32]procNameEntry
	ttl   time.Duration
}

type procNameEntry struct {
	name string
	at   time.Time
}

func newProcNames(ttl time.Duration) *procNames {
	return &procNames{cache: make(map[uint32]procNameEntry), ttl: ttl}
}

func (p *procNames) name(pid uint32) string {
	if pid == 0 {
		return ""
	}
	p.mu.Lock()
	if e, ok := p.cache[pid]; ok && time.Since(e.at) < p.ttl {
		p.mu.Unlock()
		return e.name
	}
	p.mu.Unlock()

	n := imageBaseName(pid)

	p.mu.Lock()
	p.cache[pid] = procNameEntry{name: n, at: time.Now()}
	p.mu.Unlock()
	return n
}

// imageBaseName returns the lowercased base name of a pid's executable, or "" if
// it can't be opened (access denied / already exited). Uses
// QueryFullProcessImageName, which needs only PROCESS_QUERY_LIMITED_INFORMATION
// and works for most processes without elevation beyond our Administrator token.
func imageBaseName(pid uint32) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)

	buf := make([]uint16, windows.MAX_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return ""
	}
	full := windows.UTF16ToString(buf[:size])
	return strings.ToLower(filepath.Base(full))
}
