//go:build windows

package wdengine

import (
	"net/netip"
	"sync"
	"time"
)

// natEntry records one redirected connection. The app's outbound flow
// (clientIP:clientPort → dstIP:dstPort) is rewritten onto the local proxy using
// a unique natPort so that two apps reusing the same ephemeral port to
// different servers never collide once both are folded onto the proxy.
type natEntry struct {
	natPort    uint16
	clientPort uint16
	srcIP      netip.Addr // 原始客户端源 IP(本机 NIC IP)，仅供 ForwardTCP 做日志/统计
	dstIP      netip.Addr
	dstPort    uint16
	ifIdx      uint32 // NIC the app's packets came in on (for the return injection)
	subIfIdx   uint32
	last       time.Time
	closed     time.Time // set when the proxy connection ends; zero while active
}

// clientKey identifies a connection from the application's point of view.
type clientKey struct {
	clientPort uint16
	dstIP      netip.Addr
	dstPort    uint16
}

// natTable maps between application flows and their proxy-side natPort. It hands
// out unique natPorts from [lo, hi] and recycles them on teardown / idle GC.
type natTable struct {
	mu       sync.Mutex
	byNat    map[uint16]*natEntry
	byClient map[clientKey]*natEntry
	lo, hi   uint16
	cursor   uint16
}

func newNatTable(lo, hi uint16) *natTable {
	return &natTable{
		byNat:    make(map[uint16]*natEntry),
		byClient: make(map[clientKey]*natEntry),
		lo:       lo,
		hi:       hi,
		cursor:   lo,
	}
}

// forward returns the entry for an outbound app→server packet, creating one
// (with a freshly allocated natPort) on first sight. The bool reports whether a
// new entry was allocated. It returns (nil,false) if the port pool is exhausted.
func (t *natTable) forward(srcIP netip.Addr, clientPort uint16, dstIP netip.Addr, dstPort uint16, ifIdx, subIfIdx uint32) (*natEntry, bool) {
	ck := clientKey{clientPort, dstIP, dstPort}
	t.mu.Lock()
	defer t.mu.Unlock()
	if e, ok := t.byClient[ck]; ok {
		e.last = time.Now()
		e.closed = time.Time{} // reactivate: a fresh flow reused this mapping
		return e, false
	}
	n, ok := t.allocLocked()
	if !ok {
		return nil, false
	}
	e := &natEntry{
		natPort:    n,
		clientPort: clientPort,
		srcIP:      srcIP,
		dstIP:      dstIP,
		dstPort:    dstPort,
		ifIdx:      ifIdx,
		subIfIdx:   subIfIdx,
		last:       time.Now(),
	}
	t.byNat[n] = e
	t.byClient[ck] = e
	return e, true
}

// lookupNat resolves a proxy-side natPort back to its entry (return path).
func (t *natTable) lookupNat(n uint16) (*natEntry, bool) {
	t.mu.Lock()
	e, ok := t.byNat[n]
	if ok {
		e.last = time.Now()
	}
	t.mu.Unlock()
	return e, ok
}

// markClosed flags an entry whose proxy connection has ended. The mapping is
// kept (so the closing FIN/ACK handshake on the return path still resolves) but
// becomes eligible for a fast grace-based reclaim in gc, instead of waiting out
// the full idle timeout. No-op if the natPort is already gone.
func (t *natTable) markClosed(n uint16) {
	t.mu.Lock()
	if e, ok := t.byNat[n]; ok {
		e.closed = time.Now()
	}
	t.mu.Unlock()
}

// release recycles a natPort (called on RST and by idle GC).
func (t *natTable) release(n uint16) {
	t.mu.Lock()
	t.releaseLocked(n)
	t.mu.Unlock()
}

func (t *natTable) releaseLocked(n uint16) {
	e, ok := t.byNat[n]
	if !ok {
		return
	}
	delete(t.byNat, n)
	delete(t.byClient, clientKey{e.clientPort, e.dstIP, e.dstPort})
}

// allocLocked scans for a free natPort starting at the rolling cursor.
func (t *natTable) allocLocked() (uint16, bool) {
	span := int(t.hi) - int(t.lo) + 1
	for i := 0; i < span; i++ {
		n := t.cursor
		if t.cursor >= t.hi {
			t.cursor = t.lo
		} else {
			t.cursor++
		}
		if _, used := t.byNat[n]; !used {
			return n, true
		}
	}
	return 0, false
}

// gc releases entries whose proxy connection ended more than closeGrace ago
// (the common case — recycled promptly), plus any still-open entry idle for
// longer than idle (a fallback for connections whose teardown we never saw).
func (t *natTable) gc(idle, closeGrace time.Duration) {
	now := time.Now()
	idleCutoff := now.Add(-idle)
	closeCutoff := now.Add(-closeGrace)
	t.mu.Lock()
	defer t.mu.Unlock()
	for n, e := range t.byNat {
		switch {
		case !e.closed.IsZero() && e.closed.Before(closeCutoff):
			t.releaseLocked(n)
		case e.last.Before(idleCutoff):
			t.releaseLocked(n)
		}
	}
}
