//go:build windows

package wdengine

import (
	"sync"
	"time"
)

// rateLimiter is a per-key token bucket. Each key (the destination domain, or
// the destination IP when no hostname is known) may start up to perSec new
// connections per second, with a burst of perSec. It shields the upstream SOCKS
// leg — and the OS ephemeral-port pool that leg draws from — from a single
// site's connection storms.
type rateLimiter struct {
	mu      sync.Mutex
	perSec  float64
	buckets map[string]*tokenBucket
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

func newRateLimiter(perSec int) *rateLimiter {
	return &rateLimiter{
		perSec:  float64(perSec),
		buckets: make(map[string]*tokenBucket),
	}
}

// allow reports whether a new connection to key is within budget, consuming one
// token when it is. A nil limiter or a non-positive perSec means "unlimited".
func (r *rateLimiter) allow(key string) bool {
	if r == nil || r.perSec <= 0 {
		return true
	}
	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()
	b := r.buckets[key]
	if b == nil {
		r.buckets[key] = &tokenBucket{tokens: r.perSec - 1, last: now}
		return true
	}
	// Refill by elapsed time, capped at the burst size.
	b.tokens += now.Sub(b.last).Seconds() * r.perSec
	if b.tokens > r.perSec {
		b.tokens = r.perSec
	}
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true
	}
	return false
}

// cleanup drops buckets idle longer than idle. An idle bucket would refill to
// full anyway, so recreating it on next use is equivalent — this just bounds the
// map's size.
func (r *rateLimiter) cleanup(idle time.Duration) {
	if r == nil || r.perSec <= 0 {
		return
	}
	cutoff := time.Now().Add(-idle)
	r.mu.Lock()
	for k, b := range r.buckets {
		if b.last.Before(cutoff) {
			delete(r.buckets, k)
		}
	}
	r.mu.Unlock()
}
