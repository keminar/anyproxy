//go:build windows
// +build windows

package proto

import (
	"errors"
	"net"
	"sync/atomic"
	"syscall"
	"time"
)

// wsaeAddrInUse is WSAEADDRINUSE — a local source port in the egress band is
// already bound; the dialer just tries the next slot.
const wsaeAddrInUse = syscall.Errno(10048)

// egressCursor round-robins the egress band so consecutive dials rarely land on
// the same local port (and a busy port is skipped on the next attempt).
var egressCursor uint32

func nextEgressPort() uint16 {
	span := uint32(EgressPortHi-EgressPortLo) + 1
	n := atomic.AddUint32(&egressCursor, 1)
	return EgressPortLo + uint16(n%span)
}

// tunDial dials a direct/upstream target with the local source port bound into
// the egress band (see EgressPortLo/EgressPortHi) so the WinDivert redirector
// recognizes anyproxy's own outbound connection and passes it through untouched
// instead of recapturing it into a loop.
//
// Binding the source port up front is deterministic — it happens before connect
// sends the SYN, and works identically for IPv4 and IPv6 — unlike the old
// SOCKET-layer loop guard, which raced the SYN and lost for IPv6 direct.
//
// On a bind collision it retries the next band slot; if the whole band is
// exhausted it falls back to an ordinary unbound dial (that connection may loop,
// but the engine's per-destination rate limiter caps the damage).
func tunDial(network, addr string, timeout time.Duration) (net.Conn, error) {
	const tries = 16
	var lastErr error
	for i := 0; i < tries; i++ {
		// nil IP → Go binds the wildcard of the socket's family (0.0.0.0 / ::)
		// with our chosen port, so this works for both tcp4 and tcp6.
		d := &net.Dialer{Timeout: timeout, LocalAddr: &net.TCPAddr{Port: int(nextEgressPort())}}
		conn, err := d.Dial(network, addr)
		if err == nil {
			return conn, nil
		}
		lastErr = err
		if isAddrInUse(err) {
			continue // local port busy — try the next band slot
		}
		return nil, err // genuine dial failure (unreachable / refused / timeout)
	}
	// Band exhausted (heavy concurrency): give up on binding and dial normally.
	if conn, err := net.DialTimeout(network, addr, timeout); err == nil {
		return conn, nil
	}
	return nil, lastErr
}

func isAddrInUse(err error) bool {
	return errors.Is(err, wsaeAddrInUse) || errors.Is(err, syscall.EADDRINUSE)
}
