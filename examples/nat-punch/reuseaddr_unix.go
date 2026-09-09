//go:build linux || darwin

package main

import (
	"log"
	"syscall"

	"golang.org/x/sys/unix"
)

// reuseAddrControl sets both SO_REUSEADDR and SO_REUSEPORT.
//
// SO_REUSEADDR alone is not enough on Linux: the dial loop repeatedly binds
// the same local port that the accept loop is already holding in LISTEN state,
// and Linux rejects that with EADDRINUSE unless SO_REUSEPORT is also set.
// Observed directly — every dial attempt failed with "bind: address already in
// use" while the listener was up, which silently turned the whole punch into a
// one-directional test.
//
// SO_REUSEPORT is not in Go's syscall package for linux (it is for darwin), so
// the constant comes from x/sys/unix, which also gets it right on the
// architectures where the value is not 15.
func reuseAddrControl(_, _ string, c syscall.RawConn) error {
	var sockErr error
	err := c.Control(func(fd uintptr) {
		if sockErr = syscall.SetsockoptInt(int(fd), syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); sockErr != nil {
			return
		}
		// Not fatal on its own: a kernel that refuses SO_REUSEPORT can still
		// complete a punch through the dial side alone, so warn rather than
		// failing the socket outright.
		if err := syscall.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1); err != nil {
			log.Printf("warning: SO_REUSEPORT not accepted (%v); listener and dialer cannot share the port, so inbound punch may not work", err)
		}
	})
	if err != nil {
		return err
	}
	return sockErr
}
