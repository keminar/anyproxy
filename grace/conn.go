package grace

import (
	"context"
	"fmt"
	"log"
	"net"
	"runtime"
	"sync/atomic"
	"time"

	"github.com/keminar/anyproxy/grace/autoinc"
)

// AutoInc 自增
var autoInc *autoinc.AutoInc

func init() {
	autoInc = autoinc.New(1, 1)
}

// A conn represents the server side of an HTTP connection.
type conn struct {
	// server is the server on which the connection arrived.
	// Immutable; never nil.
	server *Server

	// cancelCtx cancels the connection-level context.
	cancelCtx context.CancelFunc

	// rwc is the underlying network connection.
	rwc *net.TCPConn

	traceID uint
	// remoteAddr is rwc.RemoteAddr().String(). It is not populated synchronously
	// inside the Listener's Accept goroutine, as some implementations block.
	// It is populated immediately inside the (*conn).serve goroutine.
	// This is the value of a Handler's (*Request).RemoteAddr.
	remoteAddr string

	curState struct{ atomic uint64 } // packed (unixtime<<8|uint8(ConnState))

	startTime int64
}

// Serve a new connection.
func (c *conn) serve(ctx context.Context) {
	c.traceID = autoInc.ID()
	c.startTime = time.Now().UnixNano()
	c.remoteAddr = c.rwc.RemoteAddr().String()
	//addr, ok := ctx.Value(grace.LocalAddrContextKey).(net.Addr)
	ctx = context.WithValue(ctx, LocalAddrContextKey, c.rwc.LocalAddr())
	//traceID, ok := ctx.Value(grace.TraceIDContextKey).(uint)
	ctx = context.WithValue(ctx, TraceIDContextKey, c.traceID)
	defer func() {
		if err := recover(); err != nil {
			const size = 64 << 10
			buf := make([]byte, size)
			buf = buf[:runtime.Stack(buf, false)]
			log.Printf("%s panic serving %v: %v\n%s", traceID(c.traceID), c.remoteAddr, err, buf)
		}
		c.close()
		c.setState(c.rwc, StateClosed)
		log.Println(traceID(c.traceID), "closed")
	}()
	ctx, cancelCtx := context.WithCancel(ctx)
	c.cancelCtx = cancelCtx
	defer cancelCtx()

	c.setState(c.rwc, StateActive)
	handler := c.server.Handler
	err := handler(ctx, c.rwc)
	if err != nil {
		log.Printf("%s conn handler %v: %v\n", traceID(c.traceID), c.remoteAddr, err)
	}
}

// TraceID 日志ID
func traceID(id uint) string {
	return fmt.Sprintf("ID #%d,", id)
}

// A ConnState represents the state of a client connection to a server.
// It's used by the optional Server.ConnState hook.
type ConnState int

const (
	// StateNew represents a new connection that is expected to
	// send a request immediately. Connections begin at this
	// state and then transition to either StateActive or
	// StateClosed.
	StateNew ConnState = iota

	// StateActive represents a connection that has read 1 or more
	// bytes of a request. The Server.ConnState hook for
	// StateActive fires before the request has entered a handler
	// and doesn't fire again until the request has been
	// handled. After the request is handled, the state
	// transitions to StateClosed, StateHijacked, or StateIdle.
	// For HTTP/2, StateActive fires on the transition from zero
	// to one active request, and only transitions away once all
	// active requests are complete. That means that ConnState
	// cannot be used to do per-request work; ConnState only notes
	// the overall state of the connection.
	StateActive

	// StateIdle represents a connection that has finished
	// handling a request and is in the keep-alive state, waiting
	// for a new request. Connections transition from StateIdle
	// to either StateActive or StateClosed.
	StateIdle

	// StateHijacked represents a hijacked connection.
	// This is a terminal state. It does not transition to StateClosed.
	StateHijacked

	// StateClosed represents a closed connection.
	// This is a terminal state. Hijacked connections do not
	// transition to StateClosed.
	StateClosed
)

var stateName = map[ConnState]string{
	StateNew:      "new",
	StateActive:   "active",
	StateIdle:     "idle",
	StateHijacked: "hijacked",
	StateClosed:   "closed",
}

func (c ConnState) String() string {
	return stateName[c]
}

func (c *conn) setState(nc net.Conn, state ConnState) {
	srv := c.server
	switch state {
	case StateNew:
		srv.trackConn(c, true)
	case StateHijacked, StateClosed:
		srv.trackConn(c, false)
	}
	if state > 0xff || state < 0 {
		panic("internal error")
	}
	packedState := uint64(time.Now().Unix()<<8) | uint64(state)
	atomic.StoreUint64(&c.curState.atomic, packedState)
}

func (c *conn) getState() (state ConnState, unixSec int64) {
	packedState := atomic.LoadUint64(&c.curState.atomic)
	return ConnState(packedState & 0xff), int64(packedState >> 8)
}

// Close the connection.
func (c *conn) close() {
	c.rwc.Close()
}
