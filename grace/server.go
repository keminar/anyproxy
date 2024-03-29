package grace

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

//ConnHandler connection handler definition
type ConnHandler func(ctx context.Context, conn *net.TCPConn) error

//ErrReloadClose reload graceful
var ErrReloadClose = errors.New("reload graceful")

//TermTimeout 平滑重启主进程保持秒数
var TermTimeout = 10

// Server embedded http.Server
type Server struct {
	Addr         string
	Handler      ConnHandler
	ln           *net.TCPListener
	SignalHooks  map[int]map[os.Signal][]func()
	sigChan      chan os.Signal
	isChild      bool
	state        uint8
	Network      string
	terminalChan chan error

	mu         sync.Mutex
	activeConn map[*conn]struct{}
}

// Serve accepts incoming connections on the Listener l,
// creating a new service goroutine for each.
// The service goroutines read requests and then call srv.Handler to reply to them.
func (srv *Server) Serve() (err error) {
	srv.state = StateRunning
	defer func() { srv.state = StateTerminate }()

	// 主动重启导致的错误为ErrReloadClose
	if err = srv.serve(); err != nil && err != ErrReloadClose {
		log.Println(syscall.Getpid(), "Server.Serve() error:", err)
		return err
	}

	log.Println(syscall.Getpid(), srv.ln.Addr(), "Listener closed.")
	// wait for Shutdown to return
	return <-srv.terminalChan
}

// contextKey is a value for use with context.WithValue. It's used as
// a pointer so it fits in an interface{} without allocation.
type contextKey struct {
	name string
}

func (k *contextKey) String() string { return "tcp context value " + k.name }

var (
	// ServerContextKey is a context key. It can be used in HTTP
	// handlers with context.WithValue to access the server that
	// started the handler. The associated value will be of
	// type *Server.
	ServerContextKey = &contextKey{"server"}

	// LocalAddrContextKey is a context key. It can be used in
	// HTTP handlers with context.WithValue to access the local
	// address the connection arrived on.
	// The associated value will be of type net.Addr.
	LocalAddrContextKey = &contextKey{"local-addr"}

	// TraceIDContextKey traceID
	TraceIDContextKey = &contextKey{"traceID"}
)

func (srv *Server) serve() (err error) {
	var tempDelay time.Duration

	baseCtx := context.Background() // base is always background, per Issue 16220

	//srv, ok := ctx.Value(grace.ServerContextKey).(*grace.Server)
	ctx := context.WithValue(baseCtx, ServerContextKey, srv)
	for {
		var rw *net.TCPConn
		rw, err = srv.ln.AcceptTCP()
		if err != nil {
			// 主动重启服务
			if srv.state == StateShuttingDown && strings.Contains(err.Error(), "use of closed network connection") {
				return ErrReloadClose
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				if tempDelay == 0 {
					tempDelay = 5 * time.Millisecond
				} else {
					tempDelay *= 2
				}
				if max := 1 * time.Second; tempDelay > max {
					tempDelay = max
				}
				log.Printf("Accept error: %v; retrying in %v\n", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return err
		}
		tempDelay = 0
		c := srv.newConn(rw)
		c.setState(c.rwc, StateNew) // before Serve can return
		go c.serve(ctx)
	}
}

// closeIdleConns closes all idle connections and reports whether the
// server is quiescent.
func (srv *Server) closeIdleConns() bool {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	quiescent := true
	for c := range srv.activeConn {
		st, unixSec := c.getState()
		// Issue 22682: treat StateNew connections as if
		// they're idle if we haven't read the first request's
		// header in over 5 seconds.
		if st == StateNew && unixSec < time.Now().Unix()-5 {
			st = StateIdle
		}
		if st != StateIdle || unixSec == 0 {
			// Assume unixSec == 0 means it's a very new
			// connection, without state set yet.
			quiescent = false
			continue
		}
		c.rwc.Close()
		delete(srv.activeConn, c)
	}
	return quiescent
}

// GetConns 获取所有连接数
func (srv *Server) GetConns() int {
	return len(srv.activeConn)
}

// GetConnRange 输出全部连接
func (srv *Server) GetConnRange(f func(ID uint, startTime int64, remoteAddr string)) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	for c := range srv.activeConn {
		f(c.traceID, c.startTime, c.remoteAddr)
	}
}

// 统计连接数
func (srv *Server) trackConn(c *conn, add bool) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.activeConn == nil {
		srv.activeConn = make(map[*conn]struct{})
	}
	if add {
		srv.activeConn[c] = struct{}{}
	} else {
		delete(srv.activeConn, c)
	}
}

func (srv *Server) newConn(rwc *net.TCPConn) *conn {
	c := &conn{
		server: srv,
		rwc:    rwc,
	}
	return c
}

// ListenAndServe listens on the TCP network address srv.Addr and then calls Serve
// to handle requests on incoming connections. If srv.Addr is blank, ":http" is
// used.
func (srv *Server) ListenAndServe() (err error) {
	addr := srv.Addr
	if addr == "" {
		addr = ":3000"
	}

	go srv.handleSignals()

	srv.ln, err = srv.getListener(addr)
	if err != nil {
		log.Println(os.Getpid(), err)
		return err
	}

	ppid := os.Getppid()
	if srv.isChild && ppid != 1 { //增加一个安全检查
		process, err := os.FindProcess(ppid)
		if err != nil {
			log.Println(os.Getpid(), err)
			return err
		}
		err = process.Signal(syscall.SIGTERM)
		if err != nil {
			return err
		}
	}

	log.Println(fmt.Sprintf("Listening for connections on %v, pid=%d", srv.ln.Addr(), os.Getpid()))

	return srv.Serve()
}

// getListener either opens a new socket to listen on, or takes the acceptor socket
// it got passed when restarted.
func (srv *Server) getListener(laddr string) (l *net.TCPListener, err error) {
	if srv.isChild {
		var ptrOffset uint
		if len(socketPtrOffsetMap) > 0 {
			ptrOffset = socketPtrOffsetMap[laddr]
			log.Println(os.Getpid(), "laddr", laddr, "ptr offset", socketPtrOffsetMap[laddr])
		}

		f := os.NewFile(uintptr(3+ptrOffset), "")

		var ln net.Listener
		ln, err = net.FileListener(f)
		if err != nil {
			err = fmt.Errorf("net.FileListener error: %v", err)
			return
		}
		l = ln.(*net.TCPListener)
	} else {
		var lnaddr *net.TCPAddr
		lnaddr, err = net.ResolveTCPAddr(srv.Network, laddr)
		if err != nil {
			err = fmt.Errorf("net.Listen error: %v", err)
			return
		}

		l, err = net.ListenTCP(srv.Network, lnaddr)
		if err != nil {
			err = fmt.Errorf("net.Listen error: %v", err)
			return
		}
	}
	return
}

// handleSignals listens for os Signals and calls any hooked in function that the
// user had registered with the signal.
func (srv *Server) handleSignals() {
	var sig os.Signal

	signal.Notify(
		srv.sigChan,
		hookableSignals...,
	)

	pid := syscall.Getpid()
	for {
		sig = <-srv.sigChan
		srv.signalHooks(PreSignal, sig)
		switch sig {
		case syscall.SIGHUP:
			log.Println(pid, "Received SIGHUP. forking.")
			err := srv.fork()
			if err != nil {
				log.Println("Fork err:", err)
			}
		case syscall.SIGINT:
			log.Println(pid, "Received SIGINT.")
			// ctrl+c无等待时间
			srv.shutdown(0)
		case syscall.SIGTERM:
			log.Println(pid, "Received SIGTERM.")
			srv.shutdown(TermTimeout)
		default:
			log.Printf("Received %v: nothing i care about...\n", sig)
		}
		srv.signalHooks(PostSignal, sig)
	}
}

// 处理默认消息之外的钩子
func (srv *Server) signalHooks(ppFlag int, sig os.Signal) {
	if _, notSet := srv.SignalHooks[ppFlag][sig]; !notSet {
		return
	}
	for _, f := range srv.SignalHooks[ppFlag][sig] {
		f()
	}
}

// shutdown closes the listener so that no new connections are accepted. it also
// starts a goroutine that will serverTimeout (stop all running requests) the server
// after DefaultTimeout.
func (srv *Server) shutdown(timeout int) {
	if srv.state != StateRunning {
		return
	}

	srv.state = StateShuttingDown
	// listen close就不能accept新的链接，已接收的链接不受影响
	// 关闭已连接的是用tcpConn.Close(), 为了简单下面是用超时来等待处理
	srv.ln.Close()

	if timeout > 0 {
		log.Println(syscall.Getpid(), fmt.Sprintf("Waiting max %d second for connections to finish...", timeout))
		// 等一定时间让已接收的请求处理一下，如果还处理不完就强制关闭了
		after := time.After(time.Duration(timeout) * time.Second)

		var shutdownPollInterval = 500 * time.Millisecond
		ticker := time.NewTicker(shutdownPollInterval)
		defer ticker.Stop()
		for {
			srv.closeIdleConns()
			if len(srv.activeConn) == 0 {
				break
			}
			force := false
			select {
			case <-after:
				// 这里加break没用，只会跳一层select ，所以加一个变量
				force = true
			case <-ticker.C:
			}
			if force {
				break
			}
		}
	}

	srv.terminalChan <- nil
}

func (srv *Server) fork() (err error) {
	regLock.Lock()
	defer regLock.Unlock()
	if runningServersForked {
		return
	}
	runningServersForked = true

	var files = make([]*os.File, len(runningServers))
	var orderArgs = make([]string, len(runningServers))
	for _, srvPtr := range runningServers {
		f, _ := srvPtr.ln.File()
		files[socketPtrOffsetMap[srvPtr.Addr]] = f
		orderArgs[socketPtrOffsetMap[srvPtr.Addr]] = srvPtr.Addr
	}

	//log.Println(files)
	path := os.Args[0]
	var args []string
	if len(os.Args) > 1 {
		for _, arg := range os.Args[1:] {
			if arg == "-graceful" {
				break
			}
			args = append(args, arg)
		}
	}
	args = append(args, "-graceful")
	if len(runningServers) > 1 {
		args = append(args, fmt.Sprintf(`-socketorder=%s`, strings.Join(orderArgs, ",")))
		log.Println(args)
	}
	cmd := exec.Command(path, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = files
	err = cmd.Start()
	if err != nil {
		log.Fatalf("Restart: Failed to launch, error: %v", err)
	}

	return
}

// RegisterSignalHook registers a function to be run PreSignal or PostSignal for a given signal.
func (srv *Server) RegisterSignalHook(ppFlag int, sig os.Signal, f func()) (err error) {
	if ppFlag != PreSignal && ppFlag != PostSignal {
		err = fmt.Errorf("Invalid ppFlag argument. Must be either grace.PreSignal or grace.PostSignal")
		return
	}
	for _, s := range hookableSignals {
		if s == sig {
			srv.SignalHooks[ppFlag][sig] = append(srv.SignalHooks[ppFlag][sig], f)
			return
		}
	}
	err = fmt.Errorf("Signal '%v' is not supported", sig)
	return
}
