//go:build windows

package wdengine

import (
	"log"
	"sync"
	"time"

	"github.com/keminar/anyproxy/tun/windivert"
)

// socksGuard breaks the transparent-proxy capture loop that occurs with a local,
// rule-based proxy (clash/mihomo/v2ray/…): for destinations it routes "direct",
// it opens its own outbound TCP connection from this same host. That connection
// is outbound :443/etc., so the redirector would capture it and fold it back into
// the proxy — which egresses again, ad infinitum, until the port pools exhaust
// and the real connection resets.
//
// The network layer carries no process identity, so we watch the WinDivert
// SOCKET layer, which reports the PID of every connection event. A proxy suite
// often splits the listener and the egress across DIFFERENT processes (e.g. a GUI
// owning :3000 and a separate core process making the direct connections), so we
// exclude by PROCESS IMAGE NAME rather than a single PID: the family is seeded
// from the listener process's own executable name (auto-detected) plus any names
// given in config. Every SOCKET CONNECT from a process in that family has its
// local source port recorded; process() then passes those packets out untouched.
type socksGuard struct {
	port  uint16     // the proxy listener port
	names *procNames // pid → image base name (cached)
	pids  *pidTable  // port → owning pid (OS TCP table), for verbose diagnostics

	mu     sync.RWMutex
	family map[string]struct{} // lowercase image names whose egress we exclude
	egress map[uint16]struct{} // local source ports currently owned by the family
	h      *windivert.Handle   // SOCKET-layer session (nil only if it failed to open)
}

func (g *socksGuard) inFamily(name string) bool {
	if name == "" {
		return false
	}
	g.mu.RLock()
	_, ok := g.family[name]
	g.mu.RUnlock()
	return ok
}

func (g *socksGuard) loop() {
	for {
		addr, err := g.h.RecvSocket()
		if err != nil {
			return // handle closed on shutdown
		}
		pid := addr.SocketProcessId()
		lport := addr.SocketLocalPort()
		switch addr.Event() {
		case windivert.EventSocketListen, windivert.EventSocketAccept:
			// Whoever listens/accepts on the proxy port is (part of) the proxy suite;
			// learn its image name into the family so its egress process — even a
			// sibling sharing the name — is covered.
			if lport == g.port {
				if n := g.names.name(pid); n != "" {
					g.mu.Lock()
					if _, ok := g.family[n]; !ok {
						g.family[n] = struct{}{}
						log.Printf("SOCKS loop guard: learned proxy process %q (pid %d)", n, pid)
					}
					g.mu.Unlock()
				}
			}
		case windivert.EventSocketConnect:
			// An outbound connect: if the connecting process belongs to the proxy
			// family, exclude its source port so we don't re-capture it.
			if g.inFamily(g.names.name(pid)) {
				g.mu.Lock()
				g.egress[lport] = struct{}{}
				g.mu.Unlock()
			}
		case windivert.EventSocketClose:
			// Drop the mapping when any tracked port closes so it can be reused.
			g.mu.Lock()
			delete(g.egress, lport)
			g.mu.Unlock()
		}
	}
}

// ownsPort reports whether srcPort is an outbound source port of the proxy
// family — one of its own direct-egress connections, which must be sent out
// untouched rather than redirected (that redirection is the capture loop).
func (g *socksGuard) ownsPort(srcPort uint16) bool {
	if g == nil {
		return false
	}
	g.mu.RLock()
	_, ok := g.egress[srcPort]
	g.mu.RUnlock()
	return ok
}

// diag returns, for a captured connection's original client (source) port, the
// owning pid and its resolved image name — for verbose logging so a loop line
// reveals which process (and whether it is in the family) produced it.
func (g *socksGuard) diag(clientPort uint16) (pid uint32, name string) {
	if g == nil || g.pids == nil {
		return 0, ""
	}
	pid = g.pids.pidOf(clientPort)
	return pid, g.names.name(pid)
}

func (g *socksGuard) Close() error {
	if g == nil || g.h == nil {
		return nil
	}
	return g.h.Close()
}

// startSocksGuard builds a guard only when the proxy is on this host (a remote
// proxy can't produce a local egress loop). It requires the SOCKET layer; if that
// can't open (older WinDivert build) the guard is disabled and the rate limiter
// is the only loop backstop.
func startSocksGuard(loopbackSocks bool, port uint16, extraNames []string) *socksGuard {
	if !loopbackSocks {
		return nil
	}
	h, err := windivert.Open("tcp", windivert.LayerSocket, 0, windivert.FlagSniff|windivert.FlagRecvOnly)
	if err != nil {
		log.Printf("SOCKS loop guard disabled (SOCKET layer unavailable: %v); "+
			"direct-egress loops rely on the rate limiter only", err)
		return nil
	}
	g := &socksGuard{
		port:   port,
		names:  newProcNames(30 * time.Second),
		pids:   newPidTable(25 * time.Millisecond),
		family: make(map[string]struct{}),
		egress: make(map[uint16]struct{}),
		h:      h,
	}
	// Seed the family with any explicitly-configured names and the process that
	// currently owns the listener port.
	for _, n := range extraNames {
		if n != "" {
			g.family[n] = struct{}{}
		}
	}
	if pid := g.pids.pidOf(port); pid != 0 {
		if n := g.names.name(pid); n != "" {
			g.family[n] = struct{}{}
			log.Printf("SOCKS loop guard active: proxy process %q (pid %d) owns listener :%d", n, pid, port)
		} else {
			log.Printf("SOCKS loop guard active: listener :%d owned by pid %d (name unresolved) — "+
				"pass -socks-proc if direct-egress still loops", port, pid)
		}
	} else {
		log.Printf("SOCKS loop guard active: no process yet owns :%d; will learn on first connection", port)
	}
	go g.loop()
	return g
}
