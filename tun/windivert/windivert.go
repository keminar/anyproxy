//go:build windows

// Package windivert is a thin, cgo-free binding around WinDivert.dll (v2.x).
//
// It exposes just enough of the API to run a NETWORK-layer capture loop:
// Open / Recv / Send / SetParam / Close, plus the WINDIVERT_ADDRESS struct
// needed to know a packet's direction and to reinject it unchanged.
//
// The WinDivert.dll (and its matching WinDivert{32,64}.sys driver) must sit
// next to the executable (or on PATH). Administrator privileges are required.
package windivert

import (
	"encoding/binary"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// WinDivert layers we open.
const (
	LayerNetwork = 0 // WINDIVERT_LAYER_NETWORK — the packet capture loop
	LayerSocket  = 3 // WINDIVERT_LAYER_SOCKET  — connection lifecycle events (with PID)
)

// Open flags (WINDIVERT_FLAG_*). SOCKET-layer monitoring uses SNIFF|RECV_ONLY.
const (
	FlagSniff    = 0x0001
	FlagRecvOnly = 0x0004
)

// SOCKET-layer event codes (the Event byte of the address flags bitfield).
const (
	EventSocketBind    = 3
	EventSocketConnect = 4
	EventSocketListen  = 5
	EventSocketAccept  = 6
	EventSocketClose   = 7
)

// SetParam keys (WINDIVERT_PARAM_*).
const (
	ParamQueueLength = 0
	ParamQueueTime   = 1
	ParamQueueSize   = 2
)

var (
	dll = windows.NewLazyDLL("WinDivert.dll")

	procOpen     = dll.NewProc("WinDivertOpen")
	procRecv     = dll.NewProc("WinDivertRecv")
	procSend     = dll.NewProc("WinDivertSend")
	procClose    = dll.NewProc("WinDivertClose")
	procSetParam = dll.NewProc("WinDivertSetParam")
	procCalcCsum = dll.NewProc("WinDivertHelperCalcChecksums")
	procCompile  = dll.NewProc("WinDivertHelperCompileFilter")
)

// Address mirrors WINDIVERT_ADDRESS (80 bytes on all archs).
//
//	INT64  Timestamp
//	UINT32 <bitfield: Layer:8 Event:8 Sniffed Outbound Loopback Impostor IPv6 IPChecksum TCPChecksum UDPChecksum Reserved1:8>
//	UINT32 Reserved2
//	union  <64 bytes>
type Address struct {
	Timestamp int64
	Flags     uint32
	Reserved2 uint32
	Union     [64]byte
}

// Bit offsets inside Flags for the boolean fields we care about.
const (
	bitOutbound = 17
	bitLoopback = 18
	bitImpostor = 19
)

// Loopback reports whether src and dst are both this host (WinDivert flags any
// same-host packet as loopback, not just 127.x/::1).
func (a *Address) Loopback() bool { return a.Flags&(1<<bitLoopback) != 0 }

// Impostor reports whether the packet was injected by another driver (including
// our own re-injections). Passing these straight through avoids capture loops.
func (a *Address) Impostor() bool { return a.Flags&(1<<bitImpostor) != 0 }

// Event returns the event code (the second byte of the flags bitfield: after
// the 8-bit Layer). At the SOCKET layer this is one of the EventSocket* codes.
func (a *Address) Event() uint8 { return uint8((a.Flags >> 8) & 0xff) }

// SOCKET-layer union accessors (WINDIVERT_DATA_SOCKET): EndpointId(0), Parent(8),
// ProcessId(16), LocalAddr[4](20), RemoteAddr[4](36), LocalPort(52),
// RemotePort(54), Protocol(56). Ports are host byte order at this layer.
func (a *Address) SocketProcessId() uint32 { return binary.LittleEndian.Uint32(a.Union[16:20]) }
func (a *Address) SocketLocalPort() uint16 { return binary.LittleEndian.Uint16(a.Union[52:54]) }
func (a *Address) SocketRemotePort() uint16 {
	return binary.LittleEndian.Uint16(a.Union[54:56])
}

func (a *Address) setBit(bit uint, v bool) {
	if v {
		a.Flags |= 1 << bit
	} else {
		a.Flags &^= 1 << bit
	}
}

// SetOutbound flips the direction bit. Clearing it turns a captured packet into
// an inbound injection (used on the proxy→app return path).
func (a *Address) SetOutbound(v bool) { a.setBit(bitOutbound, v) }

// SetLoopback marks the packet as loopback (src and dst are both this host).
func (a *Address) SetLoopback(v bool) { a.setBit(bitLoopback, v) }

// The NETWORK-layer union begins with WINDIVERT_DATA_NETWORK{ UINT32 IfIdx;
// UINT32 SubIfIdx; }. We stash these off the outbound path and restore them when
// injecting the return packet inbound so the stack accepts it on the right NIC.
func (a *Address) IfIdx() uint32     { return binary.LittleEndian.Uint32(a.Union[0:4]) }
func (a *Address) SubIfIdx() uint32  { return binary.LittleEndian.Uint32(a.Union[4:8]) }
func (a *Address) SetIfIdx(v uint32) { binary.LittleEndian.PutUint32(a.Union[0:4], v) }
func (a *Address) SetSubIfIdx(v uint32) {
	binary.LittleEndian.PutUint32(a.Union[4:8], v)
}

// Handle is an open WinDivert session.
type Handle struct {
	h uintptr
}

const invalidHandle = ^uintptr(0)

// Open starts a capture on the given layer with the given BPF-like filter
// string. See https://reqrypt.org/windivert-doc.html for the filter syntax.
func Open(filter string, layer int, priority int16, flags uint64) (*Handle, error) {
	cfilter, err := windows.BytePtrFromString(filter)
	if err != nil {
		return nil, err
	}
	r1, _, e := procOpen.Call(
		uintptr(unsafe.Pointer(cfilter)),
		uintptr(layer),
		uintptr(priority),
		uintptr(flags),
	)
	if r1 == invalidHandle {
		return nil, fmt.Errorf("WinDivertOpen: %s (%w)", openHint(e), e)
	}
	return &Handle{h: r1}, nil
}

// openHint translates the well-known WinDivertOpen failure codes into an
// actionable message. See https://reqrypt.org/windivert-doc.html#divert_open.
func openHint(e error) string {
	no, ok := e.(syscall.Errno)
	if !ok {
		return "failed to open WinDivert"
	}
	switch uintptr(no) {
	case 2: // ERROR_FILE_NOT_FOUND
		return "driver not found — either WinDivert64.sys is not next to the exe, or a stale 'WinDivert' service points at an old path; " +
			"fix with: sc stop WinDivert & sc delete WinDivert (then reboot), and ensure the .dll and .sys come from the same x64 package"
	case 5: // ERROR_ACCESS_DENIED
		return "access denied — run as Administrator"
	case 87: // ERROR_INVALID_PARAMETER
		return "invalid filter string, layer or priority"
	case 577: // ERROR_INVALID_IMAGE_HASH
		return "driver signature rejected — use an official signed WinDivert build (or enable test signing)"
	case 1275: // ERROR_DRIVER_BLOCKED
		return "a different WinDivert version is already loaded — reboot or stop the other process"
	case 1058: // ERROR_SERVICE_DISABLED
		return "WinDivert service is disabled"
	default:
		return "failed to open WinDivert"
	}
}

// Recv blocks until a packet is captured, filling buf and returning the number
// of bytes written along with its address (direction, flags, interface).
func (h *Handle) Recv(buf []byte) (int, *Address, error) {
	var addr Address
	var recvLen uint32
	r1, _, e := procRecv.Call(
		h.h,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&recvLen)),
		uintptr(unsafe.Pointer(&addr)),
	)
	if r1 == 0 {
		return 0, nil, fmt.Errorf("WinDivertRecv: %w", e)
	}
	return int(recvLen), &addr, nil
}

// RecvSocket blocks until a SOCKET-layer event is captured and returns its
// address. There is no packet payload at this layer, so the packet buffer is
// NULL — only the WINDIVERT_ADDRESS (event code, PID, local/remote endpoints) is
// delivered.
func (h *Handle) RecvSocket() (*Address, error) {
	var addr Address
	r1, _, e := procRecv.Call(
		h.h,
		0, // pPacket = NULL (no payload at the SOCKET layer)
		0, // packetLen = 0
		0, // pRecvLen = NULL
		uintptr(unsafe.Pointer(&addr)),
	)
	if r1 == 0 {
		return nil, fmt.Errorf("WinDivertRecv(socket): %w", e)
	}
	return &addr, nil
}

// Send (re)injects a packet. Pass back the Address that Recv produced so the
// direction and interface are preserved.
func (h *Handle) Send(buf []byte, addr *Address) (int, error) {
	var sendLen uint32
	r1, _, e := procSend.Call(
		h.h,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(unsafe.Pointer(addr)),
	)
	if r1 == 0 {
		return 0, fmt.Errorf("WinDivertSend: %w", e)
	}
	return int(sendLen), nil
}

// CalcChecksums recomputes the IP and TCP/UDP checksums of a (possibly
// modified) packet in place. Call it after any header rewrite and before Send.
// flags 0 means "recompute all"; addr supplies the pseudo-header context.
func CalcChecksums(buf []byte, addr *Address) error {
	r1, _, e := procCalcCsum.Call(
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(addr)),
		0,
	)
	if r1 == 0 {
		return fmt.Errorf("WinDivertHelperCalcChecksums: %w", e)
	}
	return nil
}

// CompileFilter validates a filter string for the given layer WITHOUT opening a
// handle (no driver interaction). On failure it returns WinDivert's own error
// message and the character offset in the filter where parsing failed. Use it to
// explain exactly which token a given WinDivert build rejects.
func CompileFilter(filter string, layer int) (reason string, pos int, ok bool) {
	cf, err := windows.BytePtrFromString(filter)
	if err != nil {
		return err.Error(), 0, false
	}
	obj := make([]byte, 32*1024) // generous; compiled filter objects are small
	var errStr *byte
	var errPos uint32
	r1, _, _ := procCompile.Call(
		uintptr(unsafe.Pointer(cf)),
		uintptr(layer),
		uintptr(unsafe.Pointer(&obj[0])),
		uintptr(len(obj)),
		uintptr(unsafe.Pointer(&errStr)),
		uintptr(unsafe.Pointer(&errPos)),
	)
	if r1 == 0 {
		reason = "unknown error"
		if errStr != nil {
			reason = windows.BytePtrToString(errStr)
		}
		return reason, int(errPos), false
	}
	return "", 0, true
}

// SetParam tunes an internal queue parameter.
func (h *Handle) SetParam(param int, value uint64) error {
	r1, _, e := procSetParam.Call(h.h, uintptr(param), uintptr(value))
	if r1 == 0 {
		return fmt.Errorf("WinDivertSetParam: %w", e)
	}
	return nil
}

// Close shuts down the capture session.
func (h *Handle) Close() error {
	r1, _, e := procClose.Call(h.h)
	if r1 == 0 {
		return fmt.Errorf("WinDivertClose: %w", e)
	}
	return nil
}
