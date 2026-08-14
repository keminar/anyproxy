//go:build windows

package wdengine

import (
	"encoding/binary"
	"sync"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	iphlpapi           = windows.NewLazyDLL("iphlpapi.dll")
	procGetExtTcpTable = iphlpapi.NewProc("GetExtendedTcpTable")
)

const (
	tcpTableOwnerPidAll = 5  // TCP_TABLE_OWNER_PID_ALL
	afInet              = 2  // AF_INET
	afInet6             = 23 // AF_INET6
)

// pidTable maps a local TCP port to its owning process id by snapshotting the OS
// TCP table (GetExtendedTcpTable, both address families). connect() registers a
// socket in this table (SYN_SENT) before its SYN is transmitted, so a lookup at
// the moment we capture that SYN is race-free — this is the authoritative backstop
// behind the event-driven SOCKET-layer fast path, which can lag or drop events
// under a connection burst. Snapshots are cached and refreshed at most every
// minInterval to bound cost.
type pidTable struct {
	mu          sync.Mutex
	byPort      map[uint16]uint32
	last        time.Time
	minInterval time.Duration
}

func newPidTable(minInterval time.Duration) *pidTable {
	return &pidTable{byPort: make(map[uint16]uint32), minInterval: minInterval}
}

// pidOf returns the owning process id of a local TCP port (0 if unknown),
// refreshing the snapshot if the port is absent. For diagnostics/logging.
func (t *pidTable) pidOf(port uint16) uint32 {
	t.mu.Lock()
	defer t.mu.Unlock()
	if _, ok := t.byPort[port]; !ok {
		t.maybeRefreshLocked()
	}
	return t.byPort[port]
}

func (t *pidTable) maybeRefreshLocked() {
	if !t.last.IsZero() && time.Since(t.last) < t.minInterval {
		return
	}
	m := make(map[uint16]uint32, len(t.byPort)+16)
	collectTCPPorts(afInet, m)
	collectTCPPorts(afInet6, m)
	if len(m) > 0 {
		t.byPort = m
	}
	t.last = time.Now()
}

// collectTCPPorts fills m with localPort→owningPid for one address family. IPv4
// rows are 24 bytes (MIB_TCPROW_OWNER_PID), IPv6 rows 56 (MIB_TCP6ROW_OWNER_PID);
// in both the local port sits at a fixed offset in network byte order and the pid
// is the trailing DWORD.
func collectTCPPorts(af uint32, m map[uint16]uint32) {
	buf := getExtendedTCPTable(af)
	if len(buf) < 4 {
		return
	}
	n := binary.LittleEndian.Uint32(buf[0:4])
	rows := buf[4:]
	var rowLen, portOff, pidOff int
	if af == afInet {
		rowLen, portOff, pidOff = 24, 8, 20
	} else {
		rowLen, portOff, pidOff = 56, 20, 52
	}
	for i := 0; i < int(n); i++ {
		off := i * rowLen
		if off+rowLen > len(rows) {
			break
		}
		row := rows[off:]
		port := binary.BigEndian.Uint16(row[portOff : portOff+2]) // stored network order
		pid := binary.LittleEndian.Uint32(row[pidOff : pidOff+4])
		m[port] = pid
	}
}

// getExtendedTCPTable returns the raw TCP_TABLE_OWNER_PID_ALL buffer for af, or
// nil on error. It sizes the buffer via the documented two-call pattern.
func getExtendedTCPTable(af uint32) []byte {
	var size uint32
	for tries := 0; tries < 4; tries++ {
		var p uintptr
		var buf []byte
		if size > 0 {
			buf = make([]byte, size)
			p = uintptr(unsafe.Pointer(&buf[0]))
		}
		r1, _, _ := procGetExtTcpTable.Call(
			p,
			uintptr(unsafe.Pointer(&size)),
			0, // bOrder
			uintptr(af),
			tcpTableOwnerPidAll,
			0,
		)
		switch r1 {
		case 0: // NO_ERROR
			if buf == nil {
				return nil
			}
			return buf[:size]
		case 122: // ERROR_INSUFFICIENT_BUFFER — size is now set; allocate and retry
			continue
		default:
			return nil
		}
	}
	return nil
}
