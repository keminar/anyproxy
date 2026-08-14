//go:build windows

package windivert

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Diagnose gathers the facts that actually determine whether WinDivertOpen can
// find its driver, and returns them as a human-readable report. It is meant to
// be printed after an Open failure so the real cause is visible instead of
// guessed at.
//
// It answers three questions:
//  1. Which WinDivert.dll did the loader actually resolve? (may not be ours)
//  2. Is WinDivert64.sys sitting next to THAT dll?
//  3. Does a WinDivert service already exist, and where does its ImagePath point?
func Diagnose() string {
	var b strings.Builder
	b.WriteString("--- WinDivert diagnostics ---\n")

	// (1) The dll the OS loader actually bound to.
	if err := dll.Load(); err != nil {
		fmt.Fprintf(&b, "WinDivert.dll: FAILED to load: %v\n", err)
		fmt.Fprintf(&b, "  -> ensure WinDivert.dll is next to the exe and unblocked (Unblock-File)\n")
		return b.String()
	}
	dllPath := moduleFileName(windows.Handle(dll.Handle()))
	if dllPath == "" {
		b.WriteString("WinDivert.dll: loaded, but its path could not be determined\n")
	} else {
		fmt.Fprintf(&b, "WinDivert.dll actually loaded from:\n  %s\n", dllPath)
		// (2) Is the .sys beside that dll?
		dir := filepath.Dir(dllPath)
		sys64 := filepath.Join(dir, "WinDivert64.sys")
		sys32 := filepath.Join(dir, "WinDivert32.sys")
		switch {
		case fileExists(sys64):
			fmt.Fprintf(&b, "  WinDivert64.sys: FOUND beside the dll (%d bytes)\n", fileSize(sys64))
		case fileExists(sys32):
			fmt.Fprintf(&b, "  WinDivert32.sys: found beside the dll, but 64-bit Windows needs WinDivert64.sys\n")
		default:
			fmt.Fprintf(&b, "  WinDivert64.sys: NOT beside the loaded dll -> this is the cause. "+
				"Put WinDivert64.sys in:\n    %s\n", dir)
		}
	}

	// (3) Existing service registrations and their ImagePath.
	for _, name := range []string{"WinDivert", "WinDivert1.4"} {
		if path, ok := serviceImagePath(name); ok {
			fmt.Fprintf(&b, "service %q exists, ImagePath:\n  %s\n", name, path)
			if !fileExists(stripNTPrefix(path)) {
				fmt.Fprintf(&b, "  -> that file does NOT exist (stale service). Fix:\n"+
					"     sc stop %s & sc delete %s   (then reboot)\n", name, name)
			}
		}
	}

	b.WriteString("-----------------------------")
	return b.String()
}

func moduleFileName(h windows.Handle) string {
	buf := make([]uint16, 32768)
	n, err := windows.GetModuleFileName(h, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 {
		return ""
	}
	return windows.UTF16ToString(buf[:n])
}

func serviceImagePath(name string) (string, bool) {
	scm, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_CONNECT)
	if err != nil {
		return "", false
	}
	defer windows.CloseServiceHandle(scm)

	svcName, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return "", false
	}
	svc, err := windows.OpenService(scm, svcName, windows.SERVICE_QUERY_CONFIG)
	if err != nil {
		return "", false
	}
	defer windows.CloseServiceHandle(svc)

	var needed uint32
	windows.QueryServiceConfig(svc, nil, 0, &needed)
	if needed == 0 {
		return "", true // exists but no config readable
	}
	buf := make([]byte, needed)
	cfg := (*windows.QUERY_SERVICE_CONFIG)(unsafe.Pointer(&buf[0]))
	if err := windows.QueryServiceConfig(svc, cfg, needed, &needed); err != nil {
		return "", true
	}
	return windows.UTF16PtrToString(cfg.BinaryPathName), true
}

// stripNTPrefix removes a leading \??\ that service ImagePaths often carry so
// os.Stat can check the file.
func stripNTPrefix(p string) string {
	p = strings.TrimPrefix(p, `\??\`)
	return p
}

func fileSize(p string) int64 {
	fi, err := os.Stat(p)
	if err != nil {
		return 0
	}
	return fi.Size()
}
