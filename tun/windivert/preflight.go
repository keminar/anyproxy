//go:build windows

package windivert

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Preflight verifies that WinDivert.dll and the driver .sys are locatable next
// to the executable (WinDivert searches for the .sys beside the DLL). It
// returns a descriptive error naming the exact absolute paths and what's
// missing, so a "file not found" no longer requires guesswork.
func Preflight() error {
	exe, err := os.Executable()
	if err != nil {
		return nil // best-effort; don't block startup on this
	}
	dir := filepath.Dir(exe)

	dll := filepath.Join(dir, "WinDivert.dll")
	sys64 := filepath.Join(dir, "WinDivert64.sys")
	sys32 := filepath.Join(dir, "WinDivert32.sys")

	var missing []string
	if !fileExists(dll) {
		missing = append(missing, dll)
	}
	// On 64-bit Windows the driver is WinDivert64.sys. Accept either name being
	// present so a 32-bit-on-32-bit setup also passes.
	if !fileExists(sys64) && !fileExists(sys32) {
		missing = append(missing, sys64+" (or WinDivert32.sys on 32-bit Windows)")
	}

	if len(missing) == 0 {
		return nil
	}
	return fmt.Errorf(
		"missing WinDivert file(s):\n  - %s\nput WinDivert.dll and the matching .sys "+
			"(64-bit Windows => WinDivert64.sys) in the same folder as the exe:\n  %s",
		strings.Join(missing, "\n  - "), dir)
}

func fileExists(p string) bool {
	fi, err := os.Stat(p)
	return err == nil && !fi.IsDir()
}

// PathAdvisory returns a non-empty warning when the executable lives under a
// path that commonly breaks kernel driver loading: one containing spaces or
// non-ASCII (e.g. Chinese) characters. WinDivert registers the .sys via an
// absolute service ImagePath, and such paths often fail to resolve at load
// time, surfacing as ERROR_FILE_NOT_FOUND even though the file is present.
func PathAdvisory() string {
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	dir := filepath.Dir(exe)
	var reasons []string
	if strings.ContainsRune(dir, ' ') {
		reasons = append(reasons, "spaces")
	}
	for _, r := range dir {
		if r > 127 {
			reasons = append(reasons, "non-ASCII characters")
			break
		}
	}
	if len(reasons) == 0 {
		return ""
	}
	return fmt.Sprintf(
		"executable path contains %s:\n  %s\n"+
			"this frequently makes WinDivert fail with 'file not found' when loading the driver. "+
			"Move everything (exe, WinDivert.dll, WinDivert64.sys, domains.txt) to a plain ASCII path without spaces, e.g. C:\\wd",
		strings.Join(reasons, " and "), dir)
}
