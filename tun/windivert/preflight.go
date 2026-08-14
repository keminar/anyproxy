//go:build windows

package windivert

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// searchDir 若非空(由 SetSearchDir 配置)，是存放 WinDivert.dll + WinDivert{32,64}.sys
// 的目录，覆盖默认的「exe 同目录」。
var searchDir string

// SetSearchDir 指定 WinDivert 文件所在目录(含 .dll 与匹配的 .sys)。空=保持默认(exe 同目录)。
// 它通过按全路径预加载 WinDivert.dll 实现: 之后包级 NewLazyDLL("WinDivert.dll") 按名字
// 命中这个已加载模块，且 WinDivert.dll 会从它自身所在目录(=dir)去找 WinDivert64.sys。
// 必须在首次 WinDivert 调用(如 Preflight/Open)之前调用。
func SetSearchDir(dir string) error {
	searchDir = strings.TrimSpace(dir)
	if searchDir == "" {
		return nil
	}
	full := filepath.Join(searchDir, "WinDivert.dll")
	if _, err := windows.LoadLibrary(full); err != nil {
		return fmt.Errorf("preload WinDivert.dll from %q: %w", full, err)
	}
	return nil
}

// baseDir 返回配置的 searchDir，未配置则回退 exe 所在目录。
func baseDir() string {
	if searchDir != "" {
		return searchDir
	}
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	return filepath.Dir(exe)
}

// Preflight verifies that WinDivert.dll and the driver .sys are locatable in the
// search dir (configured windivertDir, else next to the executable; WinDivert
// searches for the .sys beside the DLL). It returns a descriptive error naming
// the exact absolute paths and what's missing, so a "file not found" no longer
// requires guesswork.
func Preflight() error {
	dir := baseDir()
	if dir == "" {
		return nil // best-effort; don't block startup on this
	}

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
			"(64-bit Windows => WinDivert64.sys) in this folder:\n  %s",
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
	dir := baseDir()
	if dir == "" {
		return ""
	}
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
