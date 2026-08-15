//go:build windows

package windivert

import (
	"debug/pe"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
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

	if len(missing) != 0 {
		return fmt.Errorf(
			"missing WinDivert file(s):\n  - %s\nput WinDivert.dll and the matching .sys "+
				"(64-bit Windows => WinDivert64.sys) in this folder:\n  %s",
			strings.Join(missing, "\n  - "), dir)
	}

	// 文件齐全, 再校验 DLL 架构是否与本进程一致。错架构的 WinDivert.dll 能通过
	// 上面的存在性检查, 却会让 LoadLibrary 以 ERROR_BAD_EXE_FORMAT(193,
	// "%1 不是有效的 Win32 应用程序") 在 procOpen.Call 处直接 panic, 绕过所有
	// error 处理。提前在这里拦下, 给出可读的换文件提示。
	return checkDLLArch(dll)
}

// peMachineArch 把 PE 头的 Machine 字段映射到对应的 Go GOARCH。
var peMachineArch = map[uint16]string{
	pe.IMAGE_FILE_MACHINE_I386:  "386",
	pe.IMAGE_FILE_MACHINE_AMD64: "amd64",
	pe.IMAGE_FILE_MACHINE_ARM64: "arm64",
	pe.IMAGE_FILE_MACHINE_ARMNT: "arm",
}

// checkDLLArch 读取 WinDivert.dll 的 PE Machine 字段, 与本进程架构 (runtime.GOARCH)
// 比对。不一致直接返回明确错误, 避免后续 Open 时以 193 panic。读不出机器类型或类型
// 未知时不阻塞启动 (返回 nil), 把判断交给后续 Open/Diagnose。
func checkDLLArch(dllPath string) error {
	mach, err := peMachine(dllPath)
	if err != nil {
		return nil // 读不出就别拦, 保持 best-effort
	}
	arch, known := peMachineArch[mach]
	if !known || arch == runtime.GOARCH {
		return nil
	}
	return fmt.Errorf(
		"WinDivert.dll 架构不匹配: DLL 是 %s, 本程序是 %s\n  %s\n"+
			"请换用 WinDivert 官方包中与本程序架构一致的文件 (.dll 和 .sys 要成套):\n"+
			"  amd64 -> x86_64 目录 (WinDivert.dll + WinDivert64.sys)\n"+
			"  386   -> i386 目录   (WinDivert.dll + WinDivert32.sys)\n"+
			"  arm64 -> ARM64 目录  (WinDivert.dll + WinDivert64.sys)",
		archLabel(arch), archLabel(runtime.GOARCH), dllPath)
}

// peMachine 返回 PE 文件 (exe/dll) 头部的 Machine 字段。
func peMachine(path string) (uint16, error) {
	f, err := pe.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	return f.Machine, nil
}

// archLabel 把 GOARCH 转成更直观的说明。
func archLabel(goarch string) string {
	switch goarch {
	case "386":
		return "32 位 x86 (i386)"
	case "amd64":
		return "64 位 x64 (x86_64)"
	case "arm64":
		return "ARM64"
	case "arm":
		return "32 位 ARM"
	default:
		return goarch
	}
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
