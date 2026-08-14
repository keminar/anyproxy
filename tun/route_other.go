//go:build !linux && !windows && !darwin
// +build !linux,!windows,!darwin

package tun

func setupTUNRoutes(tunName, tunIP, gw, dev string, bypassIPs []string) error { return nil }
func teardownTUNRoutes(tunName string)                                         {}

// bypass 模式 /32 例外路由仅 Windows 需要, 其它平台空操作。
func bypassEnableDirectRoutes(gw string) {}
func bypassCleanupDirectRoutes()         {}
func tunEnableDirectRoutes(gw string)     {}
