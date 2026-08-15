//go:build windows

package tun

import (
	"context"
	"log"
	"net/netip"
	"strings"

	"github.com/keminar/anyproxy/config"
	"github.com/keminar/anyproxy/tun/wdengine"
	"github.com/keminar/anyproxy/tun/windivert"
	"github.com/keminar/anyproxy/utils/dnsutil"
)

// Run 在 Windows 上用 WinDivert 透明重定向实现全局代理(替代 wintun/gVisor)。
//
// 模型: NETWORK 层捕获出站 TCP(80/443) → NAT 重写到本地监听端口 → 本地监听按 NAT
// 表还原原始目的地址 → 交给 proto.ForwardTCP 复用 anyproxy 的路由/上游逻辑。同时
// 劫持出站 DNS(UDP/53) 按 hosts 配置应答, 并对命中 hosts ip 的 QUIC(UDP/443) 丢弃。
// 防环靠 SOCKET 层 per-process guard(排除 anyproxy 自身出向) + filter 排除上游代理。
//
// cfg 的 Name/Addr/MTU/AutoRoute 属于 wintun 模型, 在 Windows 上忽略。
// cfg.ExcludeProcs / cfg.BypassIPs 逃逸参数来自 tun.windows 配置。
func Run(ctx context.Context, cfg Config) error {
	// 若配置了 windivertDir, 从该目录预加载 WinDivert.dll(.sys 也在该目录被找到),
	// 可把驱动放到无空格/中文的干净路径, 而 exe 原地不动。失败不直接返回, 交给下面
	// Preflight 给出更明确的缺文件提示。
	if cfg.WindivertDir != "" {
		if err := windivert.SetSearchDir(cfg.WindivertDir); err != nil {
			log.Printf("tun(windivert): 预加载 %s\\WinDivert.dll 失败: %v", cfg.WindivertDir, err)
		}
	}
	if err := windivert.Preflight(); err != nil {
		return err
	}
	if adv := windivert.PathAdvisory(); adv != "" {
		log.Printf("WARNING: %s", adv)
	}

	engCfg := &wdengine.Config{
		RedirectPorts:          []uint16{80, 443},
		BlockQUIC:              dnsutil.BlockQUICEnabled(),
		IPv6:                   true,
		BypassPrivate:          cfg.BypassPrivate, // 不配默认 true: 私网/LAN(含虚拟机网段)一律直连不进引擎; 配 tun.windows.bypassPrivate=false 则私网 80/443 进引擎按 router 规则。loopback 始终直连
		MaxConnPerDomainPerSec: 50,
	}
	// 上游代理排除: 若全局上游服务器是 IPv4 字面量, 把 anyproxy→上游 那条腿排除出捕获,
	// 避免自环。是域名/为空时留空, 由 SOCKET 层 guard 兜底。
	if ip, err := netip.ParseAddr(config.ProxyServer); err == nil {
		engCfg.SocksExcludeIP = ip.Unmap()
		engCfg.SocksExcludePort = config.ProxyPort
	}

	// 逃出同机隧道(如 OpenVPN)死循环:
	//  1) 按进程名排除其出向(首选, IP 无关) —— cfg.ExcludeProcs, 如 openvpn.exe
	//  2) 按目的 IP 排除捕获(补充) —— cfg.BypassIPs, 填 VPN 服务器 IP/CIDR
	for _, name := range cfg.ExcludeProcs {
		if n := strings.ToLower(strings.TrimSpace(name)); n != "" {
			engCfg.SocksProcessNames = append(engCfg.SocksProcessNames, n)
		}
	}
	for _, s := range cfg.BypassIPs {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if pfx, err := netip.ParsePrefix(s); err == nil {
			engCfg.ExcludeIPs = append(engCfg.ExcludeIPs, pfx)
		} else if a, err := netip.ParseAddr(s); err == nil {
			engCfg.ExcludeIPs = append(engCfg.ExcludeIPs, netip.PrefixFrom(a.Unmap(), a.BitLen()))
		} else {
			log.Printf("tun(windivert): ignore invalid bypassIP %q: %v", s, err)
		}
	}
	if len(engCfg.SocksProcessNames) > 0 || len(engCfg.ExcludeIPs) > 0 {
		log.Printf("tun(windivert): exclude procs=%v ips=%v", engCfg.SocksProcessNames, engCfg.ExcludeIPs)
	}

	eng, err := wdengine.New(engCfg)
	if err != nil {
		log.Printf("%s", windivert.Diagnose())
		return err
	}
	log.Printf("WinDivert engine up: redirect TCP 80/443 -> local :%d, DNS hijack per hosts, block-quic=%v",
		engCfg.ProxyPort, engCfg.BlockQUIC)

	// ctx 取消时关闭引擎(关句柄→Recv 报错→Run 返回, 同时关监听器与 guard)。
	go func() {
		<-ctx.Done()
		log.Println("tun(windivert): ctx cancelled, closing engine")
		eng.Close()
	}()

	return eng.Run()
}
