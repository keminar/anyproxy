# anyproxy 文档

## 入门与总览

- [overview.md](overview.md) — 概述与架构：能做什么、数据链路、一条连接的处理流程、运行模式总览、进程模型。

## 参考手册

- [cli.md](cli.md) — 命令行参数详解，及与配置文件的优先级。
- [configuration.md](configuration.md) — `router.yaml` 完整配置参考，按配置段逐项说明。
- [config-examples.md](config-examples.md) — 按场景的完整配置示例：全局代理、按域名分流、Windows+OpenVPN、macOS 入站 SSH、iptables、tunneld、tcpcopy、内网穿透、同机双实例。
- [routing.md](routing.md) — 路由与代理规则：域名匹配、`target`/`proxy`/`dns`/`ip`/`port`/`allowIP`、多代理 `local`/`deny`、优先级。
- [proxy-decision.md](proxy-decision.md) — 代理决策逻辑详解：`target`(local/remote/auto/deny) × `proxy`(多代理 + local/deny 后缀) 的完整判定顺序、host/全局回退链、热加载、不可用缓存。
- [modes.md](modes.md) — 运行模式：proxy / tunnel(tunneld) / bypass / tcpcopy 端口转发 / websocket 内网穿透。
- [deployment.md](deployment.md) — 部署运维：编译、后台、平滑重启、iptables 全局代理、Docker、Windows 注意事项、性能调优。

## 专题

- [tun-features.md](tun-features.md) — TUN 全局代理特性：跨平台(Linux/Windows/macOS utun)、自动路由 `autoRoute`、QUIC(UDP443) 拦截 `blockQUIC`、UDP 转发行为、`target`/`proxy` 优先级。
- [multi-instance-loop.md](multi-instance-loop.md) — 同机多实例(A 开 tun + B 普通)死循环防护：`mode=bypass` 根治、`loopGuard` 熔断器兜底、平台差异。
- [tun-dns-vpn-coexist.md](tun-dns-vpn-coexist.md) — TUN 与 VPN(OpenVPN/TAP)共存的三类回包故障：① VPN 内网 DNS 的 /32 路由丢失；② Windows(WinDivert) VPN 传输死循环与 `excludeProcs`/`bypassIPs` 逃逸；③ 入站连接回包被 TUN 吸走(外网 SSH 断)——Linux 源策略路由(自动)、macOS `pf reply-to`(`inboundPorts`)。
- [windows-winDivert.md](windows-winDivert.md) — Windows WinDivert 运行依赖：`WinDivert.dll`/`.sys` 放置、管理员权限、路径含空格/中文的驱动加载问题、bypass 模式在 Windows 无效。
- [windows-windivert-redirect.md](windows-windivert-redirect.md) — Windows WinDivert 重定向原理：数据包捕获→NAT 改写→本地代理→恢复目的地转发的完整链路；NAT 表、dual-stack 监听、环路防护。
