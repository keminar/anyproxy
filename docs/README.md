# anyproxy 文档

## 入门与总览

- [quickstart.md](quickstart.md) — 快速开始：本机启动、tunneld、转发上级代理、平滑重启、Docker。
- [overview.md](overview.md) — 概述与架构：能做什么、数据链路、一条连接的处理流程、运行模式总览、进程模型。
- [usage.md](usage.md) — 客户端接入与使用：同端口自动识别 HTTP+SOCKS5 代理、透明代理、全局(TUN/WinDivert)三种接入方式，及怎么把客户端指过来。

## 参考手册

- [cli.md](cli.md) — 命令行参数详解，及与配置文件的优先级。
- [configuration.md](configuration.md) — `router.yaml` 完整配置参考，按配置段逐项说明。
- [hot-reload.md](hot-reload.md) — `watcher: true` 配置热加载：哪些配置改动即时生效、哪些需重启或 SIGHUP，及其判定机制。
- [config-examples.md](config-examples.md) — 按场景的完整配置示例：全局代理、按域名分流、Windows+OpenVPN、macOS 入站 SSH、iptables、tunneld、tcpcopy、内网穿透、同机双实例。
- [routing.md](routing.md) — 路由与代理规则：域名匹配、`target`/`proxy`/`dns`/`ip`/`port`/`allowIP`、多代理 `local`/`deny`、优先级。
- [proxy-decision.md](proxy-decision.md) — 代理决策逻辑详解：`target`(local/remote/auto/deny) × `proxy`(多代理 + local/deny 后缀) 的完整判定顺序、host/全局回退链、热加载、不可用缓存。
- [modes.md](modes.md) — 运行模式：proxy / tunnel(tunneld) / tun / bypass(仅Linux) / tcpcopy 端口转发 / websocket 内网穿透。
- [websocket.md](websocket.md) — websocket 内网穿透详解：服务端/订阅端角色、两条转发路径（HTTP 头订阅、裸 TCP 端口转发）、`forward`/`subscribe` 字段、鉴权握手、白名单与常见坑。
- [deployment.md](deployment.md) — 部署运维：编译、后台、平滑重启、iptables 全局代理、Docker、Windows 注意事项、性能调优。
- [build.md](build.md) — 构建与交叉编译：`build.sh`/`build.bat` 各目标、路由器 MIPS(大端/小端、softfloat)、Windows 的 WinDivert、手动交叉编译(ARM 等)。

## 专题

- [geo.md](geo.md) — geoip/geosite 分流：用 `geoip.dat`/`geosite.dat`(protobuf) 或文本列表按国家 IP 段/域名类别匹配（`name: geoip:cn` / `geosite:cn`），`-geo-extract` 离线提取小文件、零依赖 protobuf 解析、只用 Domain+Full。
- [caching.md](caching.md) — 进程内缓存：DNS 解析缓存(10min，配了 `ip` 的域名不吃缓存)、auto 直连失败缓存(20s)、嗅探域名缓存(10min，救预连接场景的按域名匹配)；上级代理连通性缓存已移除(改每次实探)。
- [tun-features.md](tun-features.md) — TUN 全局代理特性：跨平台(Linux/Windows/macOS utun)、自动路由 `autoRoute`、QUIC(UDP443) 拦截 `blockQUIC`、UDP 转发行为、`target`/`proxy` 优先级。
- [tun-dns-resolution.md](tun-dns-resolution.md) — TUN 下域名解析优先级：系统 hosts / anyproxy 配置 hosts / DoH-DoT 三条路径谁生效；解析阶段(UDP53 劫持) vs 转发阶段(按 SNI 重查配置、`host.IP` 覆盖、TUN 不做本地 DNS 重解析)；DoH 绕过与 `ip:` 才能强制改写的边界；及私网/LAN 目标 `BypassPrivate`(Windows 默认 true)在捕获阶段就直连、不进引擎的例外。
- [multi-instance-loop.md](multi-instance-loop.md) — 同机多实例(A 开 tun + B 普通)死循环防护：`mode=bypass` 根治(仅Linux)、`loopGuard` 熔断器兜底、macOS/Windows 替代方案。
- [tun-dns-vpn-coexist.md](tun-dns-vpn-coexist.md) — TUN 与 VPN(OpenVPN/TAP)共存的三类回包故障：① VPN 内网 DNS 的 /32 路由丢失；② Windows(WinDivert) VPN 传输死循环与 `excludeProcs`/`bypassIPs` 逃逸；③ 入站连接回包被 TUN 吸走(外网 SSH 断)——Linux 源策略路由(自动)、macOS `pf reply-to`(`inboundPorts`)。
- [windows-winDivert.md](windows-winDivert.md) — Windows WinDivert 运行依赖：`WinDivert.dll`/`.sys` 放置、管理员权限、路径含空格/中文的驱动加载问题、bypass 模式在 Windows 已移除。
- [todo.md](todo.md) — 待办/待确认：PR #22 审查中暂留未处理的项（透明代理嗅探 `Peek(1)` 无超时 + 实现分叉、`HostBlocksUDP` 热路径线性扫描）。
- [windows-windivert-redirect.md](windows-windivert-redirect.md) — Windows WinDivert 重定向原理：数据包捕获→NAT 改写→本地代理→恢复目的地转发的完整链路；NAT 表、dual-stack 监听、环路防护。
- [windows-windivert-escape.md](windows-windivert-escape.md) — Windows WinDivert 逃逸机制（环路防护专题）：anyproxy 自身出站如何逃过捕获避免自环；SOCKS 层 Guard 的竞态缺陷（IPv4 能逃逸、IPv6 稳定自环）与 egress 源端口段根治方案。
