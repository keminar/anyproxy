# TUN 与 VPN（OpenVPN/TAP）共存时的 DNS 排查

本文记录一个真实故障：**anyproxy TUN 全局代理与 OpenVPN Connect 同机共存时，手动删掉一条 /32 路由后，所有未被 hosts 劫持的域名解析全部超时**。

## 现象

```
> nslookup baidu.com
DNS request timed out.
    timeout was 2 seconds.
服务器:  UnKnown
Address:  10.18.0.1        # 解析器指向的是 OpenVPN 隧道内网 DNS
*** 请求 UnKnown 超时
```

命中 anyproxy `hosts` 配置的域名能解析（anyproxy 本地直接构造应答），其余全部超时。

## 拓扑

同机同时跑两层隧道：

- **anyproxy TUN**：`autoRoute` 装了 `0.0.0.0/1` + `128.0.0.0/1`，接管几乎所有流量。
- **OpenVPN Connect TAP**：`TAP-Windows Adapter V9`，IP `10.18.0.70/30`（掩码 `255.255.255.252`，本地直连段只含 `10.18.0.68 ~ 10.18.0.71`），DNS 服务器 `10.18.0.1`，**无默认网关**。

关键：**DNS `10.18.0.1` 不在 TAP 的 `/30` 直连段里**，它在隧道对端，只能靠 OpenVPN 装的一条 `10.18.0.1/32 → TAP` 路由才到得了。

## 根因

Windows 路由是**最长前缀匹配优先**，`/32` 永远压过 anyproxy 的 `/1`：

- **/32 在**：查询 `10.18.0.1` 直接进 TAP → 走 VPN 的 DNS → 正常，anyproxy 全程没参与。
- **/32 被删**：到 `10.18.0.1` 只剩 anyproxy 的 `0/1` → 包被吸进 anyproxy 的 TUN → anyproxy 没有任何办法把它送回 TAP：
  - 强绑物理网卡（`IP_UNICAST_IF`）→ 物理网络上没有 `10.18.0.1` → **黑洞**；
  - 普通 dial（不绑接口）→ 系统按路由表又选中 `0/1` → 回灌 anyproxy → **死循环**。

### 为什么 `isLocalNet` 补不了

`isLocalNet` / `dstInBypassNet`（`proto/dialer_*.go`、`tun/udp.go`）**只判"本机直连子网"**（`config.TUNBypassNets`，由 `initBypassNets` 采集各网卡直连段），**没有 RFC1918 判断**。`10.18.0.1` 不属于任何本机直连子网（TAP 只给了 `/30`），因此 `isLocalNet(10.18.0.1) == false`。

即使把它改成按私有段返回 true 也无用——只会把"黑洞"换成"死循环"：删了 /32 后系统里通往 `10.18.0.1` 的唯一路由就是 anyproxy 的 `0/1`，普通 dial 照样绕回自己。**source of truth 是路由表**，代码判断造不出一条通往别人隧道的路。

## 修复

1. **别删那条 /32（最省事）**：重连 OpenVPN Connect 让它重新 push，或手动补：
   ```cmd
   :: 找 TAP 的接口索引
   netsh interface ip show interfaces
   :: 把 10.18.0.1 钉回 TAP（net30 拓扑对端一般是 .69；用接口索引最稳）
   route add 10.18.0.1 mask 255.255.255.255 10.18.0.69 if <TAP的Idx> metric 1
   ```
   anyproxy 只要不被喂到这个包，就天然正确。

2. **代码级兜住 VPN 段（待实现，方案 B）**：新增「按目标网段绑定到指定接口 ifindex」的 bypass 配置，TCP `tunDial` 与 UDP `listenUDP` 命中时把 `IP_UNICAST_IF` 指向 **TAP 的索引**（而非物理网卡），让 anyproxy 即使没有系统 /32 也能主动把 VPN 内网流量（含 DNS）送回 TAP：
   ```yaml
   tun:
     bypassRoutes:
       - net: 10.18.0.0/24     # 或精确到 10.18.0.1/32
         dev: "TAP-Windows Adapter V9 for OpenVPN Connect"
   ```

## 排查命令

### 1. 检查 /32 例外路由是否存在（VPN DNS / 上游是否还被正确导向）

```powershell
Get-NetRoute -AddressFamily IPv4 |
    ? { $_.DestinationPrefix -match '/32$' -and $_.NextHop -in '192.168.1.1','10.18.0.69' } |
    Sort-Object NextHop,DestinationPrefix |
    Format-Table DestinationPrefix,NextHop,ifIndex,RouteMetric
```

- 若 `10.18.0.1/32`（下一跳指向 TAP，如 `10.18.0.69`）**不在列表**，说明通往 VPN DNS 的路由已丢，DNS 会被 anyproxy 的 `0/1` 吞掉。
- 顺便核对上游代理 / 网关的 /32 例外是否还在（下一跳 `192.168.1.1`）。

对照哪个 ifIndex 是 TAP / 物理网卡：

```powershell
Get-NetAdapter | Format-Table Name,ifIndex,Status
```

### 2. 分别向不同 DNS 发起查询，定位是"路由问题"还是"解析问题"

```cmd
:: 走当前默认解析器（可能是 10.18.0.1）
nslookup baidu.com

:: 显式指定 VPN 内网 DNS，验证 /32 路由是否把它送进了 TAP
nslookup baidu.com 10.18.0.1

:: 显式指定物理网络的真实 DNS，作为对照
nslookup baidu.com 192.168.1.1
```

判读：

- `10.18.0.1` 超时、`192.168.1.1` 正常 → 通往 VPN DNS 的 /32 路由丢了（本故障）。
- 两者都超时 → 更上层问题（anyproxy 未逃出 TUN、`TUNBypassIfIndex=0` 等，见启动日志 `TUN bypass:` 行）。
- 两者都正常 → DNS 已恢复。

## VPN 传输死循环（Windows/WinDivert）与逃逸配置

上面讲的是 VPN **内网 DNS** 的路由问题。另一个独立故障是 **VPN 传输本身的死循环**——仅 Windows(WinDivert 模型)会遇到。

### 成因

OpenVPN 走 **TCP 传输**（如 `tcp/443`，常用于穿透防火墙）且开了 redirect-gateway（默认路由指向 VPN）时：

```
openvpn.exe → VPN服务器:443 (TCP传输)
   → WinDivert 捕获(443 是重定向端口) → NAT 到 anyproxy 本地监听
   → anyproxy 回拨 VPN服务器:443（自身出向被 SOCKET guard 放行，不再捕获）
   → 但默认路由=VPN隧道 → openvpn.exe 又封包发往 VPN服务器:443
   → 又被 WinDivert 捕获 → …… 死循环
```

根子：**OpenVPN 自己发往 VPN 服务器的传输包被 WinDivert 抓走了**。UDP 传输（默认 1194/UDP，或 udp/443）不在捕获范围（只捕获 TCP 80/443 与 UDP 53/443 且 UDP443 仅对 hosts 劫持 IP 丢弃），不受影响。

### 逃逸配置（二选一或叠加）

1. **按进程名排除（首选，IP 无关）**：把 OpenVPN 进程加进 `tun.excludeProcs`，它的一切出向连接都不重定向。换服务器/多服务器/故障切换都覆盖，最稳。
   ```yaml
   tun:
     excludeProcs:
       - openvpn.exe
   ```
2. **按目的 IP 排除（补充）**：把 VPN 服务器 IP/CIDR 填进 `tun.bypassIPs`，到该地址的流量跳过捕获、直连。
   ```yaml
   tun:
     bypassIPs:
       - 203.0.113.10       # VPN 服务器公网 IP
   ```

生效后启动日志会打印 `tun(windivert): exclude procs=[openvpn.exe] ips=[...]`。

> 为什么不自动扫路由表识别 VPN 服务器：OpenVPN 的 `<server>/32 via 物理网关` 虽可探测，但 `/32` 路由不止它会加，启发式易误伤/漏判，显式配置更可控。
>
> 注意区分两类故障：本节是**传输层被 WinDivert 抓走**（Windows 专有）；上文是**VPN 内网 DNS 的 /32 路由丢失**（跨平台路由问题）。两者独立，可能同时存在。

## 入站连接回包被 TUN 吸走（对外服务/外网 SSH 断）

另一类回包故障：**外部主动连进这台机器**（如外网 SSH 登录），本机服务(sshd)回包的源=物理网卡 IP、目标=外部客户端 IP，命中 TUN 的 `0.0.0.0/1`+`128.0.0.0/1` → 被吸进 TUN → 当成新出站处理 → 回不去，握手卡死。三平台的 gVisor TUN(Linux/macOS) 都有此问题（Windows 是 WinDivert 集中捕获模型，机制不同）。

### Linux：源策略路由（已内置，自动）

Linux 用 `ip rule` 源地址策略路由根治：TUN 默认路由挪到独立表，`ip rule from <物理IP> lookup main` 让「源=物理 IP 的回包」查主表走物理网卡，其余才进 TUN。`autoRoute=true` 时自动生效，无需配置。细节见 `tun/route_linux.go`。

### macOS：pf reply-to（需显式开启）

macOS **没有** Linux 的源策略路由/多路由表，改用 pf 的 `reply-to` 让入站连接的回包沿进来的网卡原路返回。配置需放行的入站端口即可（需 root，`autoRoute=true` 时随路由一起装）：

```yaml
tun:
  inboundPorts:
    - 22        # 外网 SSH
    - 443       # 对外 https 服务
```

生效时启动日志：`inboundPF: 已放行入站端口 22 的回包(pf reply-to via en0 <gw>)`。原理是往 `com.apple/anyproxy` 子 anchor（macOS 主规则集自带 `anchor "com.apple/*"` 通配，会自动求值）加一条：

```
pass in quick on en0 reply-to (en0 <网关>) inet proto tcp from any to (en0) port { 22 } flags S/SA keep state
```

退出时自动 flush 该 anchor 并释放 pf 启用引用（`pfctl -X <token>`），不影响系统其它 pf 规则。

验证 / 手动排查：

```bash
sudo pfctl -a com.apple/anyproxy -sr      # 查看已加载的 reply-to 规则
```

> 注意：`inboundPorts` 只在 `autoRoute=true`（默认）时随 TUN 路由一起安装；若你手动加 `0/1` 路由(autoRoute:false)，也需自行加等价 pf 规则。若你的 macOS 用了自定义 `/etc/pf.conf` 去掉了 `anchor "com.apple/*"`，子 anchor 不会被求值，此机制会静默失效——用上面的 `pfctl -sr` 确认。

**实现依赖与验证状态**（截至 2026-08-11）：

- 代码在 [tun/pf_darwin.go](../tun/pf_darwin.go) + [tun/route_darwin.go](../tun/route_darwin.go)，三平台可编译通过，但 **pf 部分尚未在真机 macOS 验证**。
- 两个环境前提：① 依赖系统主规则集里的 `anchor "com.apple/*"`（macOS 默认有）；② 仅 `autoRoute=true` 时安装。
- 首次上真机请保留一个不走该链路的会话（本地终端/屏幕共享），确认外网 SSH 能连上再依赖；若 `pass in ... reply-to ...` 规则语法在你的 macOS 版本上有出入，据 `pfctl -a com.apple/anyproxy -sr` / 系统日志调整。

## 相关

- 同机双 anyproxy 的环路防护见 [multi-instance-loop.md](./multi-instance-loop.md)。
- TUN 路由与 bypass 机制见 [routing.md](./routing.md)、[tun-features.md](./tun-features.md)。
