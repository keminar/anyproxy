# TUN 模式特性与路由/代理规则说明

本文档汇总 anyproxy TUN 全局代理相关的几项特性与规则语义：跨平台支持、自动路由、
QUIC(UDP443) 拦截、UDP 转发行为，以及 `target`/`proxy` 的优先级。

死循环防护（同机 A+B）单独见 [multi-instance-loop.md](multi-instance-loop.md)。

## 1. 跨平台 TUN 支持

| 平台 | 实现 | 说明 |
|------|------|------|
| Linux | `/dev/net/tun`（`IFF_TUN\|IFF_NO_PI`）+ gVisor 用户态栈 | 读写纯 IP 包 |
| macOS | 原生 utun（`AF_SYSTEM` 控制 socket）+ gVisor 用户态栈 | 自实现，不引入外部依赖 |
| Windows | **WinDivert** 网络层重定向（**非虚拟网卡、非 gVisor**）| 需 `WinDivert.dll` + `WinDivert64.sys`，见 [windows-winDivert.md](windows-winDivert.md) |

- **Linux/macOS**：建 TUN 虚拟网卡，包进 gVisor 用户态协议栈解析出 TCP 再复用代理逻辑。
  macOS 通过 `Socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)` + `IoctlCtlInfo` 打开 utun，
  网卡名形如 `utun4`（配 `tun.name: utunN` 可指定单元，留空由内核自选）；utun 每包带 4 字节
  地址族头，Device 层读写时自动剥/补，对上层 gVisor 透明。两者共用同一套 gVisor 栈，行为一致。
- **Windows**：不建虚拟网卡，用 WinDivert 在网络层捕获出站 TCP 80/443 并 NAT 重定向到本地监听端口，
  再复用同一套代理路由逻辑。因此 `tun.name/addr/mtu/autoRoute` 等虚拟网卡参数在 Windows 上被忽略。

启动（三平台一致，需管理员/root）：
```
# 命令行开启（配 IP 默认 10.9.0.1/24）
sudo ./anyproxy -mode tun -p 'socks5://127.0.0.1:10000'

# 网卡名和接口地址通过配置 tun.name / tun.addr 指定
sudo ./anyproxy -mode tun

# 或在 conf/router.yaml 中配置 tun.enable: true 后直接启动
sudo ./anyproxy
```

## 2. 自动路由 autoRoute（默认开启）

`tun.autoRoute` 控制启动时是否自动添加全局路由，**不配置时默认 true**（三态 `*bool`，
显式设 `false` 才关闭）。

| 配置 | 行为 |
|------|------|
| 不写 `autoRoute` | **true** — 启动自动加 `0.0.0.0/1`+`128.0.0.0/1` 路由及 bypass 例外，退出清理 |
| `autoRoute: true` | 同上 |
| `autoRoute: false` | 只打印路由命令，由你手动执行 |

三平台均已实现（Linux `ip route` / Windows `route add if` / macOS `route add -interface`）。

> 默认 true 意味着开 `mode=tun` 就会接管默认路由。上级代理必须直连、不能走 TUN，否则环路断网。
> **以 IP 指定的上级代理会自动加入直连例外**（`tun.bypassIPs`，autoRoute 加 `/32` 直连路由）；
> 只有**域名指定**的上级代理需手动把其 IP 填进 `tun.bypassIPs`。

`autoRoute: false` 时启动只打印命令，需按提示手动接管（需管理员/root）：

```
# Linux: 接管默认路由前，务必先给上级代理出口 IP 加直连例外，否则会环路断网
sudo ip route add <上级代理IP>/32 via <原网关> dev <原网卡>
sudo ip route add 0.0.0.0/1 dev anytun0
sudo ip route add 128.0.0.0/1 dev anytun0

# Windows: 同样先给上级代理 IP 加直连例外
route add <上级代理IP> mask 255.255.255.255 <原网关>
route add 0.0.0.0 mask 128.0.0.0 10.9.0.1
route add 128.0.0.0 mask 128.0.0.0 10.9.0.1
```

## 3. QUIC(UDP 443) 拦截 blockQUIC（默认开启）

### 问题

TUN 模式下所有 UDP 都直连转发、**不走代理链**（见第 4 节）。这导致 hosts 里配了 `ip:` 的
域名（内网劫持），其 QUIC/HTTP3(UDP 443) 会拿着劫持 IP 直接出网、绕过本应生效的 TCP+SNI 代理路径。

### 方案

`tun.blockQUIC`（**默认 true**，三态 `*bool`）：对「目标 IP 精确等于某个 `host.ip`」的 UDP 443
包直接 drop。QUIC 设计要求优雅回退，客户端 UDP 443 不通会自动降级到 TCP 443 → 走已有的
TCP+SNI 代理链，hosts 规则照常生效。

- **判定只用 `dstIP == host.ip` 精确匹配**（确定、唯一）。不做 IP→域名反查：一个 IP 可对应多个
  域名（CDN/共用 IP），反查不唯一、不能作为判定依据。
- **不解析 QUIC 包**：复用 DNS 劫持已知的 `ip` 配置即可，无需 QUIC Initial 解密。
- 关闭：`tun.blockQUIC: false`。

### 覆盖范围与边界

- ✅ 覆盖：hosts 配了 `ip:` 的域名（含 `target=remote`+`ip`）。
- ⚪ `deny` 域名无需在此处理：DNS 层已返回 NXDOMAIN、客户端拿不到 IP，天然发不出 QUIC。
- ⚠️ 不覆盖：`target=remote` 但**没配 `ip`** 的域名（走真实 DNS/真实 IP，本机无可靠域名信号）。
  如需拦截，给该域名配上 `ip:` 即可纳入。
- ⚠️ 用 DoH/DoT 绕过本机 DNS 劫持的客户端不受此机制影响（拿不到劫持 IP）。

误杀风险极低：屏蔽 UDP 443 的效果是 HTTP3 降级为 HTTP2/TCP，页面照常打开，仅失去 QUIC 性能优化，
是业界标准做法（Clash/sing-box 默认亦如此）。

## 4. UDP 转发行为

- **所有 UDP（任意端口）在进 gVisor 前被拦下直连转发**，经物理网卡出网（绑源 IP + `SO_BINDTODEVICE`
  逃出 TUN，见第 6 节），**不走上级代理**（tunnel/socks5 碰不到 UDP）。
- **DNS(53)** 额外做一层本地 hosts 劫持：命中配了 `ip` 的域名直接本地应答该 IP；`deny` 域名回
  NXDOMAIN；未命中的照常直连转发到真实 DNS。
- **QUIC(443)** 见第 3 节。其余 UDP 一律 NAT 直连转发。

## 5. target 与 proxy 的优先级

`hosts[].target` 与 `hosts[].proxy` 组合时的语义（`proto/tunnel.go` handshake）：

| target | proxy | 结果 |
|--------|-------|------|
| `local` | 有 | **本地直连**，proxy 被忽略（显式 local 优先级最高）|
| `remote` | 有 | 走该定制 proxy；代理挂了且无 `local` 兜底则报错，不直连 |
| `auto` | 有 | **先直连**，不通再走该 proxy（本地优先，不强制走代理）|
| `remote`/`auto` | 无 | 走全局代理 / auto 自动选择 |
| `deny` | — | 中断请求 |

要点：`target: local` 优先级最高，配了 proxy 也直连；`auto` 一律本地优先，不会因配了 proxy 就强制走代理。
完整判定逻辑（多代理、`local`/`deny` 兜底、host/全局回退、缓存）见 [proxy-decision.md](proxy-decision.md)。

## 6. 本机出向如何逃出 TUN（Linux）

TUN 接管全局流量后，anyproxy 自己的出向连接（直连目标、或连上级代理）**必须逃出 TUN**，否则
出向包又被自己的 `anytun0` 抓走、源地址变成 `10.9.0.1`，被 gVisor 当成新连接再处理一遍 → **死循环**。

Linux 用**策略路由**（`tun/route_linux.go`，`autoRoute=true` 自动生效）区分「本机出向」和「进 TUN 的流量」：

| ip rule | 作用 |
|---------|------|
| `pref 100  from <物理网卡IP> lookup main` | **源 IP=物理网卡 IP** 的包查 main → 走物理网卡默认路由（逃出 TUN）|
| `pref 110  from all lookup main suppress_prefixlength 0` | 用 main 的**具体**路由（LAN/环回/上级代理 `/32`），但忽略默认路由 |
| `pref 120  from all lookup <tun表>` | 其余（本该走默认路由的）进 `anytun0`，被 gVisor 接管 |

关键点：**`pref 100` 是按「源 IP」匹配的，不是按网卡**。所以本机出向要逃出 TUN，必须让连接的
**源 IP 一开始就是物理网卡 IP**。为此 `tunDial`（TCP，`proto/dialer_linux.go`）与 `listenUDP`
（UDP，`tun/udp_dial_linux.go`）对**非本机直连子网**的 IPv4 目标同时做两件事：

1. **绑源 IP = 物理网卡 IP**（`LocalAddr` / `bind`）——命中 `pref 100` 的**主**手段，决定能否逃逸。
2. **`SO_BINDTODEVICE` 绑物理网卡**——兜底，强制从该网卡出（取不到源 IP、或**一网卡多 IP**时保证出口正确）。

> 为什么绑源 IP 是主、绑网卡是次：`SO_BINDTODEVICE` 在内核路由决策阶段**并不设置源 IP**，单靠它
> 命中不了按源 IP 匹配的 `pref 100`，会掉进 `pref 120` 进 TUN 成环路。绑网卡只能保证「从哪块网卡
> 出」，保证不了「用哪个源 IP」，而逃逸判据恰恰是源 IP。
>
> **一网卡多 IP**：`pref 100` 对该网卡的**每个** IPv4 都加了规则，绑其中任一个都能命中；我们绑
> `physIPv4s(dev)[0]`（该网卡第一个 IPv4），再叠加 `SO_BINDTODEVICE` 锁定网卡，多 IP 场景也正确。

启动日志 `TUN bypass: device="enp3s0" ip="192.168.144.183" ...`：`device` 与 `ip` 都非空才算逃逸
就绪。若 `ip=""`（旧版本症状）则没绑源 IP，本机直连公网会环路。

### 排查：反复 `direct to <IP>` 是环路还是正常遥测？

现象：日志里同一个域名（常见如 `otheve.beacon.qq.com` 等 QQ/腾讯**打点遥测**域名）不停刷
`direct to <IP>`，尤其**流量来自 TUN 后面的虚拟机（VM）里的 Windows**时。这**多数不是环路**，而是
VM 里的应用在高频上报遥测，每次都新建连接。**逃逸正常**时它们都是「连上→传完→关闭」的真实直连。

判断是不是环路（二选一即可确诊）：

```bash
# 1) 有没有源=10.9.0.1 的本机出向连接？有＝没逃出 TUN＝环路铁证；空＝正常。
sudo ss -tnp | grep anyproxy | grep 10.9.0.1

# 2) 采样几秒, 到该 IP 的连接数是否只涨不落 / 某个 IP 连接数异常多(几十上百)？
sudo ss -tnp | grep anyproxy | grep -oE '[0-9.]+:(443|80)' | sort | uniq -c | sort -rn | head
```

- 出向源全是物理网卡 IP（如 `192.168.144.183%enp3s0`）、无 `10.9.0.1`、每个目标连接数个位数 → **正常**，只是遥测吵。
- 出现 `10.9.0.1` 源、或某 IP 连接数暴涨 → 真环路，检查启动日志 `TUN bypass:` 的 `ip` 是否为空、`ip rule` 是否有 `pref 100`。

消除噪声：给该遥测域名配 `target: deny` 直接掐掉即可（不影响正常业务）：

```yaml
hosts:
  - name: otheve.beacon.qq.com
    match: contain
    target: deny
```

> 注意：手动 `ip route add <IP> via <网关> dev <物理网卡>` 也能让日志消失，但那是把该 IP 的
> **VM 流量在 `pref 110` 处直接放行、绕开了 anyproxy**（`/32` 是具体路由不被 suppress），并不代表
> 之前有环路，也不是推荐做法。确认逃逸正常后应删掉这类手动 `/32`，用 `deny` 或直接忽略遥测噪声。

## 配置速查

| 配置项 | 默认 | 说明 |
|--------|------|------|
| `mode` | `proxy` | `tun` 建虚拟网卡全局代理（三平台）|
| `tun.name` | 平台默认 | Linux `anytun0` / Windows `AnyProxy` / macOS `utunN`(内核自选) |
| `tun.autoRoute` | **true** | 不配置即自动加路由；`false` 只打印命令 |
| `tun.bypassIPs` | 空 | 直连例外（以 IP 指定的上级代理自动并入；域名代理需手动填 IP）|
| `tun.blockQUIC` | **true** | drop 配了 ip 的域名的 UDP443，逼 QUIC 回退 TCP；`false` 关闭 |
