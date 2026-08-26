# TUN 模式下的域名解析优先级（系统 hosts / DoH / 配置 hosts）

本文回答一个常见困惑：**Windows 开了 TUN（WinDivert）、但没设系统代理时，浏览器访问某域名，
到底是走系统 `hosts` 文件、还是被 anyproxy 的 UDP DNS 劫持接管、还是走 DoH？最终连的是哪个 IP？**

结论先行：要分**两个独立的阶段**看——**DNS 解析阶段**决定「拿到哪个 IP」，**TCP 转发阶段**
anyproxy 还会按 SNI 域名**再查一次自己的配置**，可能覆盖前一步的 IP。二者互不等价，也各有盲点。

同时要分清两个都叫 "hosts" 的东西：

| 名字 | 是什么 | 谁在用 |
|------|--------|--------|
| **系统 hosts** | `C:\Windows\System32\drivers\etc\hosts` | 操作系统解析器（DNS Client / dnscache） |
| **anyproxy 配置 hosts** | `router.yaml` 里的 `hosts:` 段（`name`/`ip`/`target`/`dns` …） | anyproxy 的 DNS 劫持 与 TCP 转发路由 |

anyproxy **不读系统 hosts 文件**；它只认自己配置里的 `hosts:`。

---

## 1. 解析阶段：三条路径

anyproxy 的 DNS 劫持只拦**明文 UDP/53**：WinDivert 过滤器捕获 `outbound and udp.DstPort == 53`
（[`tun/wdengine/redirect.go`](../tun/wdengine/redirect.go) 的 `candidateFilters`），捕到后由
`hijackDNS`（[`tun/wdengine/dns.go`](../tun/wdengine/dns.go)）按配置 hosts 应答。据此有三种情况：

### ① 域名在系统 hosts 里 → 系统 hosts 赢，UDP 劫持拦不到

Windows DNS Client 的解析顺序是**先查系统 hosts 文件**，命中就立刻返回，**根本不往网络发 UDP/53 包**。
没有出站 UDP 包 → WinDivert 无从捕获 → `hijackDNS` 不触发。**anyproxy 的配置 hosts、fake-ip、AAAA
抑制在这一步全部落空**，浏览器拿到的是系统 hosts 里写的 IP。

### ② 域名不在系统 hosts，走明文 UDP/53 → anyproxy 劫持生效

出站 UDP/53 被 WinDivert 捕获，`hijackDNS` 按配置 hosts 匹配（`dnsutil.MatchHostDNS`）：

- 命中且配了 `ip:`、查询是 A 记录 → 直接构造应答返回**配置的 ip**（并记 `ip→域名` 供后续 TCP 还原域名）。
- 命中且是 AAAA → 返回 NOERROR 空应答，逼客户端回退 A 记录（避免真实 DNS 污染内网域名）。
- 命中 `deny` → 返回 NXDOMAIN。
- 命中但没配 `ip`（如 `target=remote` 无 `ip`）→ **不拦截**，放行走正常解析。

### ③ 客户端用 DoH/DoT → 两层解析都被绕过

DoH 把 DNS 查询封装成 HTTPS 发到 DoH 服务器的 **TCP/443**。这条 TCP 连接**会被 WinDivert 捕获**
（`tcp.DstPort == 443`），但它是**加密**的：anyproxy 只能嗅到 SNI（如 `dns.google`）后原样代理转发，
**看不到、也改不了里面查的域名**。而 `hijackDNS` 只认明文 UDP/53。于是：

- 系统 hosts 被绕过（DoH 不查本机 hosts）；
- anyproxy 的 DNS 层劫持也被绕过（拿不到明文查询）；
- DoH 服务器返回域名的**真实公网 IP**。

> DoT（DNS over TLS，TCP/853）同理：加密、不经 UDP/53，anyproxy DNS 层拦不到。
> 文档 [tun-features.md](tun-features.md) 第 3 节也标注了这个边界。

---

## 2. 转发阶段：anyproxy 会按 SNI 域名再查一次配置

拿到 IP 之后，浏览器对该 IP 发起 TCP 80/443，被 WinDivert 重定向进 anyproxy 的 `ForwardTCP`
（[`proto/forward.go`](../proto/forward.go)）。这里会**从首包嗅探域名**（TLS SNI / HTTP Host），
然后在握手前用 `findHost(dstName, dstIP)` 重查配置，核心逻辑在
[`proto/tunnel.go`](../proto/tunnel.go) 的 `handshake`：

```go
host := findHost(dstName, dstIP)   // 按嗅到的域名 或 dstIP 匹配配置 hosts
...
if host.IP != "" {
    dstIP = host.IP                        // ← 配了 ip，就覆盖掉前一步解析出的 IP
} else if dstName != "" && confDNS != "remote" && !s.req.TUN {
    dstIP, state = s.lookup(dstName, dstIP) // ← 本地 DNS 重解析：TUN 流量走不到这里
}
```

两条关键规则：

- **`host.IP != ""`：无条件用配置的 ip 覆盖目标 IP。** 这一步不区分来源，DoH 拿到的真实 IP
  在这里会被改回配置值。
- **本地 DNS 重解析那条分支带 `!s.req.TUN` 门槛。** TUN 连接 `req.TUN == true`
  （[`proto/forward.go`](../proto/forward.go) 里 `ForwardTCP` 建 `Request` 时置 `TUN: true`），
  **分支被跳过**——即便配了 `dns: local` 也不会重新解析。原因：TUN 的目标 IP 已由内核路由定死，
  再按域名解析可能得到与客户端不一致的 IP，反而错乱，解析超时还会白卡。

### DoH 场景下最终连哪个 IP（关键结论）

即便 DoH 在解析阶段绕过了一切、拿到真实公网 IP，**转发阶段仍会按 SNI 域名重查配置**：

| 该域名在 anyproxy 配置 hosts 里 | 最终连的 IP |
|---|---|
| 配了 `ip:` | **配置的 ip**（覆盖 DoH 结果，等于 DoH 白查了） |
| 只配 `dns: local`（无 `ip:`） | **DoH 的真实 IP**（TUN 不重解析，`dns: local` 对 TUN 无效） |
| 什么都没配 | **DoH 的真实 IP** |

所以：**要在 DoH 场景下强制某域名走指定 IP，唯一可靠手段是给它显式配 `ip:`**；靠 `dns: local` 或
指望本地 hosts 都不行。

### 前提：必须能嗅到 SNI 域名

`findHost` 靠 SNI/Host 得到域名才能命中 `name` 规则。若域名嗅不到（**ECH 加密 ClientHello**、
非 TLS/HTTP 协议、服务器先说话的协议等），`dstName` 为空，`findHost` 退化为**按 dstIP 匹配**——
配的是 `name` 就命不中，`host.IP` 不生效，直接用手里的 IP（DoH 真实 IP）连出去。

> 兜底：`dstName` 为空时，`ForwardTCP` 会先用 dstIP 去 DNS 劫持记录里反查域名
> （`cache.SniffName.Lookup`）。但该记录只在**明文 UDP/53 被劫持时**写入，DoH 路径不写，救不回来。

---

## 3. 需要注意的例外：这些目标压根不进转发（直连）

前两节讲的「转发阶段按 SNI 重查配置、`host.IP` 覆盖」有个大前提——**这条 TCP 得先被 WinDivert
重定向进 anyproxy**。而有几类目标在**捕获阶段**（`isDirect` / `shouldRedirect`，
[`tun/wdengine/redirect.go`](../tun/wdengine/redirect.go)）就被判为直连，**根本不进引擎**，
于是 SNI 重查、`host.IP` 覆盖、代理路由**全都不会发生**，客户端直连该 IP：

| 例外 | 判定 | 默认 |
|------|------|------|
| **私网/LAN/链路本地 IP** | `BypassPrivate && isPrivateOrLinkLocal(dstIP)` | Windows 下 **默认 true** |
| **loopback**（`127.0.0.0/8`、`::1`） | `dstIP.IsLoopback()` | 始终直连，不可关 |
| **SkipPorts**（配置的跳过端口） | `containsPort(SkipPorts, dstPort)` | 按配置 |
| **tun.bypassIPs**（`ExcludeIPs`） | `isExcludedIP(dstIP)` | 按配置（如上级代理/VPN 端点 IP） |
| **anyproxy 自身出站**（egress 源端口段 / guard） | 逃逸，防自环 | 自动 |

### ⚠️ `BypassPrivate` 默认开，最容易踩

Windows 下 `tun.windows.bypassPrivate` **不配即为 `true`**
（[`tun/tun_windows.go`](../tun/tun_windows.go)、[`utils/conf/router.go`](../utils/conf/router.go)）：
凡目标是**私网/LAN/链路本地地址（含虚拟机 VM 网段）一律直连、不进引擎**。

这与「hosts 劫持内网域名」正好高频撞车：

- 若把域名 A 的 `ip:` 配成**私网地址**（内网服务很常见），客户端解析到该私网 IP 后发起 TCP，
  **在捕获阶段就被判直连**——不走 anyproxy，也就谈不上「按 SNI 重查 / `target=remote` 走代理」。
  想让内网域名直连内网服务，这正是期望行为；但**若本意是让它走上级代理，就会被这条默认规则拦下**。
- 需要私网目标也进引擎按 router 规则处理时，显式配 `tun.windows.bypassPrivate: false`
  （此时私网 80/443 才进引擎；loopback 仍始终直连）。

> 注意与第 2 节的区别：`host.IP` 覆盖发生在**转发阶段**（已进引擎）；`BypassPrivate` 直连发生在
> **捕获阶段**（还没进引擎）。前者能改写 IP，后者直接让连接绕开 anyproxy。

### DoH 场景下这条例外一般不触发

DoH 拿到的是**真实公网 IP**（非私网），所以 `BypassPrivate` 对 DoH 结果通常不生效——DoH 的 TCP
仍会进引擎、仍会被 SNI 重查。`BypassPrivate` 主要影响的是**解析到私网 IP** 的场景
（系统 hosts / 配置 hosts 配了私网 ip / 明文 DNS 解到内网）。

---

## 4. 一张表看全

假设域名 A：

| 客户端解析方式 | A 在系统 hosts | A 在配置 hosts 的 `ip:` | 解析拿到的 IP | anyproxy 转发最终连的 IP |
|---|---|---|---|---|
| 明文 UDP/53 | 有 | — | 系统 hosts 的 IP | 若配置也配了 `ip` 则改为配置 ip；否则系统 hosts 的 IP |
| 明文 UDP/53 | 无 | 有 | **配置 ip**（DNS 劫持直接返回） | 配置 ip |
| 明文 UDP/53 | 无 | 无 | 真实 DNS 的 IP | 真实 IP（TUN 不重解析） |
| DoH/DoT | 有 | 有 | 真实公网 IP（绕过 hosts） | **配置 ip**（SNI 重查覆盖） |
| DoH/DoT | 有 | 无 | 真实公网 IP | 真实 IP（系统 hosts 也救不回） |
| DoH/DoT + ECH | — | 有 | 真实公网 IP | 真实 IP（嗅不到 SNI，`host.IP` 命不中） |

> 表中「转发最终连的 IP」列**假设连接进了引擎**。若**解析拿到的 IP 是私网/LAN**（Windows 默认
> `BypassPrivate=true`），则在捕获阶段就直连、不进引擎，该列不适用——直接连解析到的私网 IP（见第 3 节）。

一句话：**解析归解析、转发归转发**。DoH 能在解析层绕过系统 hosts 与 anyproxy 的 UDP 劫持，
但只要能嗅到 SNI 且该域名在配置里配了 `ip:`，转发层就会把 IP 改回来；`dns: local` 对 TUN 流量不生效。
再往前，私网/LAN 目标默认在捕获阶段就直连、压根不进引擎（`BypassPrivate`）。

---

## 5. 黑洞哨兵 IP：解决「系统 hosts + 代理」并存的问题

前面几节暴露了一个两难：想用**系统 hosts** 把某域名「本地屏蔽」，一旦开了 WinDivert 代理，这个域名
又希望能**经代理正常访问**。直接在 hosts 写真实 IP 做不到二者兼得。**黑洞哨兵 IP** 就是为此设计的。

### 用法

在系统 hosts（或 anyproxy 配置 hosts）里，把域名指向一个**不可路由的哨兵 IP**（默认 `192.0.0.0`）：

```
# C:\Windows\System32\drivers\etc\hosts
192.0.0.0 example.com
```

哨兵 IP 由 `default.blackholeIP` 配置，**不配默认 `192.0.0.0`**；设 `off`/`none`/`disable` 关闭。
`192.0.0.0` 属 IANA 特殊用途地址，不会撞真实业务目标，且不可路由。

### ⚠️ 哨兵必须用 192.0.0.0，不能用 127.0.0.1 或私网

哨兵能生效的前提是**目标 IP 会被路由进 TUN/引擎**。常见误用是把域名指到 `127.0.0.1`——**这不会被拦截**：

- **`127.0.0.1`（loopback）**：内核用内置路由 `127.0.0.0/8 dev lo`（/8）把它送到 loopback，比
  autoRoute 的 `0.0.0.0/1`+`128.0.0.0/1`（/1）**更具体、必然优先**；且内核特判 127/8 不往 lo 以外发。
  结果**数据包根本不进 TUN**，anyproxy 看不到、日志无记录；本机 `127.0.0.1:80` 又无人监听，于是
  立刻 `Connection refused`。典型现象是 `curl` **几毫秒内**就失败（走 TUN 经代理应是几十~几百 ms）。
- **私网/LAN（`10.x`/`192.168.x` 等）**：Windows 默认 `bypassPrivate=true` 会在捕获阶段直连、不进引擎；
  Linux 若落在本机直连子网也可能被 bypass。都不稳定。
- **`192.0.0.0`**：非 loopback、非私网、不可路由，落在 `128.0.0.0/1` 会被路由进 TUN；WinDivert 下又被
  哨兵规则强制进引擎。**这才是唯一稳妥的选择**（也是默认值）。

| 哨兵候选 | 是否进 TUN/引擎 | 结论 |
|---|---|---|
| `127.0.0.1`（loopback） | ❌ 走 lo，不进 TUN | 无法捕获，秒级 refused |
| `10.x`/`192.168.x`（私网） | △ 可能被 bypass 直连 | 不稳定 |
| **`192.0.0.0`** | ✅ 进 TUN；WinDivert 强制进引擎 | **正解（默认）** |

### 达成的两个效果

**① 没开代理时：本地不可达 = 天然屏蔽。**
`192.0.0.0` 不可路由，浏览器连它必然失败，等于把 example.com 在本机屏蔽掉——无需防火墙规则。

**② 开了 WinDivert 代理（未设系统代理）时：拦截进 anyproxy 并以 `dns:remote` 出去 = 可访问。**
分两个阶段：

- **捕获阶段**（[`tun/wdengine/redirect.go`](../tun/wdengine/redirect.go) `isDirect`）：哨兵 IP 被标记为
  **必须进引擎**，不受 `bypassPrivate`/`SkipPorts` 影响（即便你把哨兵配成私网地址也照拦不误）。
- **转发阶段**（[`proto/tunnel.go`](../proto/tunnel.go) `handshake`）：**目标 IP == 哨兵**即判定为黑洞连接，
  **强制 `target=remote` + `dns=remote`**——绝不直连 `192.0.0.0`，而是把**域名**交给下级代理，由下级
  远程解析真实 IP 并连出。于是 example.com 经代理正常访问。

  > **检测靠 `dstIP`，不靠 SNI。** 哨兵 IP 是浏览器**实际连接的目的地**（系统 hosts 把 example.com
  > 解析成 `192.0.0.0`，浏览器就朝 `192.0.0.0` 发起连接），WinDivert 捕获还原后 `dstIP` 就是它——
  > 这个信号**总是有**，判定黑洞不需要 SNI。SNI 是**另一路独立信号**，只用来还原「背后真实域名是谁」，
  > 好把域名交给下级远程解析（`192.0.0.0` 本身不能拨、也不能反查——多个域名可指向同一哨兵，反查不唯一）。

  | 要判断的事 | 信号来源 | 是否总是有 |
  |---|---|---|
  | 是不是黑洞连接 | `dstIP`（内核路由/捕获得到） | **总是有** |
  | 背后真实域名 | SNI / Host 首包 | 可能嗅不到（ECH、非 TLS、无首包） |

```
浏览器 → example.com(hosts→192.0.0.0) → TCP 192.0.0.0:443
      → WinDivert 捕获(哨兵强制进引擎) → anyproxy 嗅 SNI=example.com
      → 强制 remote+remote → 下级代理按域名解析真实 IP → 连通
```

### 边界与注意

- **有哨兵 dstIP 但嗅不到域名 → 拒绝**（不是死代码，正为这种情形准备）：会出现「`dstIP==192.0.0.0`
  但 `dstName==""`」的真实情况——浏览器开 **ECH**（加密 ClientHello）照样从 hosts 拿到 `192.0.0.0`
  并连过去，但 SNI 被加密；还有非 TLS/HTTP、非 80/443 无首包等。此时**确知是黑洞连接**（dstIP 命中），
  却**不知道让下级解析哪个域名**，又绝不能直连 `192.0.0.0`——三者叠加只能**拒绝**
  （`blackhole ip ... but no domain to proxy`）。
  - 细节：若哨兵是通过 **anyproxy 配置 hosts**（非系统 hosts）映射的，DNS 劫持时已把 `192.0.0.0→域名`
    记进 `cache.SniffName`，即便无 SNI，`ForwardTCP` 也能反查回域名，不会走到拒绝。**只有系统 hosts
    哨兵 + 无 SNI** 才真正落到拒绝分支（系统 hosts 不经 UDP 劫持，SniffName 无记录）。
- **必须有可用的下级代理**：走到转发阶段仍无可用代理时**直接判失败**
  （`blackhole ip ... requires an upstream proxy`），不会徒劳拨号 `192.0.0.0` 等超时。等价于"无代理即不可访问"。
- **显式 `deny` 优先**：若配置规则已把该域名判 `deny`，不被哨兵逻辑覆盖（仍然拒绝）。
- **端口范围**：捕获仍受 WinDivert 过滤器端口约束（默认 80/443）。哨兵主要面向 Web 域名；
  其它端口若未纳入捕获则不生效。
- **跨平台**：转发阶段的强制 `remote+remote` 逻辑是三平台共用的（[`proto/tunnel.go`](../proto/tunnel.go)）；
  Linux/macOS gVisor TUN 同样适用（`192.0.0.0` 非私网，本就会被捕获）。捕获阶段的"强制不 bypass"
  仅 Windows WinDivert 需要（其它平台哨兵非私网、本就进栈）。

### 与 DoH 的关系

若客户端用 DoH，解析 example.com 时**不查系统 hosts**，拿到的是真实公网 IP（不是哨兵）——此时效果①
（本地屏蔽）失效。要对 DoH 客户端也生效，需改用 anyproxy 配置 hosts 把域名映射到哨兵（DNS 层劫持，
见第 1 节②），或屏蔽 DoH 服务器逼其回退明文 DNS。

## 相关文档

- [tun-features.md](tun-features.md) — TUN 特性总览、DNS 劫持与 `blockQUIC`（QUIC/UDP443 对配了 `ip` 域名的 drop）。
- [windows-windivert-redirect.md](windows-windivert-redirect.md) — WinDivert 捕获→NAT→本地代理→恢复目的地的转发链路。
- [routing.md](routing.md) — `target`/`proxy`/`dns`/`ip` 等路由字段语义与优先级。
