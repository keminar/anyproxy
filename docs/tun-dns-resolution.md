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

上面几节暴露了一个两难：想用 **hosts 把域名本地屏蔽**，一旦开了代理，这个域名又希望能**经代理正常访问**。
直接写死一个 IP 做不到两全。**黑洞哨兵 IP**（默认 `192.0.0.0`）就是解法——把域名指向它：

```
# hosts：C:\Windows\System32\drivers\etc\hosts 或 /etc/hosts
192.0.0.0 example.com
```

- **没开代理**：`192.0.0.0` 不可路由 → 连它必然失败 → 域名本机被屏蔽。
- **开了 anyproxy（tun/WinDivert）**：连接被拦截进引擎 → 从 SNI/Host 还原真实域名 → 强制
  `target=remote`+`dns=remote` → 下级代理解析真实 IP 连出 → 正常访问。

关键点：**检测靠 `dstIP`（哨兵就是浏览器实际连的目的地，总是有），SNI 只用来还原真实域名交给下级解析**；
哨兵**必须用 `192.0.0.0`**，用 `127.0.0.1`（loopback 不进 TUN）或私网（可能被 bypass）都不行。

> 📖 完整专题（动机、两阶段原理、配置、跨平台、示例、排错 FAQ）见
> **[blackhole-sentinel.md](blackhole-sentinel.md)**。

## 相关文档

- [blackhole-sentinel.md](blackhole-sentinel.md) — **黑洞哨兵 IP 专题**：一个哨兵 IP 同时实现「无代理时本地屏蔽」+「有代理时经下级远程解析访问」。

- [tun-features.md](tun-features.md) — TUN 特性总览、DNS 劫持与 `blockQUIC`（QUIC/UDP443 对配了 `ip` 域名的 drop）。
- [windows-windivert-redirect.md](windows-windivert-redirect.md) — WinDivert 捕获→NAT→本地代理→恢复目的地的转发链路。
- [routing.md](routing.md) — `target`/`proxy`/`dns`/`ip` 等路由字段语义与优先级。
