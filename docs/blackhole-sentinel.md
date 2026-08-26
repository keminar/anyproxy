# 黑洞哨兵 IP 专题

> 一个哨兵 IP，同时解决「**没开代理时本地屏蔽某域名**」和「**开了 anyproxy 代理时该域名又能正常访问**」
> 这对看似矛盾的需求。

## 1. 要解决的问题

用**系统 hosts** 屏蔽域名是最省事的手段——把 `example.com` 指到一个连不通的地址，浏览器就打不开它。
但一旦开了 anyproxy 的全局代理（TUN / Windows WinDivert），你往往又希望**这个域名恰恰要能经代理访问**
（例如它在本地网络被污染/被墙，只有走下级代理才通）。

直接在 hosts 里写死一个 IP 无法两全：

| hosts 写法 | 没开代理 | 开了代理 |
|---|---|---|
| 写**真实公网 IP** | 能连（没屏蔽） | 能连，但绕过了「按域名走代理」的意图 |
| 写**假 IP**（如 `1.2.3.4`） | 连不通（屏蔽✓） | 代理**直连这个假 IP** 也连不通 ✗ |
| 写 **`127.0.0.1`** | 连本机（不是屏蔽，行为怪异） | loopback **根本不进代理**，连本机 80 端口 ✗ |

**黑洞哨兵 IP** 就是为这个两难设计的：把域名指到一个**不可路由的哨兵地址**（默认 `192.0.0.0`），
anyproxy 识别到「目标是哨兵」后，不去直连它，而是**从流量里还原真实域名、强制交给下级代理远程解析**。

## 2. TL;DR

```
# 系统 hosts（C:\Windows\System32\drivers\etc\hosts 或 /etc/hosts）
192.0.0.0 example.com
```

- **没开 anyproxy 代理**：`192.0.0.0` 不可路由 → 连它必然失败 → `example.com` 本机被屏蔽。
- **开了 anyproxy（tun / WinDivert，未设系统代理）**：连接被拦截进引擎 → 从 SNI/Host 还原
  `example.com` → **强制 `target=remote` + `dns=remote`** → 下级代理解析真实 IP 并连出 → 正常访问。
- 无需改配置即可用（`default.blackholeIP` 默认就是 `192.0.0.0`）；配了下级代理才有「可访问」效果，
  没配下级代理就是纯屏蔽。

## 3. 配置

唯一开关是 `default.blackholeIP`：

```yaml
default:
  # 黑洞哨兵IP, 不配默认 192.0.0.0; 设 off/none/disable 关闭
  #blackholeIP: 192.0.0.0
```

- **不配 = 默认 `192.0.0.0`**（功能默认开启，但只有流量真的指向该 IP 时才触发，平时零影响）。
- 可改成别的哨兵地址（需满足第 4 节的「可路由进引擎」条件）。
- 设 `off` / `none` / `disable` 彻底关闭。

哨兵可来自**两处**，语义一致、可混用：

| 来源 | 写法 | 特点 |
|---|---|---|
| **系统 hosts** | `192.0.0.0 example.com` | 最简单；但 **DoH 客户端不查 hosts**，对其无效（见第 7 节） |
| **anyproxy 配置 hosts** | `- name: example.com` + `ip: 192.0.0.0` | 走 anyproxy DNS 层劫持，**对 DoH 也生效**；还能顺带被 `blockQUIC` 覆盖 |

## 4. 哨兵为什么必须是 192.0.0.0（不能用 127.0.0.1 / 私网）

哨兵生效的前提是**目标 IP 会被路由进 TUN / 被引擎捕获**。这条最容易踩坑：

- **`127.0.0.1`（loopback）——无法拦截。** 内核用内置路由 `127.0.0.0/8 dev lo`（/8）把它送去 loopback，
  比 TUN autoRoute 的 `0.0.0.0/1` + `128.0.0.0/1`（/1）**更具体、必然优先**，且内核特判 127/8 不往 lo
  以外发。结果**数据包根本不进 TUN**，anyproxy 看不到、日志无记录；本机 `127.0.0.1:80` 又无人监听，
  于是立刻 `Connection refused`。典型现象：`curl` 在**几毫秒内**就失败（走 TUN 经代理应是几十~几百 ms）。
- **私网/LAN（`10.x` / `192.168.x` / `172.16.x` 等）——不稳定。** Windows 默认 `bypassPrivate=true`
  会在捕获阶段直连、不进引擎；Linux 若该地址落在本机某直连子网也会被 bypass。
- **`192.0.0.0`——正解。** 属 IANA 特殊用途地址（IETF Protocol Assignments），不会撞真实业务目标，
  不可路由；落在 `128.0.0.0/1` 会被路由进 TUN；WinDivert 下又被哨兵规则强制进引擎。

| 哨兵候选 | 是否进 TUN/引擎 | 结论 |
|---|---|---|
| `127.0.0.1`（loopback） | ❌ 走 lo，不进 TUN | 无法捕获，秒级 refused |
| `10.x` / `192.168.x`（私网） | △ 可能被 bypass 直连 | 不稳定 |
| **`192.0.0.0`** | ✅ 进 TUN；WinDivert 强制进引擎 | **正解（默认）** |

## 5. 工作原理（两个阶段）

```
浏览器 → example.com(hosts→192.0.0.0) → TCP 192.0.0.0:443
      → [捕获阶段] TUN/WinDivert 拦截(哨兵强制进引擎)
      → [转发阶段] anyproxy 嗅 SNI=example.com → 强制 remote+remote
      → 下级代理按域名解析真实 IP → 连通
```

### 捕获阶段：强制进引擎

- **Windows（WinDivert）**：[`tun/wdengine/redirect.go`](../tun/wdengine/redirect.go) 的 `isDirect` 把哨兵 IP
  标记为**必须进引擎**，**不受 `bypassPrivate` / `SkipPorts` 影响**（即便有人把哨兵配成私网地址也照拦不误）。
- **Linux / macOS（gVisor）**：哨兵是普通可路由地址，autoRoute 的 `0/1`+`128/1` 已把它导入 TUN，
  自然进栈，无需额外处理。

### 转发阶段：强制 remote + remote（三平台共用）

[`proto/tunnel.go`](../proto/tunnel.go) 的 `handshake`：**目标 IP == 哨兵**即判定为黑洞连接，
**强制 `target=remote` + `dns=remote`**——绝不直连 `192.0.0.0`，而是把**域名**交给下级代理，
由下级远程解析真实 IP 并连出。

> **检测靠 `dstIP`，不靠 SNI。** 哨兵 IP 是浏览器**实际连接的目的地**（hosts 把 `example.com` 解析成
> `192.0.0.0`，浏览器就朝 `192.0.0.0` 发起连接），捕获还原后 `dstIP` 就是它——这个信号**总是有**，
> 判定黑洞不需要 SNI。SNI 是**另一路独立信号**，只用来还原「背后真实域名是谁」，好把域名交给下级
> 远程解析（`192.0.0.0` 本身不能拨、也不能反查——多个域名可指向同一哨兵，反查不唯一）。

| 要判断的事 | 信号来源 | 是否总是有 |
|---|---|---|
| 是不是黑洞连接 | `dstIP`（内核路由 / 捕获得到） | **总是有** |
| 背后真实域名 | SNI / Host 首包 | 可能嗅不到（ECH、非 TLS、无首包） |

这也解释了为什么 anyproxy 的 gVisor（Linux/macOS）路径同样生效：TCP 连接由
[`tun/stack.go`](../tun/stack.go) `handleTCP` 交给共享的 `proto.ForwardTCP`（`TUN=true`），
走的正是同一套 `handshake` 黑洞判定。

## 6. 完整示例

### 例 A：Windows + 系统 hosts（最常见）

```
# C:\Windows\System32\drivers\etc\hosts
192.0.0.0 blocked-but-proxyable.com
```

```yaml
# router.yaml
mode: tun            # Windows 走 WinDivert
default:
  proxy: socks5://127.0.0.1:1080   # 下级代理(能解析并访问目标)
  #blackholeIP: 192.0.0.0          # 默认即此, 可省
```

- 不启动 anyproxy：浏览器打不开该域名（屏蔽）。
- 启动后：域名经 `127.0.0.1:1080` 下级代理正常访问，日志出现 `blackhole ip 192.0.0.0 -> force remote dns for ...`。

### 例 B：配置 hosts（对 DoH 客户端也生效）

```yaml
# router.yaml
default:
  proxy: socks5://127.0.0.1:1080
hosts:
  - name: blocked-but-proxyable.com
    ip: 192.0.0.0        # DNS 层劫持成哨兵, 效果同系统 hosts, 但 DoH 也拿到哨兵
```

## 7. 边界与排错（FAQ）

- **哨兵配了但域名嗅不到 → 拒绝。** 会出现「`dstIP==192.0.0.0` 但没有域名」的真实情况：浏览器开
  **ECH**（加密 ClientHello）照样从 hosts 拿到 `192.0.0.0` 并连过去，但 SNI 被加密；还有非 TLS/HTTP、
  非 80/443 无首包等。此时确知是黑洞连接，却不知让下级解析哪个域名，又绝不能直连哨兵——只能**拒绝**
  （日志 `blackhole ip ... but no domain to proxy`）。
  - 例外：若哨兵来自**配置 hosts**，DNS 劫持已把 `192.0.0.0→域名` 记进 `cache.SniffName`，即便无 SNI
    也能反查回域名，不触发拒绝。**只有系统 hosts 哨兵 + 无 SNI** 才真正落到拒绝分支。
- **没有可用下级代理 → 直接判失败。** 走到转发阶段仍无可用代理时不会徒劳拨号 `192.0.0.0` 等超时，
  直接失败（日志 `blackhole ip ... requires an upstream proxy`）。等价于「无代理即不可访问」。
- **显式 `deny` 优先。** 若配置规则已把该域名判 `deny`，不被哨兵逻辑覆盖（仍拒绝）。
- **端口范围。** Windows WinDivert 的捕获受过滤器端口约束（默认 80/443）；哨兵主要面向 Web 域名，
  其它端口若未纳入捕获则不生效。
- **DoH/DoT 客户端 + 系统 hosts 哨兵：效果①失效。** DoH 解析不查系统 hosts，拿到真实公网 IP（不是哨兵），
  本地屏蔽这一半就没了。对策：改用**配置 hosts**（例 B）让 DNS 层劫持成哨兵，或屏蔽 DoH 服务器逼其回退
  明文 DNS。详见 [tun-dns-resolution.md](tun-dns-resolution.md)。
- **「日志完全没有捕获记录 / `curl` 几毫秒 refused」** ——几乎一定是把哨兵写成了 `127.0.0.1` 或私网。
  改回 `192.0.0.0`（见第 4 节）。

## 相关文档

- [tun-dns-resolution.md](tun-dns-resolution.md) — TUN 下域名解析优先级全景：系统 hosts / 配置 hosts / DoH
  三条路径、解析阶段 vs 转发阶段、`BypassPrivate` 直连例外。黑洞哨兵是其中「hosts + 代理」难题的解法。
- [routing.md](routing.md) — `target` / `dns` / `proxy` / `ip` 字段语义（哨兵强制的正是 `target=remote`+`dns=remote`）。
- [tun-features.md](tun-features.md) — TUN 特性总览、DNS 劫持与 `blockQUIC`。
- [windows-windivert-redirect.md](windows-windivert-redirect.md) — WinDivert 捕获→NAT→本地代理→恢复目的地的转发链路。
