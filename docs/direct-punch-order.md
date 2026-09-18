# 直连打洞的顺序问题：CGNAT 侧必须先发第一个包

> 一句话结论：跨"运营商级 CGNAT 家宽 ↔ 公网云主机"打洞时，**居民/CGNAT 那一侧必须在
> 收到对端任何包之前，先发出自己的第一个打洞包**。谁先打决定成败，与"打得紧不紧、连
> 不连续对轰"无关。顺序错了不仅连不上，即便勉强连上也会严重丢包。

这是排查一次真实的"直连打不通"问题时确认的结论，过程绕了很多弯，值得单独记下来——因为
它反直觉：两边 NAT 类型都正常（都是 cone/EIM）、包也都发出去了、抓包能看到出向流量，却
就是连不通，而唯一的变量是**谁先发的第一个包**。

## 现象

拓扑：居民宽带 A（示例地址 `192.0.2.10`）、居民宽带 C（示例地址 `198.51.100.20`）、
公网云主机 VPS（示例地址 `203.0.113.30`，1:1 NAT + 有状态安全组）。

- **VPS 主动拨 A / C**（用 VPS 跑 `-send`/`-recv`）→ **一定成功**。
- **A / C 主动拨 VPS**（用 A/C 跑 `-send`/`-recv`）→ **一定失败**。
- 两台不同运营商的居民机器，表现完全一致。

失败时的典型日志（A 主动拨 VPS）：

```
nat direct: path selection for ...: punch all failed (no candidate answered: ...: no answer),
  falling back to a quic dial race across all candidates
nat direct: quic dial ...: timeout: no recent network activity
```

抓包会看到：A 的包从物理网卡正常发出去了，但 VPS 一个都收不到；反过来 VPS 打给 A 的包，
A 也一个都收不到。**双向都到不了对面**。

## 规律与机制

**规律**：居民 / CGNAT 那一侧，必须在收到对端任何包之前，先发出自己的第一个打洞包。

**机制**：居民宽带的 CGNAT 有一个特性——**如果它在自己发出第一个包之前，先收到了对端
的包，它对这个目的地的映射就被"毒化"了**：之后它再往对端发包时，用的外网端口不再是它
之前通告出去（反射器观测到）的那个。结果两个方向全对不上：

- 它发出的包，从一个对端没预期的源端口冒出来 → 对端（尤其云主机的有状态安全组，只按
  它先前打洞开的洞放行）把它丢掉；
- 对端回的包，打到它当初通告的那个端口，而它的 CGNAT 已经不再把那个端口映射到本机 →
  也被丢掉。

**这种毒化是这一整轮持久的**：一旦发生，靠"持续打、密集对轰"救不回来。公网/云主机那
一侧没有这个毛病——它先收到对端的包也无所谓，安全组照常按自己打出去的洞放行返回。

一个有力的旁证是**丢包率**：顺序错了即使因为某些时序凑巧勉强连上，也会严重丢包（实测
37%，因为毒化的映射让一部分包走错端口）；顺序对了，同一条链路 **0% 丢包**。

### 精确一点：废的是"关联"，不是"端口"

容易误解成"这个端口被对端先打就报废了"。更准确的说法是：

- **端口本身没废**：这个 socket / 外网端口对 B、对反射器、对其它任何目的地都照常好用。
  被影响的**只是"到对端这一个特定目的地"**这条流。
- **触发单位是 `(本机这个 socket ↔ 对端这个目的地)` 这一对，触发条件是"收在发之前"**：
  A 的 CGNAT 在"A 先主动发"时是端口无关的（EIM，所以对 B、对反射器都用同一个端口，A
  才把它通告出去）；但如果 A 在**自己还没往对端发过包之前先收到了对端的包**，CGNAT 对
  "对端这个目的地"就改用另一套（端口相关）的映射，用的外网端口不再是通告出去的那个。
- **不会越试越少**：换一次新连接（新 socket、新端口）就是全新的一次机会——只要这次
  A 先发，就好使。失败一次不会污染下一次的新 socket，不存在"端口被用废、越来越少"。

**一个诚实的边界**：上面"A→对端用了不同外网端口"是**从行为推断**出的最合理模型（顺序错
就双向全灭 + 高丢包、顺序对就 0 丢包），但**没能直接抓到那个不同的外网端口**——A 本机只
看得到内网端口，而对端在顺序错时根本没收到包、也读不到。所以当"最佳解释模型"看，别当
"抓包实证的铁律"。也正因为它是"收在发之前"才触发，`nat-punch` 的双反射器 EIM 测试**测不
出来**：那个测试里 A 都是先主动发给两个反射器的，从没"先收后发"，自然显示 EIM——真正的
坑只在"先收到对端包"时才冒头。

## 实测证据

**裸工具 `examples/nat-punch`**（把 anyproxy 整个排除掉，纯测两台机器能不能互发 UDP）：

- **A 先回车（先打）→ 通**；**VPS 先回车（先打）→ 不通**。
- 这直接排除了"紧不紧、连续对轰"的因素——`nat-punch` 两种顺序都是持续对轰，唯一差别
  就是谁先按的回车（谁先发第一个包）。

**anyproxy 验证**（见下文"怎么用"）：让接受方推迟打洞、居民侧先打，A 主动拨 VPS **立刻
连上**（`punch 2.7s`）、19.8MB 传完、**丢包 0%**。假设坐实——这就是下面 `direct.punchFirst`
配置的由来。

## 为什么 anyproxy 现状会踩中它

现在的直连信令时序（见 [nat/direct_msg.go](../nat/direct_msg.go)）：

```
A --d_request--> B --d_punch--> C   ← C 一收到 d_punch 就 punchOnly, 先打洞了
C --d_ready-->   B --d_offer--> A   ← A 这才拿到 C 的地址, 开始打洞
```

**接受方（C）总是先打洞**——它在收到 `d_punch` 时就 `punchOnly`，而这**早于**发起方（A）
拿到 `d_offer`、开始打洞。所以谁当接受方、谁就先打：

| 方向 | 谁是接受方（先打洞） | 居民侧是先发还是后收 | 结果 |
|---|---|---|---|
| VPS → 居民 | 居民 | 居民先发 → 映射干净 | **通** |
| 居民 → VPS | VPS | VPS 先发、居民后收 → 居民被毒化 | **灭** |

这就完整解释了"VPS 当拨号方一定成、当被拨方一定败"，也解释了为什么把两侧都改成"持续
打洞"（接受方 `punchOnly` 持续打、发起方拨号期间 `keepPunching`）**仍救不了**——问题在
**顺序**，不在持续性。

## 怎么用：`direct.punchFirst`

原则：**让居民 / CGNAT 侧先打洞。** 落地成一个**按机器**的配置开关
`websocket.client.direct.punchFirst`：

```yaml
# 家宽 / CGNAT 那台(A、C)——它主动发起直连时必须先打
websocket:
  client:
    direct:
      punchFirst: true
# 公网 / 云主机那台(VPS)——保持默认(不设), 它当接受方时会读发起方的这个声明并推迟自己的打洞
```

- **设 `true` 的一侧**：本机作为发起方去连对端时，在 `d_request` 里带上 `punchFirst`；
  对端（接受方）收到 `d_punch` 后**先不打、把打洞停下**，等本机开打后经 B 转来的
  `d_punching` nudge 再打。`d_ready` 照常立即回，好让本机（居民侧）先发出第一个包。
- **按机器设，不是按每条 `direct.rules[]` 规则**：因为"本机在不在 CGNAT 后"是这台机器的属性；
  对 `direct.rules[]` 端口转发与 `-send`/`-recv` 文件传输**同时生效**。
- **只在 CGNAT 侧作为发起方时需要**：家宽机器设、公网/云主机别设。用它跑之前失败的
  方向（家宽 → 云主机）应当立刻连上（实测 `punch 2.7s`、丢包 0%）。

**为什么按机器、且能自动适配链路**：同一条 `居民 A → VPS → 居民 C` 链里，两跳需要的顺序
正好相反——

| 跳 | 发起方 | 接受方 | 谁该先打 | 靠什么达成 |
|---|---|---|---|---|
| A → VPS | A（居民，设了 `direct.punchFirst`）| VPS（云）| A 先打 | A 的 `punchFirst` 让 VPS 停下等 nudge |
| VPS → C | VPS（云，没设）| C（居民）| C 先打 | 默认就是"接受方先打"，C 正好先打 |

所以只要**给每台家宽机器都设 `direct.punchFirst: true`、公网机器不设**，两跳各自都对了，
不用去管每一跳的方向。

**局限**：两端都是 CGNAT 的直连（比如 A 直连 C，不经 VPS）这个开关覆盖不了——那时无论谁
先打，另一侧都会"先收后发"被毒化。好在这种两端 CGNAT 的直连本就极难打通，实践中走中转
（经 VPS 或 relay）。

### 顺序怎么保证：`d_punching` nudge（信令控制）+ 固定延迟兜底

难点是：接受方在收到 `d_punch` 时就想打，但那时发起方还没拿到 offer、还没开始打——不能让
接受方先打。所以：

1. 接受方收到带 `punchFirst` 的 `d_punch` 后**先不打**，把这次打洞按 `token` 停在
   `pendingPunch` 里，`d_ready` 照常立即回；
2. 发起方拿到 offer、**一开打**就发一条 `d_punching` nudge（`A -> B -> C`，B 按 email 路由，
   C 按 `token` 对上停着的那次打洞）；
3. 接受方收到 nudge 才打 `punchOnly`。因为 nudge 要经 B 转一小段、而发起方紧接着立刻开打，
   所以**发起方必先发出第一个包**，映射不被毒化。

这是**确定性**的，不靠猜 B 的延迟。`directPunchFirstDelay`（`nat/direct.go` 里的常量，5s，
**不是配置项**）降级成**兜底**：万一 nudge 丢了（B 抖动、发起方没发），接受方到点也打，退回
"固定延迟"的老行为——不会永久卡住。正常走 nudge 时它几乎不触发；真遇到 B 极卡、nudge 常丢
的环境要加大它，只能改这个常量重新编译（有意不做成配置项：它是极少触发的安全网，不值得
多一个旋钮）。

> 早期验证用过的临时环境变量 `ANYPROXY_DIRECT_PUNCH_DELAY`（接受方无条件固定延迟）已被上面
> 这套"配置 + nudge + 兜底"取代、删除。

### 别混淆两个时间量：打多久 vs 何时开打

排查时容易把这两个量搞混，其实一个是"时长"、一个是"时机"：

- **打多久（时长）= `directPunchCount × directPunchGap`**：接受方 `punchOnly` 对每个候选连发
  `directPunchCount`（默认 6）个包、间隔 `directPunchGap`（默认 150ms），即 **~900ms 的短脉冲**
  就停。**不需要更久**——打洞在对端 NAT/安全组上开出的是**有状态映射**，一旦建立能存活数十秒
  乃至更久；这 900ms 只负责把洞**开出来**，之后发起方的 QUIC Initial 一进来、握手一开始，QUIC
  报文自己就不断刷新这条流，无需持续补打。
- **何时开打（时机）= 由 `direct.punchFirst` + nudge 决定**：接受方是在**收到 nudge**（或
  `directPunchFirstDelay` 兜底到点）时**才**开始那 900ms 脉冲，而不是一收到 `d_punch` 就打。
  这样才保证发起方（受限 CGNAT 侧）先发出第一个包。

一个常见误会：早期用 `ANYPROXY_DIRECT_PUNCH_DELAY=2s` 验证成功时看到 `punch 2.739s`，那个
"2s 多"是"信令往返 + 接受方**延迟 2s 才开打**"堆出来的——是**时机**，不是脉冲**时长**。当时
接受方的第一个 punch 一到，连接就几乎立刻建立，900ms 脉冲的持续时长从不是瓶颈。换成 nudge
后，接受方比那 2s 固定延迟**更早**开打（nudge 一到就打），所以现在通常更快。

## 排查清单（遇到"直连打不通"时）

1. **先确认不是代理劫持**：居民机器若挂了全局/分应用代理，发往对端的 UDP 可能被从虚拟
   网卡劫走，根本没走物理网卡。抓物理网卡 `host <对端IP>` 确认包真出去了。
2. **确认 NAT 类型**：用 `nat-punch -mode=punch -reflect=<r1>,<r2>`（两个不同 IP 的反射器）
   看是不是 cone/EIM。都是 cone 却打不通，就往"顺序"上想。
3. **两边对齐抓包**：一边发、两边抓，看包到没到对面。两边都"发了但对面没收到" = 典型的
   顺序毒化（不是路径封锁）。
4. **换顺序验证**：让另一侧先发第一个包（`nat-punch` 手动控制回车顺序，或 anyproxy 在
   CGNAT 侧设 `direct.punchFirst: true`）。一换就通 = 实锤顺序问题。
5. **注意丢包率**：连上但高丢包，往往也是映射没对齐的征兆，同样指向顺序。

## 相关代码

- [nat/direct_msg.go](../nat/direct_msg.go)：直连信令时序与结构——`d_request`/`d_punch`/
  `d_ready`/`d_offer`，以及本方案新增的 `d_punching`（nudge，`DirectPunching`）、
  `DirectRequest.PunchFirst`/`DirectPunch.PunchFirst`。
- [nat/direct_entry.go](../nat/direct_entry.go)：`ensureSession`（发起方拨号；设了
  `direct.punchFirst` 时先发 `d_punching` nudge 再开打）、`requestPeer`（把 `punchFirst` 带进
  `d_request`）、`raceQUICDial`。
- [nat/direct_broker.go](../nat/direct_broker.go)：`onPunching`（B 把 nudge 按 email 转给 C）。
- [nat/direct_accept.go](../nat/direct_accept.go)：`onPunch`（接受方入口，`p.PunchFirst` 时
  改走 `parkPunch`）、`parkPunch`（停下等 nudge / 兜底超时）、`onPunching`（收到 nudge 触发打洞）。
- [nat/direct_reflect.go](../nat/direct_reflect.go)：`punchOnly`（接受方打洞，一次几包即可）、反射器。
- [nat/direct.go](../nat/direct.go)：`directPunchFirstDelay`（nudge 丢失时的兜底延迟）、
  `directPeer.pendingPunch`（停着等 nudge 的打洞表）。
- [utils/conf/router.go](../utils/conf/router.go)：`DirectSettings.PunchFirst`（挂在
  `WsClient.Direct` 下）配置字段。
- [examples/nat-punch](../examples/nat-punch)：独立的裸 UDP 打洞测试工具。
- 路径 C（QUIC 直连）的整体说明见 [websocket.md](websocket.md)。
