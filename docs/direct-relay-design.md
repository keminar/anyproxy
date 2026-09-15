# VPS 盲转发中继(TURN 式 direct relay)

> **状态:已实现(第一期)。** 控制面(via/d_relay_open/两腿打洞协调)、数据面(专用 socket
> 盲转发)、鉴权(e2e uuid 挑战-应答绑指纹)均已落地并有单测/全链路测试覆盖。代码落点见 §11。
> 取代了早期"VPS 两腿各终结 TLS、在中间桥接"的思路(见文末"废弃方案")。
>
> 实现与本文的一处措辞出入:C 不靠 A 在流里自报 email,而是用 **B 经打洞消息(DirectPunch.Email)
> 转来的、B 认证过的发起方 email** 去查 receive.allow(A 伪造不了身份),挑战-应答只走 nonce 与
> HMAC 应答两帧。

## 1. 目标

一台公网 VPS 当 A、C 之间的**配置极轻的中继**:VPS **不为每对 A-C 配 `forward`/`direct`/
`receive.allow`**,只需一个"允许中继"总开关;目标 C 由 **A 在请求里指定**。

适用场景:A、C 都在受限 CGNAT 后、彼此直连打不通(见 [direct-punch-order.md](direct-punch-order.md)),
但各自能和公网 VPS 打通。数据经 VPS 中继,**不经**信令服务器 B(B 网络差)。

一次性覆盖 **TCP + UDP**(RDP 的 TCP 主通道 + UDP 图形通道)。文件传输(`-send`/`-recv`)
**不在本设计**,那条已有 `-via relay`(经 B)可用。

## 2. 核心模型:VPS 只做盲转发,QUIC 端到端在 A↔C 之间

关键选择:**QUIC/TLS 连接是端到端 A↔C 的**(A 当 client、C 当 server 出示 C 的自签证书,
A 用指纹固定校验);**VPS 只在传输层转发不透明的 UDP 包**,不终结 TLS、不解 QUIC。

```
   A ─────(QUIC-TLS 端到端, VPS 看不见明文)───── C
   │                                             │
   │  UDP 包                              UDP 包  │
   └───────────▶  VPS 专用中转 socket  ◀──────────┘
              (按源地址在 A↔C 之间盲转发)
   数据不经 B;B 只在建立阶段交换地址/指纹/token
```

**这个模型顺带把 TCP+UDP 的难点消掉了**:VPS 转发的是 A↔C 那条 QUIC 连接的**不透明报文**,
TCP 走它的 stream、UDP 走它的 datagram,全在 A 和 C 之间那条端到端 QUIC 里处理——**和现在的
直连完全一样**。VPS 不区分协议、不做 stream/datagram 桥接、不做 sessionID 映射。所以
"TCP+UDP 一起"是天然成立的。

## 3. 控制面:信令流程

**A 的配置**(给 `client.direct.rules[]` 加 `via`):

```yaml
# A(居民, CGNAT)
websocket:
  client:
    direct:
      punchFirst: true                # A 在 CGNAT 后, 见 direct-punch-order.md
      rules:
        - listen: "both://:13389"     # mstsc 连这里
          email: minggui-home@cloudme.io  # 最终目标 C
          forwardPort: 2224           # 用 C 的 forward[] 里哪条规则
          via: proxy-test@cloudme.io  # 经这个 VPS 中继; 不填=直连 C(现状)
```

**信令复用原则(重要)**:中继本质是**两条普通的"居民→云"打洞腿(A↔VPS、C↔VPS),都打向
VPS 的同一个中继端点 E**,加上 B 居中牵线。所以**现有直连信令几乎原样复用**,只把"要打/要拨
的目标"从"对方"换成"VPS 的中继端点 E"。**只需新增一个消息类型 `d_relay_open`**(B→VPS)。

| 现有信令 | 中继里怎么用 | 改动 |
|---|---|---|
| `d_request`(A→B) | A 加 `via=VPS`;B 见 `via` 非空即进中继模式 | `DirectRequest` 加 `Via string` |
| `d_relay_open`(B→VPS) | **唯一新消息**:让 VPS 开一个专用 socket、问反射器拿公网端点 E、准备被 A/C 打洞 | 新增 `DirectRelayOpen` |
| `d_ready`(VPS→B) | VPS 用它报回中继端点 E(填进 `Candidates`) | 复用,无改动 |
| `d_punch`(B→VPS) ×2 | B 把 A、C 的候选**分两条**转给 VPS,让 VPS 知道往哪儿"打回去"开自己那侧的洞 | 复用其 `PeerAddrs` 形状 |
| `d_offer`(B→A) | 把"A 要拨的端点"填成 **E**、把 **C 的证书指纹**给 A | 复用,无改动 |
| `d_punch`(B→C) | 让 C 打洞到 **E**(`PeerAddrs` 填 E),而非打向 A | 复用,无改动 |
| `d_punching`(nudge) | 两条腿的 nudge 都复用 | 复用,无改动 |

> **为什么 VPS 需要 B 把 A/C 的候选转过去**:居民先打时,它的第一个包会被 VPS 关着的安全组
> 丢掉,VPS **观察不到**居民的源地址;得靠 B 用 `d_punch` 把居民候选告诉 VPS,VPS 才知道往哪
> "打回去"、开出自己这侧的返回通道。这正是 §6 两腿都套 `direct.punchFirst` 的落地方式:居民先
> 打(A、C 各自 `direct.punchFirst: true`),VPS 收到 nudge 后朝居民候选打。

**流程**(建立阶段,信令经 B;数据不经 B):

1. `d_request`(A → B,**带 `via`**):A 要经 `via`(VPS)中继到 C(`email`)的 `forwardPort`,
   附上 A 自己的候选与本次 `token`。B 见 `via` 非空 → 进中继模式。
2. `d_relay_open`(B → VPS):让 VPS 为本次 `token` **新建一个专用 UDP socket**,问反射器探到
   它的公网中继端点 **E**,准备接受来自 A、C 的打洞。VPS 用 `d_ready` 把 E 报回 B。
3. B 用两条 `d_punch` 把候选分别转给 VPS:一条带 A 的候选、一条带 C 的候选(先向 C 发普通
   `d_punch` 拿到 C 的候选与指纹)。VPS 据此朝 A、C 两侧各打洞(收到 nudge 后)。
4. `d_offer`(B → A):把要拨的端点填成 **E**,附 **C 的证书指纹**。同时向 C 发 `d_punch`,其
   `PeerAddrs` 填 **E**,让 C 打洞到 E(而非打向 A)。
5. **A、C 各自 punch 到 E**(都是"居民→云",各自 `direct.punchFirst`:居民先打、VPS 收 nudge 后
   打;`d_punching` 两腿复用)。VPS 从两个来源地址各**观察到** A、C 的公网地址,绑定成一对。
   - **两条腿都通才算通**;任一腿打不到 VPS,整条中继失败(见失败语义)。
6. 两边都通后,**A 发起 QUIC 拨号**:目的地址填 E(中继端点),TLS 期望 C 的指纹。VPS 把包
   转给 C,C 的监听收到(来源是 VPS 中继口)并 accept,QUIC 握手在 **A↔C 端到端**完成。
7. A 在这条 e2e QUIC 流里发自己的 `email`(标签),与 C 做一次 **uuid 挑战-应答**(见鉴权,
   uuid 全程不上线);C 验过后放行。之后 TCP 流 / UDP 数据报都在这条 e2e QUIC 里跑,VPS 一路
   盲转发。

**VPS 的配置**(去掉 per-pair 的 forward/direct):

```yaml
# VPS(公网)
websocket:
  client:
    direct:
      accept: true       # 仍要: 这样居民能 punch 连上来
      relay: true         # 新增: 允许作为中继; 默认对 B 内所有已鉴权订阅方开放
      # relayAllow:       # 可选: 限制哪些源 email 可用本机中继(不填=全放开)
```

**C 的配置**(基本不变;`forward` 白名单仍是关口):

```yaml
# C(居民, CGNAT)
websocket:
  client:
    direct:
      punchFirst: true
      accept: true
    forward:
      - port: 2224
        target: 192.168.1.10:3389
    receive:                         # C 保留一份"允许哪些 A"的名单(见鉴权)
      allow:
        - email: office@cloudme.io
          uuid: <A 的 uuid>
```

## 4. 鉴权:关口在 C,VPS 全程盲

- **A 确认对面是真 C(证书指纹,非 uuid)**:A↔C 的 **e2e QUIC-TLS** 用 C 的自签证书,A 用经 B
  下发的指纹**固定校验**。哪怕包是从 VPS 转来的,A 靠证书就能确认对面是 C——**与地址无关**,VPS
  没有 C 的私钥、冒充不了 C。数据也由这条 TLS 加密,VPS 没密钥、只见密文。
- **C 确认对面是真 A(uuid 挑战-应答,单向,uuid 全程不上线)**:整个中继里 uuid **只用于
  "C 验 A"这一个方向**("A 验 C"上面已由证书指纹负责)。A、C 本地都有 A 的 uuid(A 有自己的,
  C 的 `receive.allow` 里有 A 的——**复用现有 `receive.allow`,不新开名单**),所以不必把 uuid
  发过去,用挑战-应答证明"我知道 uuid"即可:
  1. A 在 e2e QUIC 流里发自己的 `email`(**标签、非机密**,发了无所谓);
  2. C 按 email 去 `receive.allow` 查到期望的 uuid,发一个随机 `nonce`;
  3. A 回 `HMAC(uuid, nonce || C 的证书指纹)`,C 用查到的 uuid 验一遍。nonce 每次新的防重放;
     **把 C 的证书指纹绑进 HMAC 是为防中继层重放**——VPS 是不可信中间人,若不绑指纹,一段
     被录下的挑战-应答理论上可被 VPS 重放到"另一条它冒名顶替的连接"上;绑上 C 的指纹后,
     应答只对"对面确是持有该证书私钥的 C"这条 e2e TLS 有效,VPS 换条连接就对不上。
  - 这与现有 `-via relay` 的做法一致(uuid 当密钥材料、靠"用得对"证明身份,**不明发**)。
  - 对比:现有**直连**文件传输是把 uuid 塞进 e2e 流里逐字比对(明发在 TLS 内)——对直连可接受
    (对端就是 C),但中继里 VPS 是不可信中间人,更该用挑战-应答,连 TLS 里都不放 uuid:哪怕
    C 的证书私钥泄露,uuid 也不跟着漏。
- **不需要单独的 broker token**:C 的 relay 监听口只有"经 B 建好绑定 + A 的包经 VPS 转过来"
  才够得着(随机扫描到不了),再加 C 的 `forward` 白名单把关端口,已经把未授权连接挡在外面;
  uuid 挑战-应答独扛身份鉴权即可。要保留 token 当"更早拒非法连接"的廉价门也行——但注意
  **token 是一次性能力值、本就设计来传输**(B 下发),传它不泄露长期秘密,和 uuid 性质不同。
- **防注入**:VPS 的专用 socket **只在"A 的地址 ↔ C 的地址"之间对转**,其它来源地址的包直接
  丢;分配绑定必须经 B(B 已鉴权发起方)。

**跨网络传输的只有非长期秘密**:`email`(标签)、`nonce`(随机)、C 的一次性证书指纹(经 B)。
**长期秘密 uuid 绝不上线**;数据由 e2e QUIC-TLS 加密。

**关键结论:安全性不依赖 `direct.encrypt`。** 鉴权(uuid 挑战-应答)和数据都在 A↔C 的 e2e
QUIC-TLS 里/之上,与打洞包加密无关。`direct.encrypt` **退化为纯可选**:只给"居民↔VPS"两条腿的
打洞包加密、抹掉明文特征防运营商 DPI 丢包(是"能不能打通"的可靠性问题,不是"会不会泄密")。
不开也不泄任何秘密——明文打洞包里本就只有 `verb+nonce`。

> 与早期步骤 2 的区别:鉴权**不**放在"uuid 加密的打洞包"上(那样会让鉴权依赖 direct.encrypt、
> 且相当于用 uuid 直接加解密打洞包),而是放在建好 e2e QUIC 之后的**流内挑战-应答**。打洞包在
> 本模型里只负责开洞。

## 5. 数据面:专用 UDP socket 盲转发

- VPS 每对 A↔C 用**一个专用 UDP socket**(不经 quic-go,纯 `ReadFrom/WriteTo`)。
- 绑定:socket 上先后出现 A、C 两个来源地址,记下后即"A→C、C→A"对转;只认这两个地址。
- **TCP/UDP 无区别**:转发的是不透明字节,A↔C 的 QUIC 自己区分 stream/datagram。
- **生命周期简单**:空闲 **30 分钟无数据**就关掉这个 socket + 它的转发 goroutine(沿用
  `directUDPIdle`)。因为 A↔C 的 QUIC 有 20s keepalive,连接活着时 socket 每 20s 有包过、
  永不误判空闲;只有 QUIC 真死了才会 30 分钟后回收。活的留着、死的自清,不用复杂回收逻辑。
- **专用 socket 的额外好处**:天然隔离,一对中继的关闭不影响别对;地址绑定也天然防抢用。

## 6. 复用打洞顺序

中继有两条腿,都是"居民→云",各自套用 [direct-punch-order.md](direct-punch-order.md):

- `A↔VPS`:A(居民)先打、VPS 停下等 nudge —— A 侧 `direct.punchFirst: true`;
- `C↔VPS`:C(居民)先打、VPS 停下等 nudge —— C 侧 `direct.punchFirst: true`。

B 在第 5 步协调两边的 nudge。两条腿直接复用现有 `direct.punchFirst` 机制,不需额外处理。

## 7. 失败语义

两条腿(A↔VPS、C↔VPS)必须**都**打通才算成功;任一腿失败,整条中继失败,按直连一贯约定
**直接失败、不再兜底**(中继本身就是打洞不通时的替代,它自己没有下一级)。失败原因尽量经
`METHOD_CLOSE` 回传给 A,便于区分"连不上 VPS 的哪条腿"还是"C 的 forward/uuid 拒绝"。

## 8. 分期

因为 VPS 是不透明转发、TCP/UDP 无区别,数据面**一次做完**(专用 socket 盲转发)。工作量主要
在**控制面**(新信令 + 两腿 punch 协调 + QUIC 穿中继)。建议:

- **第一期**:整套控制面 + 专用 socket 盲转发 + 鉴权(uuid 挑战-应答,e2e)。跑通 A→VPS→C 的
  RDP(TCP+UDP 一并),VPS 无 per-pair 配置。
- 无需为 TCP/UDP 分期。

## 9. 已定的决定

- **鉴权方向**:单向——**C 用 uuid 挑战-应答验 A**;A 用**证书指纹**验 C(非 uuid)。两头都被
  认证,VPS 冒充不了任何一方。
- **C 侧名单**:**复用现有 `receive.allow`**(email+uuid),不新开 `relayAllow`(把它的注释从
  "仅文件传输用"改成"文件传输 + 中继鉴权用")。
- **direct.relay 默认**:开了即对"B 内所有已鉴权订阅方"开放;`direct.relayAllow` 可选收紧。
- **中继目标粒度**:每条 A↔VPS 连接一个目标 C。
- **命名**:A 侧 `via`、VPS 侧 `direct.relay`。
- **不需要单独 broker token**:uuid 挑战-应答独扛(见 §4);可选保留当廉价早拒门。
- **VPS 端点 vs C 地址**:A 拨的是 **VPS 的中继端点(`VPS_ip:专用端口`)**,A、C 都 punch 到
  这同一个端点、VPS 按来源地址区分;A **从不用 C 的真实 ip:port**(够不着,也不需要——"对面
  是不是 C"由证书指纹保证,与地址无关)。
- **VPS 中继端点的公网地址怎么来**:VPS 那个专用 socket 本地绑的地址 ≠ 外面看到的地址(如
  腾讯云本地 `10.x`、公网 `49.x`),所以 VPS 不能直接报本地地址。**复用现有的反射器探测**——
  VPS 让这个 socket 也问一次反射器("我在你眼里是什么 `ip:port`"),把探到的公网地址经 B 报给
  A 和 C(和居民机器、以及 VPS 现在做普通直连时学自己公网端点的是同一套 `gatherCandidates`)。
  这样不论 VPS 是纯公网、1:1 NAT(端口保留)、还是端口会变的 NAT,都拿到正确端点。
  - **例外: 出口逐流随机的对称 NAT 网关**。反射器探到的出口 E_ref 是 `VPS->反射器` 那条流的
    映射; 若 VPS 挂在对称型 NAT 网关后(去反射器、去 A、去 C 各拿到不同外网 IP:port), A 往
    E_ref 发根本到不了 VPS 的入向映射, 中继就废(和对称 NAT 打不了洞同理)。此时反射器探测这条
    路本身失效, 需要**静态入站**兜底(见下)。
- **静态公网端点(direct.relayPublic)**: 配了它就**跳过反射器**, 直接用配置端点当 E, 并把中继
  socket **绑到端点里的固定端口**。用于上面的对称 NAT 网关场景: 改配一条固定 DNAT 入站规则
  (公网 `IP:端口` -> VPS 同一 UDP 端口), 入站恒开、与出口随不随机无关。因为固定端口一个 socket
  只能有一个, 所以**配几个不同端口就最多几对并发中继**(open 时挑空闲端口绑; 都占满则该次失败)。
  假定 DNAT 端口保留; 直接公网 IP 无 NAT 时同样适用(放行端口即可)。最省事仍是给 VPS 一个真正
  的 1:1 公网 IP, 那样默认的反射器探测就够。
- **信令最大化复用现有直连信令**(见 §3 表):中继 = 两条"居民→云"打洞腿(都打向 VPS 中继端点
  E)+ B 牵线。复用 `d_request`(加 `Via` 字段)/`d_ready`/`d_punch`/`d_offer`/`d_punching`,
  **只新增 `d_relay_open`(B→VPS)一个消息**让 VPS 开专用 socket、探 E、准备被打洞。B 用两条
  `d_punch` 把 A、C 的候选转给 VPS(VPS 被安全组挡着观察不到居民源地址,得靠 B 告知)。
- **uuid 挑战-应答绑证书指纹防中继层重放**:`HMAC(uuid, nonce || C 的证书指纹)`。VPS 是不可信
  中间人,绑上指纹后应答只对"对面确是持有该证书私钥的 C"有效,VPS 无法把它重放到别的连接上。
  nonce 每次新、防常规重放。可复用 [nat/direct_crypto.go](../nat/direct_crypto.go) 的派生手法。

## 10. 待定(实现时定)

- (信令与鉴权构造已在 §3、§4、§9 定稿;此处暂无未决项,实现时如遇细节再补。)

## 11. 相关代码(实现落点)

- 信令:[nat/direct_msg.go](../nat/direct_msg.go)、[nat/direct_broker.go](../nat/direct_broker.go)
  (B 侧新的中继协调)、[nat/direct.go](../nat/direct.go)(客户端信令分发)。
- A 侧发起:[nat/direct_entry.go](../nat/direct_entry.go)(`via` 非空 → 走中继建立 + e2e 拨号)。
- 命令行:`-send`/`-recv` 的 `-via` 除 `direct`/`relay` 两个保留关键字外, 填一台 VPS 的
  email 就等价于给这次一次性传输的 `conf.ClientDirect.Via` 赋值(见 `resolveVia`), 不需要
  写进配置文件, 见 [nat/file_send.go](../nat/file_send.go)、[nat/file_recv.go](../nat/file_recv.go)。
- VPS 侧中继:新代码(专用 UDP socket 盲转发 + 绑定 + 空闲回收);`direct.relay` 开关。
- C 侧接受:[nat/direct_accept.go](../nat/direct_accept.go)(punch 到中继端点 + 监听接受 +
  uuid 挑战-应答校验)。
- 打洞顺序:复用 [direct-punch-order.md](direct-punch-order.md) 的 `direct.punchFirst`。
- 配置:[utils/conf/router.go](../utils/conf/router.go)(`ClientDirect.Via`、`DirectSettings.Relay`、
  可选 `DirectSettings.RelayAllow`、`DirectSettings.RelayPublic`, 均挂在 `WsClient.Direct` 下)。

## 附:废弃方案(VPS 两腿桥接)

早期设想:VPS 各自终结 `A↔VPS` 和 `VPS↔C` 两条 QUIC-TLS,在中间桥接 stream/datagram。缺点:
VPS 看得到明文、需要为 UDP 做 sessionID 映射与双向桥接(复杂),且 C 只能认证 VPS 不认 A。
本设计的盲转发模型全面更优(VPS 盲、TCP/UDP 统一、C 直接认证 A),故废弃两腿桥接。
