# websocket 内网穿透

anyproxy 内置一套基于 websocket 长连接的内网穿透：**内网侧主动回连公网侧**，之后公网侧把流量经 websocket 送进内网。适合内网在 NAT 后、没有公网 IP 的场景（远程访问家里/公司的机器、暴露内网服务）。

代码在 [nat/](../nat/) 包；配置在 `router.yaml` 的 `websocket` 段（[utils/conf/router.go](../utils/conf/router.go)）。

## 两个角色

| 角色 | 怎么判定 | 职责 |
|------|----------|------|
| **服务端**（公网侧） | 配了 `websocket.server.listen`（或 `-ws-listen`） | 起 websocket 监听 `/ws`，等订阅端接入；对外接收流量并经 ws 转发 |
| **订阅端**（内网侧） | 配了 `websocket.client.connect` / `websocket.clients[]`（无命令行等价，只能配置文件） | 主动回连服务端、鉴权、订阅；收到服务端来的连接后 dial 内网目标；可同时回连多台服务端，见下文「同时订阅多台 server」 |

一个进程可同时是普通代理 + 服务端/订阅端（同进程复用监听端口）。方向永远是**订阅端 → 服务端**发起长连接。

> **纯穿透不想起代理监听**：把 `listen` 设为 `off`（或 `-l off`），进程只跑 websocket 后台、不绑本机代理端口。适用于只做**裸 TCP 转发**的场景；**HTTP 头订阅路径依赖本机代理端口，关闭后失效**。见文末「配置字段」。

## 两条转发路径

服务端把每条转发标了类型（`nat/message.go` 的 `ConnHTTP` / `ConnTCP`），两路的连接 ID 各自从 1 采番，互不串扰。

### 路径 A：HTTP 头订阅转发（`ConnHTTP`，旧路径）

按 **HTTP 请求头**把公网侧的请求送进某个订阅端，再由订阅端的**本机代理**向内网发起。

```
公网 client ──HTTP 请求(带 Anyproxy-Action: websocket + 命中订阅的头)──▶ 服务端 :3000 代理入口
                                                                        │ 按头部匹配订阅端
                                                                        ▼ (websocket 长连接)
                                            订阅端 ──dial 本机代理 127.0.0.1:ListenPort──▶ 内网目标
```

- 触发：请求经服务端的**代理监听端口**进来，带头部 `Anyproxy-Action: websocket`（`proto/http.go` 的 `response()`）。`CONNECT` 请求不支持这条路径。
- 选订阅端：服务端用请求头去匹配各订阅端的 `subscribe`（`nat/client_hub.go` 的 `GetClient`，`header.Get(key) == val` 命中即选中）。匹配不到就回退普通转发。
- 落地：订阅端收到后 dial **自己的本地代理**（`127.0.0.1:ListenPort`，`nat/handler.go` 的 `dialProxy`），把原始 HTTP 请求原样重放，由订阅端的 router 规则决定后续（直连/再代理）。
- 适合：把「带特定标记的公网请求」定向送进某内网环境走它的代理。

### 路径 B：端口转发（`ConnTCP`，新路径）

在服务端开一个**裸入口端口**，整条 TCP 连接经 ws 桥接到订阅端，订阅端 dial 一个**写死的内网目标**。就是反向隧道，即内网穿透。同一个端口还可以再开一条并行的 UDP 通道，见下。

```
任意 client ──TCP──▶ 服务端 :2222 (裸TCP监听)
                        │ 按 email 选订阅端
                        ▼ (websocket 长连接)
     订阅端 ──dial 写死的 target 127.0.0.1:22──▶ 内网 sshd
```

- 服务端：`websocket.server.forward[].listen` 每条起一个裸 TCP 监听（`protocol` 含 udp 时同端口再起一个 UDP 中继）（`nat/forward.go` 的 `StartForward`/`listenForward`），每个进来的连接按该规则的 `email` 找订阅端（`GetClientByEmail`）桥接。
- 订阅端：`websocket.client.forward[].port → target` 建映射（`nat/forward.go` 的 `buildForward`，每台 server 连接各自一份）。收到服务端「入口端口 Port」来的连接时，dial 对应 `target`；**Port 未在本地映射则拒绝**（`nat/forward.go` 的 `dialForCreate`）——天然白名单。
- 适合：暴露内网 Web/DB 等任意 TCP 服务（如远程 SSH、内网 Web）。

#### 路径 B 的第二条通道：UDP 中继（`protocol: udp | both`）

上面那条通道只有 TCP。给规则加 `protocol: both`，服务端会在**同一个 host:port** 上再起一个 UDP 监听，UDP 走自己的一条路，跟 TCP 那条互不相干：

```
mstsc ──TCP 3389──▶ B:2222 ──websocket(TCP)──▶ C ──▶ 127.0.0.1:3389
mstsc ──UDP 3389──▶ B:2222 ═══════UDP════════▶ C ──▶ 127.0.0.1:3389
```

```yaml
websocket:
  server:
    forward:
      - listen: ":3389"
        email: c@example.com
        protocol: both      # tcp(默认) / udp / both
```

订阅端不用改：落地目标仍查同一张 `client.forward[port] → target` 白名单，未映射的端口一样拒绝。

**为什么必须另开一条，而不是把 UDP 塞进 websocket**：websocket 跑在 TCP 上，把数据报塞进去等于给每个包重新套上重传和保序——丢一个包，后面已经到达的帧全得排队等它。这正是 RDP 的 UDP 通道特意要绕开的东西，那样做只会比纯 TCP 更卡。这里三段全程都是 UDP，丢包就是丢包，不会被放大成停顿。

**为什么不用打洞**：两头都是 NAT 内侧主动发起的，B 是公网。`mstsc → B` 是 A 主动发；`C → B` 的上行是 C 主动发，出去时就在自己 NAT 上开了映射，B 顺着回发即可。映射会老化，所以 C 每 20 秒发一个保活包。

**上行是请求驱动的**（和路径 C 一个思路）：C 平时不占 UDP 端口、不发保活包。B 收到第一个客户端数据报时才通过 websocket 发 `u_open` 让 C 建上行，等待期间暂存最多 16 个数据报，C 注册成功后补发。代价是第一个包要等一个来回——RDP 的 UDP 通道是在 TCP 主通道之后才协商的，本来就有富余，且它自己会重试。所有会话空闲 30 分钟后，C 撤掉上行 socket，B 忘掉端点。

**B↔C 那一段带 8 字节包头**（`magic | kind | session(4) | port(2)`，见 `nat/relay_udp.go`）。会话号让 C 知道回包该送回哪个客户端——所以内网目标看到的每个客户端是**各自独立的源端口**，不会被并成一个。端口号每个包都带，不只带在首包：UDP 会乱序，绑在首包上一旦乱序就查不到目标。发给客户端的包是**裸**数据报，包头只存在于 B↔C 之间。

**上行冒充的防护**：C 注册时要出示 B 通过 websocket 下发的一次性 token；注册之后，只有来自那个确切端点的包才当上行处理。光看包头魔数是不够的——那样任何人发个 `0xA5` 开头的包就能往客户端方向注入数据。

**两个已知限制**：

- **B↔C 那段每包多 8 字节**。RDP-UDP 自己探的是到 B 的路径 MTU，不知道后面还有一跳要加头。实际负载在 1200 上下、离 1500 还远，所以基本碰不到；真跑满 MTU 的应用要留意。
- **中继本身不加密**。`mstsc → B` 这段是客户端直接发的裸数据报，本来就没法包一层，所以只给 B↔C 加密并不能让整条路径变私密。RDP 的 UDP 通道自带 DTLS，不受影响；但换成别的明文 UDP 协议就要自己考虑。真要端到端保密，用路径 C 的直连（那条是 QUIC，全程加密）。

### 路径 C：QUIC 直连（`direct`，数据不经服务端）

前两条路径的数据都经服务端转发，服务端要吃掉全部流量。这条路径把**入口挪到订阅端自己机器上**，两个订阅端之间用 QUIC 直连，服务端只交换候选地址、不碰任何数据字节。

```
任意 client ──TCP──▶ A(订阅端) :13389 (本机入口监听)
                        │ ①经 ws 问服务端要 C 的端点, 并让 C 朝我打洞
                     服务端 B (只转信令)
                        │ ②
                        ▼
     A ══QUIC 直连(v4/v6/端口映射, 择优)══▶ C(订阅端) ──dial client.forward[port]──▶ 内网 RDP
```

代码在 [nat/direct.go](../nat/direct.go)、[direct_entry.go](../nat/direct_entry.go)（A 侧）、[direct_accept.go](../nat/direct_accept.go)（C 侧）、[direct_broker.go](../nat/direct_broker.go)（服务端信令）、[direct_reflect.go](../nat/direct_reflect.go)（UDP 反射器）。

**为什么必须有 UDP 反射器**：websocket 是 TCP，服务端从这条连接上看到的是订阅端 **TCP socket** 的地址；而 QUIC 走另一个 UDP socket。一台机器常同时持有多个地址（IPv6 的稳定地址 + 会轮换的隐私临时地址 RFC 4941，或多张网卡），内核按 RFC 6724 **按目的地分别选源**，两者不保证相同；外网端口同理由沿途 NAT 决定。所以端点必须由订阅端**用 QUIC 那个 socket 本身**去问反射器要。反射器自动绑在与 `websocket.server.listen` 相同的端口号上（TCP/UDP 互不冲突，且绑双栈两族都答），订阅端从 `connect` 地址推导，无需额外配置。

**为什么还要打洞**：IPv4 那边是 NAT，IPv6 这边虽然没有 NAT，但家用路由器默认开有状态防火墙、拦截主动入站——两种情况都要先从内侧发包才能开出返回通道。所以 A 发起前，服务端先让 C 朝 A 的**每个候选**连发几个 UDP 包，在 C 这侧开出允许 A 回包的状态，A 的 QUIC Initial 才进得来。

配置：

```yaml
# C（被连的一方，内网目标所在机器）
websocket:
  client:
    connect: "[2001:db8::1]:3002"   # 反射器在同端口的 UDP 上; 服务端两族都有地址时两族候选都能探到
    user: someuser
    pass: somepass
    email: home
    directAccept: true               # 允许别人直连自己(监听按需起, 平时不占端口)
    forward:                         # 复用同一张白名单: 未映射的 port 一律拒绝
      - port: 3389
        target: 192.168.1.10:3389

# A（发起的一方，入口在自己机器上）
websocket:
  client:
    connect: "[2001:db8::1]:3002"
    user: anotheruser
    pass: anotherpass
    email: office
    direct:
      - listen: ":13389"             # 本机入口, mstsc 连这里
        email: home                  # 直连到这个 email 的订阅端
        port: 3389                   # 用对方 forward 里的哪条规则
        protocol: both               # tcp(默认) / udp / both
```

### 多条路同时打，谁通用谁

A↔C 那一跳不再只走 IPv6。三类候选**同时**探测、同时打洞，谁先通谁先被观测到：

| 候选来源 | 怎么来的 |
|---|---|
| 反射器 IPv4 端点 | 用 QUIC 那个 socket 问服务端的 UDP 反射器（IPv4 那一族） |
| 反射器 IPv6 端点 | 同上，IPv6 那一族 |
| 端口映射 | 主动向家用路由器申请一个外网端口（PCP / NAT-PMP / UPnP，三种并行试） |

任何一路探不到都只是少一个候选，不影响其它路——这正是多候选的意义。以前只探 IPv6，探不到整条直连就废了。

**不收本机接口地址**（网卡上的 IP，不经反射器/端口映射）。那一类候选只在"两台机器同网段"时才有用，而这里面向的场景是跨网——两台机器分处不同网络，中间隔着 CGNAT 或真正的公网，同网段直连不是要解决的问题。收上来也只会占服务端候选上限（见下）的名额、干扰排查；真到了需要同网段优化的时候再加回来。

**多条都通了才谈优先级**，按实测 RTT 加一个地址类型偏置（相当于给它减去一点 RTT，让它更容易胜出）：

| 地址类型 | 偏置 | 含义 |
|---|---|---|
| 回环 | −50ms | 最优先，同机 |
| 链路本地 | −30ms | 次之，同二层 |
| 私有地址 / CGNAT | −20ms | 同网段直连优于绕公网 |
| 公网地址 | 0 | 基准 |

**公网 IPv4 与公网 IPv6 是平等竞争的**，偏置都是 0，纯比实测 RTT。哪个先打通、哪个更快就用哪个——没有"优先 IPv6"这种先验。

偏置是让近距离地址"更容易"胜出，不是无条件胜出：私有地址比公网慢 15ms 仍然赢，慢 30ms 就该输。

选了哪条、为什么选它，日志里能看到每条候选的 RTT、偏置和最终得分：

```
path selection for home: 1.2.3.4:41203(v4) rtt=38ms bias=0s score=38ms,
  [2400:3200::1]:41203(v6) rtt=22ms bias=0s score=22ms <-,
  192.168.1.7:41203(local) failed
```

"为什么没走 IPv6" 这类问题只有这一行答得了。

**打洞和测速是同一个动作**：发一个打洞包，对端自动回一个 pong。发出去那一下在本机这侧的防火墙/NAT 上开出返回通道（IPv6 没有 NAT，但家用路由器默认拦主动入站，同样需要），回来那一下就是这条路的 RTT。只对胜出的那条做一次 QUIC 拨号——不给每条候选都拨 QUIC，那是 N 次完整握手，而打洞包一来一回就够判断通不通与快慢了。

**端口映射能救什么、不能救什么**：它对付的是**对称 NAT**——那种给每个目的地都换一个外网端口的 NAT，反射器问到的端口对第三方根本没用，只能直接向路由器要一个洞。它**救不了 CGNAT**：路由器上映射成功了，拿到的也只是运营商内网地址，外面依旧进不来，除非 ISP 自己支持 PCP（国内基本没有）。三种协议都失败很正常，只是少一个候选。

**三段的地址族**：

| 段 | 地址族 | 说明 |
|---|---|---|
| 发起端 → A 入口 | 不限 | `listen: ":13389"` 这样写会绑 `[::]` 双栈，IPv4 客户端照样连得进来 |
| A ↔ C | 不限 | QUIC socket 绑双栈，两族候选在同一个源端口上竞争 |
| C → 内网目标 | 不限 | `forward` 里的 target 写 IPv4 内网地址是最常见的用法 |

注意入口地址的写法：`:13389` 是双栈；写成 `127.0.0.1:13389` 就只监听 IPv4（本机访问够用），写成 `[::1]:13389` 则只监听 IPv6。

**为什么 QUIC socket 必须是同一个双栈 socket**，而不是 v4/v6 各一个：打洞在对端防火墙上开出来的状态是按"本地 ip:port ↔ 对端 ip:port"记的。两个 socket 就是两个源端口，那边开出来的状态和这边实际拨号用的对不上。

### 直连传文件（`-send` / `receive`）

隧道本身能跑 scp/rsync，但那要求对端装了 sshd——跨 Windows 时这条往往不成立（OpenSSH 服务器是可选功能，默认不装）。所以内置了一条文件传输，**对端机器上不需要任何额外服务**，anyproxy 自己落盘。

接收端（配置里指定目录，需同时开 `directAccept`）：

```yaml
websocket:
  client:
    directAccept: true
    receive:
      dir: D:/incoming            # 收到的文件放这里；不配则一律拒收
      allow:                      # 可选，只允许这些 email 发过来
        - office@example.com
```

发送端（一条命令，传完就退出）：

```bash
anyproxy -send bigfile.zip -to home@example.com
```

```bash
anyproxy -send D:/photos -to home@example.com    # 目录递归，收端保持同样的结构
```

多个路径直接跟在后面：`anyproxy -send a.zip -to home@example.com b.zip D:/dir`。

**打洞不成功就报失败，一个字节都不传**——这条路径没有经服务端中继的回落，和直连入口的约定一致。失败时退出码非零、原因打在终端上，脚本里 `anyproxy -send ... && echo ok` 直接可用。

几个设计上的选择：

- **一个文件一条 QUIC stream**。每个文件的结果（存成什么名字、校验过没有、错在哪）互相独立，中间一个出错不会把整批的状态搅乱；开一条 stream 在 QUIC 上几乎不要钱。
- **SHA-256 校验，摘要放在数据后面**（不是首部）。放后面发送端才能边读边算——写首部的话必须先把整个文件读一遍算摘要，大文件等于白读一遍。收端摘要对不上就删掉并报错：留着一个内容错误、名字正确的文件比没收到更糟。
- **先写 `.part` 再改名**。中断留下的是一眼看得出没传完的东西，而不是一个看着正常、内容是半截的文件。
- **不覆盖同名文件**，自动改成 `x (1).zip`。覆盖会悄无声息毁掉收方已有的数据，代价远大于多一个带序号的名字；实际存成什么名字会回报给发送端。
- **文件名是对端说了算的，所以要防越界**：拒绝绝对路径、`..`、反斜杠和盘符，拼完之后再确认结果确实落在接收目录内。两道都做——先检查原始名字再规范化，顺序反了的话 `path.Clean` 会把 `..` 直接吃掉，检查永远不触发。
- **发送端是独立进程**，不要求本机已经跑着 anyproxy。传文件是有明确起止的动作，独立进程的退出码就能表达成败。它会临时多开一条 websocket，不影响常驻那条——直连信令是按"发起请求的那条连接"回的，不是按 email 查的。

**千兆链路上的吞吐**：QUIC 接收窗口已按千兆调过（单流 32MB / 连接 64MB）。quic-go 的默认值（单流 6MB）是按网页流量定的，吞吐上限约等于 `窗口 / RTT`，6MB 在 50ms RTT 下只剩约 960Mbps、100ms 下掉到约 480Mbps，跨省传大文件正好撞上。Linux 上还要保证 UDP 收包缓冲够大（`anyproxy -check` 会检查 `net.core.rmem_max`），否则 quic-go 会打一行 "failed to sufficiently increase receive buffer size" 并跑不满。

### TCP 与 UDP：两种协议在 QUIC 上的承载不同

`protocol` 决定入口与落地要还原哪种协议，两者在 QUIC 上走不同机制，语义才对得上：

| 内层协议 | QUIC 承载 | 说明 |
|---|---|---|
| TCP | **stream**（可靠有序） | 每条入口 TCP 连接一条 stream |
| UDP | **datagram**（不可靠无序，RFC 9221） | 每个用户源地址一个会话 ID |

**不能拿 stream 扛 UDP**——那会给 UDP 强加重传与保序，把我们特意要避开的队头阻塞又请回来。

`protocol: both` 对 RDP 特别有用：mstsc 主通道走 TCP 3389，而 RDP 8+ 的 Enhanced RDP 会用 **UDP 3389** 走图形通道专门对抗卡顿——只转发 TCP 等于把它堵死。

UDP 的两个限制：QUIC datagram 必须装进单个 QUIC 包（受 MTU 约束，约 1200 字节），超长的 UDP 包会被丢弃并记日志；UDP 无连接，会话靠空闲超时（30 分钟，与 websocket 转发路径的 `forwardIdleTimeout` 一致）回收。若用来转发大量短生命周期的 UDP 流（如 DNS），这个值应当调小。

### 连接复用：一条 QUIC 连接，多条 stream

**A 到同一个 email 只维持一条 QUIC 连接**，每条入口 TCP 连接在上面开一条独立 stream（SSH/RDP 同时开多个会话是常态）。这正是相对「单条 TCP 隧道复用」的核心优势：**stream 之间互不队头阻塞**，一条丢包不会让其他会话跟着卡。

并发上限 256（`directMaxStreams`）。超过后 `OpenStreamSync` 会**阻塞等待**而不是报错，现象是新会话卡住不动——撞上限时光看日志很难想到，所以这个值显式写在代码里而不是用 quic-go 的默认 100。

### 端点的寿命：请求驱动，不预先通告

**C 平时不占端口**。整个流程是请求驱动的：

```
A →B  请求(我的候选列表, token, 要连 email X)
B →C  有人要连你: 起监听 → 当场收集自己的候选 → 朝他的每个候选都打洞
C →B  我的候选列表 + 证书指纹(或失败原因)
B →A  offer(C 的候选列表 + 指纹)
A     朝 C 的每个候选并行打洞测 RTT → 按 RTT+偏置选一条
A ⇒C  对胜出的那条做 QUIC 拨号
```

这样设计是因为**对端能用的那个端点完全不受本机控制**：

- 地址会变——IPv6 隐私临时地址通常几小时到一天轮换一次，ISP 前缀也可能变；
- 端口也会变——路径上有 NAT（IPv4 必然，IPv6 也存在 NAT66/NPTv6、CPE 改写）时，外网端口和本地端口就不是一回事；映射老化重建后还会换一个。

所以协议里**从不传本地端口**，传的一律是当场探测到的完整端点。既然每次都要探，预先通告就没有意义——缓存下来的端点随时可能已经作废，而服务端无从得知。

**候选列表在服务端封顶 8 条**。服务端会把这份列表转给对端，对端朝**每一条**发打洞包——不封顶的话，一个恶意订阅方报上几百个地址，就能借另一台机器朝任意目标扫射，服务端成了放大器。列表里只收 IP 字面量，不收域名，免得让对端顺带做 DNS 去够任意主机。

请求驱动还顺带解决了几件事：C 空闲时零后台流量、不占 UDP 端口；也不存在"开机时网络还没就绪导致直连永久禁用"的问题——下次有人来连时重试即可。

### 身份校验：证书指纹只从 C 流向 A

C 起监听时生成自签证书并算出 SHA-256 指纹，经**已鉴权的 websocket** 交给服务端、再转给 A；A 拨号时把它放进 `VerifyPeerCertificate`，握手时比对 C 出示的证书。

所以 **A→C 的数据里不带指纹**——它是 A 用来确认"连上的确实是那台 C"的凭据，而不是 A 出示给 C 的东西。A 向 C 证明身份靠的是另一样东西：一次性凭证（见上文）。

自签证书过不了 CA 校验，指纹固定是这条链路唯一的身份凭据，因此**缺指纹的连接一律不建立**：服务端收到 C 的回复时校验指纹非空，A 收到 offer 时再校验一次；指纹不匹配则在 TLS 握手阶段失败。

注意 C 每次起监听都会重新生成证书，空闲释放后再起来指纹是新的——这不影响，因为指纹和端点是同一次请求里一起交给 A 的，永远配套。

### 空闲自动释放

两级回收，都以"没有活跃会话"为前提：

- **A 侧连接**：一条 QUIC 连接上所有会话结束、空闲超过 90 秒后关闭（`reapSessions`）。
- **C 侧监听**：没有活跃入向连接、空闲超过 90 秒后关掉监听并**释放 socket**（`reapAccept`）。下次再有请求时重新起一个，端口变了也无所谓——端点本来就是每次当场探的。

「活跃」对两种协议的判据不同，这点很关键：

| | 判据 | 为什么 |
|---|---|---|
| TCP | 入口连接的引用计数 | 连接开着就算在用，哪怕长时间没数据（RDP 静默、SSH 挂着不动） |
| UDP | 该入口还有会话在自己的 30 分钟窗口内 | UDP 没有"连接"可数，只看"最近收发"会误杀 |

UDP 这条尤其要紧：**mstsc 的 UDP 图形通道在用户不操作时可能很久没有包**，但会话并没有结束。若按"最近一次收发"判空闲，连接会被关掉，用户一动鼠标就得重新打洞建连。所以只要该入口还有用户会话在窗口内，就不算空闲。

（配 `protocol: both` 时另有一层保险：mstsc 主通道走 TCP 且全程保持，引用计数本来就会把整条 QUIC 连接锚住。但纯 `udp` 配置就只能靠上面这条判据。）

活跃期间 QUIC 开着 20 秒 keep-alive，用来焐住 NAT 映射和有状态防火墙的洞（RDP 常有大段没数据的时候）。但 keep-alive 会一直把 QUIC 自身的空闲超时顶回去，连接不会自然死亡，所以上面这两级回收是必需的——否则多台 A 连过同一个 C 时，C 会永久累积连接和保活包。

socket 也支持失效重建：网卡下线、地址被撤等情况下会丢弃坏掉的 socket，下次用时重新建一个。

## 配置字段

`websocket` 段（[router.go](../utils/conf/router.go) 的 `Websocket`）按角色分 `server` / `client` 两块：

`websocket.server`（服务端，`WsServer`）：

| 字段 | 说明 |
|------|------|
| `listen` | websocket 监听地址，如 `:3002`（订阅端连它的 `/ws`）。等价 `-ws-listen` |
| `users` | 鉴权账号数组，每条 `{user, pass, disable}`；不同订阅端各用各的账号，可单独停用某个，见下文「多用户鉴权」 |
| `allowIP` | 可接入的客户端 IP 白名单（CIDR/单 IP，**IPv4 与 IPv6 都支持**），为空不限制。按**真实 TCP 来源**（`r.RemoteAddr`）判定，不信任 `X-Real-IP` 等可伪造头部；loopback 始终放行。命中即拒绝、连 upgrade 都不做。约束范围：websocket 接入、裸 TCP 转发入口（`forward.listen`）、以及直连用的 UDP 反射器 |
| `forward` | 裸 TCP 转发入口规则数组（路径 B），每条 `{listen, email}`，见下 |

### 多用户鉴权

服务端只有一种写法：`websocket.server.users` 数组，每项 `{user, pass}` 或 `{user, key}`（没有单用户的简写）。只有一个订阅端时也要写成长度为 1 的数组：

```yaml
websocket:
  server:
    listen: :3002
    users:
      - user: dmit
        pass: 1ab2d964
      - user: office
        pass: 9f3c7a21
        disable: true   # 临时停用该账号: 鉴权直接拒绝, 不用删配置/改密码
```

每个账号是**密码或密钥二选一**（两个都配时用密钥），见下节。订阅端各自在自己的 `websocket.client.user`/`pass`（或 `clients[].user`/`pass`）填对应账号即可，鉴权时服务端按订阅端发来的 `user` 查 `users` 里对应的账号信息算 token（`nat/conn.go` 的 `serveWs` 调用 `utils/conf/router.go` 的 `WsServer.LookupUser`）。

**停用某个账号**：给对应条目加 `disable: true` 即可，不用删掉整条配置或改密码——`user` 还能查到这条记录，但鉴权会直接拒绝（服务端日志打 `user %s is disabled`，返回给订阅端的错误和"查无此人"一样都是 `user err`，不额外暴露账号是否存在）。这个字段热加载生效（下次订阅端重连时就会被拒），不用重启服务端；订阅端本身仍会按自己的退避策略反复重试，只是连不上。

`websocket.client`（订阅端，`WsClient`）：

| 字段 | 说明 |
|------|------|
| `connect` | 要回连的服务端 ws 地址，如 `<公网IP>:3002`。无命令行等价，只能配置文件 |
| `host` | `connect` 用的 `Host` 头/域名（走 TLS 网关时需要；无则可填服务端 IP） |
| `user` | 鉴权用户，**与服务端一致** |
| `pass` | 鉴权密码，**与服务端一致**；参与 token 计算，漏配会鉴权失败。与 `key` 二选一 |
| `key` | 鉴权私钥（`anyproxy -genkey` 生成），与 `pass` 二选一、都配时用它；对应公钥配在服务端 `users[].key` |
| `email` | 本订阅端身份，用于服务端定位/选择（HTTP 路径辅助、TCP 路径按它匹配 `server.forward.email`）。非空且不参与 token |
| `subscribe` | HTTP 头订阅规则数组，每条 `{key, val}`；路径 A 用 |
| `forward` | 裸 TCP 转发目标规则数组（路径 B），每条 `{port, target}`，见下 |

### 密钥对鉴权（免时钟同步）

密码方案把时间戳算进 token 来防重放，代价是两端时钟差超过 300s 就连不上，而没有 NTP 的机器上这很常见。密钥方案换成**挑战-应答**：服务端每次发一个一次性随机数，订阅端用私钥签名，服务端用公钥验签——随机数只用一次，天然防重放，**完全不看时间**。另一个好处是服务端配置里只有公钥，泄露也无法用于登录。

用 Ed25519 而不是 xray 里那种 X25519：这里要证明的是"我持有私钥"，那是签名的活；X25519 是密钥交换原语，拿来做认证还得两边各有一对密钥再派生共享密钥，步骤更多，而多出来的相互认证在这儿用不上。

生成一对（在哪台机器生成都行，两串是配套的）：

```bash
anyproxy -genkey
```

```text
Private key (client, websocket.client.key): b9sbLhlE...（私钥，给订阅端）
Public key  (server, websocket.server.users[].key): dU0T51WQ...（公钥，给服务端）
```

服务端把公钥填进对应账号，**`pass` 留空**：

```yaml
websocket:
  server:
    users:
      - user: dmit
        key: dU0T51WQ2lgy9xLT+g8CzQuFjcsc8KYawZx7mNXNoXc=
```

订阅端填私钥，同样 `pass` 留空：

```yaml
websocket:
  client:
    connect: 1.2.3.4:3002
    user: dmit
    key: b9sbLhlEnH7TwyDQTHbrI9G0vBVv683WfJGVAwtJcIB1TRPnVZDaWDL3EtP6DwLNC4WNyxzwphrBnHuY1c2hdw==
    email: me@example.com
```

**逐账号选择**：走哪套由服务端该账号的配置决定——配了 `key` 就只认密钥，没配就只认密码。所以可以一部分订阅端用密钥、另一部分继续用密码，互不影响，也不用一次性全改。

**两端配错方案时能看出来**，不会只是"连不上"：服务端配了 key 而订阅端发密码 → 订阅端收到 `auth err: server expects key auth for this user, please set websocket.client.key`；反过来 → `auth err: server has no key for this user, please use websocket.client.pass`。私钥本身格式不对的话订阅端在发出去之前就会报 `websocket.client.key is invalid: ...`。

### 同时订阅多台 server

一个订阅端进程可以同时回连多台 server，每台账号/订阅规则/端口转发表可以完全不同。用 `websocket.clients`（复数，数组）代替单个 `websocket.client`，数组每个元素就是一个完整的 `WsClient` 块（字段同上表）：

```yaml
websocket:
  clients:
    - connect: 1.2.3.4:3002
      host: ws1.example.com   # 可选, 走 TLS 网关时用
      user: someuser
      pass: somepass
      email: home
      subscribe:               # 可选, HTTP 头订阅路径(路径A)用, 裸TCP转发不需要
        - key: X-Env
          val: home
      forward:
        - port: 2222
          target: 127.0.0.1:22
    - connect: 5.6.7.8:3002
      user: anotheruser
      pass: anotherpass
      email: office
      forward:
        - port: 2222          # 入口端口号可以和上一台重复, 互不冲突(各连接独立的转发表)
          target: 192.168.1.10:3389
```

每个元素就是一个完整独立的 `WsClient`（和单个 `websocket.client` 用的是同一个结构体），`host`/`subscribe`/`forward` 这些字段和单块 `client` 写法一样都能用，只是上面第二条示例省略了没写（省略的字段就是空/不启用，不代表不支持）。

`nat.ConnectServer` 对每台 server 各自维护一份独立的 websocket 连接、请求 ID 计数、桥接表(`Bridge`)和端口转发映射（[nat/handler.go](../nat/handler.go) 的 `wsClientConn`），互不串扰；日志每行会带 `[connect地址]` 前缀，方便区分是哪条连接。

**与旧 `client` 字段的关系**：`clients` 与旧的单块 `client` 二选一 —— 配了 `clients` 就只用 `clients`（`client` 被忽略）；不配 `clients` 时退化为旧行为（`client` 块包装成单元素列表）。

`server.forward` 每条（`ServerForward`）/ `client.forward` 每条（`ClientForward`）：

| 字段 | 角色 | 说明 |
|------|------|------|
| `listen` | 服务端 | 入口监听地址，如 `:2222` |
| `email` | 服务端 | 把该入口端口的连接转发给此 `email` 的订阅端 |
| `protocol` | 服务端 | `tcp`(默认) / `udp` / `both`。TCP 经 websocket 转发，UDP 另起一条 UDP 中继，两条各走各的（见路径 B 的第二条通道） |
| `port` | 订阅端 | 对应服务端入口端口号（如 `2222`），TCP 与 UDP 共用同一张表 |
| `target` | 订阅端 | 收到该端口来的连接/数据报时 dial 的内网真实目标，如 `127.0.0.1:22` |

## 鉴权与握手

订阅端连服务端的 `/ws`，随后发 `AuthMessage`（`nat/handler.go` 的 `auth`）。服务端先查账号（`LookupUser`），再按该账号配的是 `key` 还是 `pass` 分支（`nat/conn.go` 的 `authClient`）：

**密码方案**（`authByPass`）：

- `token = md5(user | pass | xtime)`，`xtime` 为当前秒级时间戳；
- 服务端校验 `email` 非空、`user` 能查到且未被 `disable`、`|now - xtime| <= 300`（防重放，**两端时钟需大致同步**）、`token` 与用**该 user 对应的 pass** 算出的一致。时差超限时回包会带上**实际差了多少秒**，不用去服务端翻日志。

**密钥方案**（`authByKey`，见上面「密钥对鉴权」）：

- `AuthMessage` 里 `KeyAuth: true`，`Token`/`Xtime` 不参与；
- 服务端回 `AuthChallenge{challenge}`（32 字节一次性随机数）而不是 `ok`，订阅端用私钥签名回 `AuthSignature{signature}`，服务端用配置里的公钥验签。**这条路径不检查时钟**；这一步多一个来回，服务端对签名设了 10s 超时。

之后订阅端发 `subscribe`（可为空）。若 `subscribe` 为空，仅当该 `email` 命中某条服务端 `forward` 规则时才放行（`isForwardEmail`）——即**纯裸 TCP 转发的订阅端不需要 `subscribe`**。

失败会断开并退避重连（订阅端自带重连循环）。

## 命令行等价

| 参数 | 配置项 |
|------|--------|
| `-ws-listen` | `websocket.server.listen` |
| `-genkey` | 生成一对鉴权密钥并退出（私钥填 `websocket.client.key`，公钥填 `websocket.server.users[].key`） |
| `-send PATH -to EMAIL` | 经直连把文件/目录发给另一个订阅端并退出（见"直连传文件"） |

> 订阅端(客户端)**没有命令行参数**，`connect`/`user`/`pass`/`key`/`email`/`subscribe`/`forward` 都只能写在配置文件里；同时订阅多台 server 也只能用 `websocket.clients[]`。所以裸 TCP 转发（依赖 `forward`）和订阅端相关配置只能用配置文件。

## 常见坑

- **`user`/`pass` 两端不一致** → 订阅端 token 校验失败、连不上。`pass` 必须两端都配（旧文档示例曾漏配订阅端 `pass`）；订阅端的 `user` 要能在服务端 `server.users` 里查到、且该条没设 `disable: true`，否则报 `user err`。
- **`email` 对不上** → 裸 TCP 转发时服务端日志 `no forward ... no subscriber for email ...`。服务端 `server.forward.email` 必须等于某订阅端的 `client.email`。
- **时钟漂移 > 300s** → 鉴权失败，订阅端会收到 `xtime err: your clock differs from the server by Ns ...`（带实际时差）。保证两端时间同步，或**改用密钥对鉴权**（见上），那套不看时钟。
- **被服务端 `allowIP` 挡掉** → 订阅端日志 `ws connect err: ... (server replied 403 Forbidden ...)`。注意 IPv6 地址会轮换（RFC 4941 临时地址），白名单建议写前缀网段而不是单个地址。
- **订阅端只认白名单**：只 dial 自己 `forward` 里写死的 `target`，未映射的 `port` 直接拒绝——服务端入口端口被人乱连也打不进内网。
- **UDP 中继的第一个包会慢一拍**：上行是收到第一个数据报才建的，头一个包要等 B→C→B 一个来回。RDP 会自己重试，不用管；自己写的 UDP 应用如果不重试就要注意。
- **UDP 中继只在 `protocol: udp|both` 时才起**：默认 `tcp`，光配 `client.forward` 是不够的，入口那条规则也得写 `protocol`。
- **路径 A 的 `CONNECT` 不支持**：HTTP 头订阅路径只处理非 `CONNECT` 的 HTTP 请求。

## 示例

见 [config-examples.md](config-examples.md) 第 8 节（8.1 HTTP 头订阅、8.2 裸 TCP 内网穿透）。
