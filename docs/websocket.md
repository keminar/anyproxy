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
- 订阅端：`websocket.client.forward[].port → target` 建映射（`nat/forward.go` 的 `buildForward`，每台 server 连接各自一份）。收到服务端「入口端口 Port」来的连接时，dial 对应 `target`；**Port 未在本地映射则拒绝**（`nat/forward.go` 的 `dialForCreate`）——天然白名单。拒绝原因会经 `METHOD_CLOSE` 带回服务端（`Bridge.CloseReason`），折进服务端自己的 `nat forward closed ... reason=peer close: ...` 汇总行——不用再跨机器去翻订阅端的本地日志。
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
  [2400:3200::1]:41203(v6) rtt=22ms bias=0s score=22ms <-
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

### 文件传输（`-send` / `-recv` / `receive`）

隧道本身能跑 scp/rsync，但那要求对端装了 sshd——跨 Windows 时这条往往不成立（OpenSSH 服务器是可选功能，默认不装）。所以内置了一条文件传输，**对端机器上不需要任何额外服务**，anyproxy 自己读写文件。

两个方向，都是一条命令跑完就退出的一次性进程：

| | 做什么 | 谁在操作 |
|---|---|---|
| `-send PATH -to EMAIL` | 把本机的文件推给对方 | 发送的那台 |
| `-recv EMAIL:PATH -to DIR` | 把对方的文件取回本机 | **取文件的那台**，对方不需要有人配合 |

配置只有一份，两个方向共用（直连路径还需同时开 `directAccept`）：

```yaml
websocket:
  client:
    directAccept: true
    receive:
      dir: D:/incoming            # 收到的文件落这里，也是允许被取走的根目录；不配则收发都拒绝
      readonly: false             # true 时 dir 只能被取走、不接受任何人写入
      allow:                      # 一条一个 {email, uuid}; 留空=谁都不接受
        - email: office@example.com
          uuid: 3fa85f64-5717-4562-b3fc-2c963f66afa6
```

**`allow` 是双向的**：列在这里的人既能往 `dir` 里发文件，也能取走 `dir` 下的任何东西。这是有意的——收和取是对称的动作、面向的是同一批人（往往就是自己的另外几台机器），不值得为此维护两份几乎一样的名单。代价要清楚：**配一个人进来 = 同时把这个目录的读和写都交给了他**，所以 `dir` 应该是一个专门用来交换文件的目录，而不是随手指向什么重要位置。取文件时对方只能拿到 `dir` 以内的东西（路径逐段校验，`..`、绝对路径、以及指向目录外的符号链接都会被拒绝）。

要只给读不给写，用 `readonly: true`——`dir` 变成只出不进，别人 `-send` 过来会收到一句明确的拒绝，`-recv` 照常。这是为"对外放一份东西让几台机器自己来拿"（装机包、备份、发布产物）准备的：那种场景本来就不需要对方能写，而 `allow` 一填就是读写一起给。拒收发生在协议层，不依赖文件系统权限——目录在操作系统层面是不是只读，anyproxy 管不着也不假设。

`allow` 里的 `email` 只是备注/查找用——标明这个 `uuid` 是谁的机器，服务端（B）从不校验它，任何一个拿到合法账号密码的人都能在自己的 `client.email` 里填别人的地址（`email` 本来就"用于定位用户，不鉴权"，见「配置字段」）。真正的凭证是 `uuid`：对端必须自带与这里配置一致的 `websocket.client.uuid`，才能通过校验（直连路径是精确比对，中继路径是能否用它解密，见下）。

发送方的 `websocket.client.uuid` 不可手动配（配置文件里没有这个字段）：启动时自动生成一个随机值，持久化到配置文件同目录、同名的**隐藏文件**（`router.yaml` 对应 `.router.uuid`，`office.yaml` 对应 `.office.uuid`；Windows 上还会打上隐藏属性。生成后会打在启动日志里，方便复制），重启不会变。它是程序自己维护的状态而不是配置，所以不跟 `router.yaml` 摆在一起显眼处——拷贝配置时别顺手把它也带走，两台机器同一个 uuid 等于同一个身份。老版本留下的 `router.uuid`（不带点）在下次启动时会被自动改名成 `.router.uuid`，uuid 的值不变，对端 `receive.allow` 不用改。去发送方的启动日志抄一次这个值，填进接收方这里的 `allow[].uuid` 即可。

身份是按**配置文件**分的，不是按物理机器：同一份配置文件下的多个 `client` 块（`websocket.clients[]`）共用一个 uuid；但用 `-c` 指向不同的配置文件（哪怕在同一目录下）会各自生成独立的 uuid，不会共用——这与"一份配置文件本身就是一份独立、可单独拷贝到别处的设置"这个前提一致，不去猜测两份配置是不是描述同一台物理机器。

这与旧版的关键区别：旧版 `allow` 是纯 email 列表，而 email 本身在 B 那从没被鉴权过，`allow` 形同虚设。现在换成 email（查找用）+ uuid（真正的凭证）：uuid 是随机生成的高熵值，不像 email 那样是对方本就知道的公开信息，光知道对方的邮箱地址不足以冒充。

发送端（一条命令，传完就退出）：

```bash
anyproxy -send bigfile.zip -to home@example.com
```

```bash
anyproxy -send D:/photos -to home@example.com    # 目录递归，收端保持同样的结构
```

多个路径直接跟在后面：`anyproxy -send a.zip -to home@example.com b.zip D:/dir`。

**打洞不成功就报失败，一个字节都不传**——这条路径没有经服务端中继的回落，和直连入口的约定一致。失败时退出码非零、原因打在终端上，脚本里 `anyproxy -send ... && echo ok` 直接可用。

#### 反向：`-recv` 主动去对方那儿取（对方不需要有人操作）

`-send` 要求文件所在的那台机器上有人跑命令。但常见的情况恰恰相反：人在 A 上，想要 C 上的某个文件，而 C 那边没人——机房里的一台服务器、家里没人看着的 NAS。`-recv` 就是这个方向，写法照抄 scp：

```bash
anyproxy -recv home@example.com:backup/db.sql -to /data/in   # 取一个文件
anyproxy -recv home@example.com:backup       -to /data/in    # 取整个目录，结构原样重建
```

冒号后面的路径**相对于对方的 `receive.dir`**（不是对方的文件系统根），且必须写出来——不给路径不会默认"整个目录"，一句话把对方的共享目录全端过来不该是手滑的后果。`-to` 是本机的存放目录，不给就是当前目录。

跑起来是这样：A 先要一份清单（一个文件就一条，目录则递归展开），打印总数和总大小，然后逐个取回，每个文件一行进度。中途任何一个失败就停下并非零退出，不会留下一个"看着成功了"的半份目录。

前提与 `-send` 完全对称：A 的 `websocket.client.uuid` 必须列在 C 的 `receive.allow` 里——就是那份让 C 能接收 A 发来的文件的同一份名单（见上面「`allow` 是双向的」）。

实现上不需要反转连接方向：A 仍然是打洞/拨号的发起方，只是在流上先说一句"把这个给我"，之后两边的角色互换——C 跑发送逻辑，A 跑接收逻辑，落盘、`.part` 占位、SHA-256 校验、重名不覆盖这些跟 `-send` 是同一份代码。

#### 两条路径，必须显式声明：`-via direct`（默认）还是 `-via relay`

`-send` 和 `-recv` 都认这个参数。

```bash
anyproxy -send bigfile.zip -to home@example.com -via relay
```

| | `-via direct`（默认） | `-via relay` |
|---|---|---|
| 数据怎么走 | A↔C 打洞直连（路径 C），不经 B | 经 B 转发，走 A、C 各自已鉴权的 websocket 连接 |
| 加密 | QUIC 全程加密，B 看不到内容 | 用 `receive.allow` 里的 uuid 派生出的密钥端到端加密（见下），B 转发的是密文，同样看不到内容 |
| 前提条件 | 收端要开 `directAccept`；打洞可能失败（双方都在严格 NAT/CGNAT 后面） | 收端**不需要**开 `directAccept`；只要 A、C 都连着同一个 B 就能传，不需要打洞 |
| 失败即拒收 | 是——一个字节都不传 | 是——同样不做静默回落，两条路径互不兜底 |

`receive.allow` 在两条路径下都有效，但核验方式不同：

- **`direct`**：发送方在 QUIC 流首部（已经端到端加密，B 看不到）自报 `(email, uuid)`，接收方按 email 查到期望的 uuid，逐字比对。
- **`relay`**：uuid 直接被当作这次传输的加密密钥的派生来源——接收方按发送方自报的 email 查到 uuid，用它加密/解密整段数据；能不能解密+校验通过本身就是身份证明，不需要另外声明一次。这带来一个额外的好处：**中继路径现在也是端到端加密的**，B 全程只转发密文，连 email/uuid 这些字段的值都不需要保密。

选哪条：两条路径现在都是端到端加密，主要看能不能打洞——能打洞就用 `direct`（延迟更低，不占 B 的带宽）；打洞失败、或者双方所在网络已知走不通打洞（比如同一个运营商大内网互相看不见）时用 `relay`，代价是吞吐受 B 的带宽限制。

**版本要求**：`-recv -via relay`（经中继取文件）要求**服务端 B 也升级到本版本**——B 转发中继请求时会重新拼一个消息，老版本的 B 不认识新增的"这是取件不是发件"标记，会把它丢掉，C 于是当成收文件来处理，最后回一个语焉不详的错误。表现是明确失败（不会静默地传错东西），但要看懂就得知道这一段。`-recv -via direct`（打洞取件）不受影响：数据面完全不经 B，B 只转交地址，一行都不用动。

几个设计上的选择：

- **一个文件一条 QUIC stream**。每个文件的结果（存成什么名字、校验过没有、错在哪）互相独立，中间一个出错不会把整批的状态搅乱；开一条 stream 在 QUIC 上几乎不要钱。
- **SHA-256 校验，摘要放在数据后面**（不是首部）。放后面发送端才能边读边算——写首部的话必须先把整个文件读一遍算摘要，大文件等于白读一遍。收端摘要对不上就删掉并报错：留着一个内容错误、名字正确的文件比没收到更糟。
- **先写 `.part` 再改名**。中断留下的是一眼看得出没传完的东西，而不是一个看着正常、内容是半截的文件。
- **不覆盖同名文件**，自动改成 `x (1).zip`。覆盖会悄无声息毁掉收方已有的数据，代价远大于多一个带序号的名字；实际存成什么名字会回报给发送端。
- **文件名是对端说了算的，所以要防越界**：拒绝绝对路径、`..`、反斜杠和盘符，拼完之后再确认结果确实落在接收目录内。两道都做——先检查原始名字再规范化，顺序反了的话 `path.Clean` 会把 `..` 直接吃掉，检查永远不触发。
- **取文件方向多一道符号链接检查**。收文件时创建的是新文件，符号链接无从谈起；取文件不一样——共享目录里放一个指向 `/etc/shadow` 的软链，光靠上面那套字符串检查是拦不住的（拼出来的路径确实在目录内），所以解析完软链之后要再确认一次仍在目录内。共享目录自己经由软链（macOS 的 `/tmp` → `/private/tmp`）是正常配置，两边都解析后再比，不会误判。
- **`-send` / `-recv` 都是独立进程**，不要求本机已经跑着 anyproxy。收发文件是有明确起止的动作，独立进程的退出码就能表达成败。它会临时多开一条 websocket，不影响常驻那条——直连信令是按"发起请求的那条连接"回的，不是按 email 查的。
- **常驻的那份配置若只是为了给 `-send`/`-recv` 取凭证，不用额外配置**：`anyproxy` 常驻进程启动时会为每一条 `websocket.client(s)` 判断值不值得发起常驻连接——只要 `subscribe`/`forward`/`direct`/`directAccept`/`receive.dir` 全是空的，就自动跳过（这条配置仍然完好，只是常驻进程不去连它；运行 `-send`/`-recv` 时照常按这条配置的凭证取用）。这是因为服务端也是同一套判断：空 `subscribe` 又不是转发目标/直连方/接收方的连接会被 `serveWs` 一直拒绝并断开（日志刷 `ignore, subscribe is empty`），常驻进程连上去纯属陪跑。想强制跳过（哪怕配了其中几项）就显式加 `sendRecvOnly: true`。

**千兆链路上的吞吐（仅 `direct`；`relay` 受 B 的带宽限制，不受这个影响）**：QUIC 接收窗口已按千兆调过（单流 32MB / 连接 64MB）。quic-go 的默认值（单流 6MB）是按网页流量定的，吞吐上限约等于 `窗口 / RTT`，6MB 在 50ms RTT 下只剩约 960Mbps、100ms 下掉到约 480Mbps，跨省传大文件正好撞上。Linux 上还要保证 UDP 收包缓冲够大（`anyproxy -check` 会检查 `net.core.rmem_max`），否则 quic-go 会打一行 "failed to sufficiently increase receive buffer size" 并跑不满。

#### 单个大文件切块并行传输：`-parallel N`

默认每个文件只占一条连接（`direct` 下是一条 QUIC stream，`relay` 下是一次中继会话），这在单条连接吞吐已经打满链路时够用，但受限于单流拥塞窗口爬升、中继流控窗口这些"单条连接"自身的天花板时就不够了。`-parallel N`（默认 1）让**单个**大文件按字节区间切成最多 `N` 块，各开一条独立连接并行传，两条路径（`-via direct`/`-via relay`）和两个方向（`-send`/`-recv`）都支持：

```bash
anyproxy -send bigfile.zip -to home@example.com -parallel 4
anyproxy -recv home@example.com:backup/bigfile.zip -to /data/in -parallel 4
```

- **只切单个文件，不做多文件并发**。批量 `-send`/`-recv` 多个文件时仍然一个接一个传——切块并行的目的是让单个大文件更快用满带宽,不是让多个文件抢同一份带宽（那样反而会拖长每一个文件的耗时）。
- **文件太小不会被切**：低于 8MiB 的文件永远走单连接路径，`-parallel` 的值被忽略，切块的握手/首部开销在小文件上不划算。
- **失败语义与不切块时一致**：任意一块传输失败（网络错误、校验不过）就让整份文件报错、`.part` 文件被清理，不会留下一个只传对了几块的半成品，也不会自动重试。
- **`-via relay` 下每一块各自协商一次加密会话**（各自独立的随机 salt、独立派生的 AES-256-GCM 密钥），协议本身早就支持"随时开一条新的加密会话"，不需要为切块单独改握手。

##### `-parallel` 未必总能提速：先搞清楚瓶颈在哪

**分块用的是同一条底层连接**——`direct` 下 N 个分块是同一条 QUIC 连接上的 N 条 stream，`relay` 下是同一条 websocket（同一条 TCP 连接）上的 N 个中继会话。QUIC/TCP 的拥塞控制（congestion control）都是按**连接**算的，不是按 stream/会话算的，也就是说这 N 条并发路径共用同一个拥塞窗口、在网络设备眼里是**同一个五元组**（同一对源/目的 IP+端口）。如果瓶颈是运营商按流限速、或者链路本身拥塞丢包，`-parallel` 在这种同连接复用的实现下大概率没用——运营商看到的还是"一条流"，不会因为应用层多开了几条 stream 就分配更多带宽。

`-parallel` 真正能帮上忙的场景，是单条 stream/中继会话自身的流控窗口（不是拥塞窗口）先于网络带宽打满——比如高延迟长距离链路上单流的窗口不够大、或者瓶颈其实是 CPU（哈希计算、加解密）而不是网络。这两种情况开多条并发路径能实打实提速；如果瓶颈是运营商跨网互联质量差或者按流/按账号限速，开再多条也没用。

**用之前先用 `iperf3` 诊断一下，别凭感觉猜**（假设 A 传得慢，C 是收数据的那台，两台要能相互访问）：

```bash
# 1. 在 C 上起服务端(默认 5201 端口, 注意防火墙放行)
iperf3 -s

# 2. 在 A 上先测单流基线, 换算成 KB/s 跟你实际观察到的速度对一下
iperf3 -c <C的IP> -t 20

# 3. 再测多流并发(TCP), 4 条独立连接, 看 [SUM] 那一行的总吞吐
iperf3 -c <C的IP> -P 4 -t 20

# 4. UDP 模式(QUIC 走的是 UDP, 这组更贴近实际情况; -b 指定目标速率, 因为
#    UDP 本身没有拥塞控制, iperf3 会按你给的速率硬发, 看 Lost/Total Datagrams 的丢包率)
iperf3 -u -b 500M -c <C的IP> -t 20
iperf3 -u -b 500M -c <C的IP> -P 4 -t 20

# 5. 可选: 加 -R 反向测一遍, 排除单向拥塞(比如电信->联通和联通->电信的
#    瓶颈链路往往不是同一条)
iperf3 -c <C的IP> -P 4 -t 20 -R
```

看结果：

| 现象 | 结论 |
|---|---|
| 单流慢，多流（`-P 4`）的 `[SUM]` 明显比单流高很多 | 是按流限速/单流窗口撑不满，`-parallel` 值得用 |
| 单流慢，多流 `[SUM]` 也差不多、丢包率高 | 链路本身拥塞（常见于运营商跨网互联质量问题），`-parallel` 收益有限 |
| TCP 结果还行，UDP 明显更差 | 运营商可能单独限制了 UDP，这种情况即使改造成多条独立 QUIC 连接也未必顶得上去，可以考虑改用 `-via relay`（走 TCP 的 websocket）绕开 |

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
| `users` | 鉴权账号数组，每条 `{user, pass, disable}` 或 `{user, key, disable}`（密码/密钥二选一）；不同订阅端各用各的账号，可单独停用某个，见下文「多用户鉴权」「密钥对鉴权」。`pass` 至少 18 位、英文字母和数字都要有，不达标（含没配 `pass` 又没配 `key`）的账号加载时会被自动置为 `disable`，日志里会说明原因 |
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
        pass: Tr0ub4dor-and-Battery1
      - user: office
        pass: correcthorsebattery9
        disable: true   # 临时停用该账号: 鉴权直接拒绝, 不用删配置/改密码
```

每个账号是**密码或密钥二选一**（两个都配时用密钥），见下节。订阅端各自在自己的 `websocket.client.user`/`pass`（或 `clients[].user`/`pass`）填对应账号即可，鉴权时服务端按订阅端发来的 `user` 查 `users` 里对应的账号信息算 token（`nat/conn.go` 的 `serveWs` 调用 `utils/conf/router.go` 的 `WsServer.LookupUser`）。

**密码强度**：`pass` 至少 18 位、英文字母和数字都要有。不达标（含没配 `pass` 又没配 `key`）的账号在配置加载时会被自动置为 `disable`，不会悄悄放行一个弱密码/空密码账号——服务端日志会打一行说明是哪个账号、为什么被停用。这条校验只在服务端做，订阅端不判断（`websocket.client(s).pass` 弱不弱，订阅端照样会拿去发起连接），这样新版本订阅端也能照常连尚未升级的旧服务端（或者密码还没改达标的账号），不会因为本地这关先拒了就白白拨不出去——服务端这一关本来就够了。改用 `key` 走密钥挑战-应答的账号不受这条限制。

**停用某个账号**：给对应条目加 `disable: true` 即可，不用删掉整条配置或改密码——`user` 还能查到这条记录，但鉴权会直接拒绝（服务端日志打 `user %s is disabled`，返回给订阅端的错误和"查无此人"一样都是 `user err`，不额外暴露账号是否存在）。这个字段热加载生效（下次订阅端重连时就会被拒），不用重启服务端；订阅端本身仍会按自己的退避策略反复重试，只是连不上。

`websocket.client`（订阅端，`WsClient`）：

| 字段 | 说明 |
|------|------|
| `connect` | 要回连的服务端 ws 地址，如 `<公网IP>:3002`。无命令行等价，只能配置文件 |
| `host` | `connect` 用的 `Host` 头/域名（走 TLS 网关时需要；无则可填服务端 IP） |
| `user` | 鉴权用户，**与服务端一致** |
| `pass` | 鉴权密码，**与服务端一致**；参与 token 计算，漏配会鉴权失败。与 `key` 二选一。服务端要求它至少 18 位、英文字母和数字都要有，但这条强度校验只在服务端做——本机不判断，弱密码照样会拿去发起连接，让新版本订阅端也能连尚未升级的旧服务端 |
| `key` | 鉴权私钥（`anyproxy -genkey` 生成），与 `pass` 二选一、都配时用它；对应公钥配在服务端 `users[].key` |
| `email` | 本订阅端身份，用于服务端/对端定位（HTTP 路径辅助、TCP 路径按它匹配 `server.forward.email`、文件传输 `-to`/`receive.allow` 按它查表）。非空，本身不参与鉴权、也不是安全边界 |
| `uuid` | 这份配置的身份凭证，只在文件传输(`-send`)的收发双方之间使用，B 完全不感知。**不可在配置文件里配**：启动时自动生成并持久化到配置文件同目录、同名的隐藏文件（`router.yaml` 对应 `.router.uuid`），重启不变；`-c` 指向不同配置文件各自独立、不共用。生成后打在启动日志里，复制给对端配进它的 `receive.allow[].uuid`。见「文件传输」 |
| `subscribe` | HTTP 头订阅规则数组，每条 `{key, val}`；路径 A 用 |
| `forward` | 裸 TCP 转发目标规则数组（路径 B），每条 `{port, target}`，见下 |
| `directAccept` | `true` 时起 QUIC 监听并把端点通告给服务端，允许其它订阅方直连自己（路径 C，见下）；监听按需起、空闲释放，平时不占端口 |
| `direct` | 本机 QUIC 直连入口规则数组（路径 C），每条 `{listen, email, port, protocol}`，见下 |
| `receive` | 接收文件传输（直连或中继）的配置 `{dir, allow}`，`allow` 每条 `{email, uuid}`；不配 `dir` 则一律拒收，`allow` 留空则谁都不接受，见「文件传输」 |
| `sendRecvOnly` | `true` 时强制这条配置只用来给 `-send`/`-recv` 命令行取凭证（含生成/持久化 `uuid`），常驻进程不会为它发起连接，哪怕配了 `subscribe`/`forward`/`direct`/`receive` 也照样跳过。**通常不需要配它**：这几项全空时常驻进程会自动判断出没什么可连的而跳过，见下方说明 |

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

`client.direct` 每条（`ClientDirect`，路径 C 的本机直连入口，配在**发起方** A 上）：

| 字段 | 说明 |
|------|------|
| `listen` | 本机入口监听地址，如 `:13389`；`:13389` 绑 `[::]` 双栈，IPv4 客户端也能连 |
| `email` | 直连到这个 email 的订阅方（即 C，须与本条 `server` 连接下的另一订阅方一致） |
| `port` | 告诉 C 用它自己 `client.forward[port]` 里的哪条规则；C 未映射该端口即拒绝 |
| `protocol` | `tcp`(默认) / `udp` / `both`。两种协议在 QUIC 上走不同承载（stream / datagram），见下文「TCP 与 UDP」；`both` 常用于 RDP |

`client.receive`（`ClientReceive`，接收直连传来的文件，配在**接收方** C 上，需同时开 `directAccept`）：

| 字段 | 说明 |
|------|------|
| `dir` | 收到的文件落盘的目录；**不配则一律拒收**（对端会收到明确的拒绝原因，见「直连传文件」） |
| `allow` | 可选，email 白名单数组；只有列在里面的发送方才能发文件过来，为空表示不限制（仍受直连本身的鉴权约束——对方必须先通过服务端信令拿到一次性凭证）。判断依据是**服务端在 punch 信令里填的发起方身份**，不是对端自己在应用层声称的，无法伪造 |

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
| `-send PATH -to EMAIL [-via direct\|relay] [-parallel N]` | 把文件/目录发给另一个订阅端并退出，`-via` 默认 `direct`，`-parallel` 默认 1（见"文件传输"） |

> 订阅端(客户端)**没有命令行参数**，`connect`/`user`/`pass`/`key`/`email`/`subscribe`/`forward` 都只能写在配置文件里；同时订阅多台 server 也只能用 `websocket.clients[]`。所以裸 TCP 转发（依赖 `forward`）和订阅端相关配置只能用配置文件。

## 常见坑

- **`user`/`pass` 两端不一致** → 订阅端 token 校验失败、连不上。`pass` 必须两端都配（旧文档示例曾漏配订阅端 `pass`）；订阅端的 `user` 要能在服务端 `server.users` 里查到、且该条没设 `disable: true`，否则报 `user err`。
- **`email` 对不上** → 裸 TCP 转发时服务端日志 `no forward ... no subscriber for email ...`。服务端 `server.forward.email` 必须等于某订阅端的 `client.email`。
- **时钟漂移 > 300s** → 鉴权失败，订阅端会收到 `xtime err: your clock differs from the server by Ns ...`（带实际时差）。保证两端时间同步，或**改用密钥对鉴权**（见上），那套不看时钟。
- **被服务端 `allowIP` 挡掉** → 订阅端日志 `ws connect err: ... (server replied 403 Forbidden ...)`。注意 IPv6 地址会轮换（RFC 4941 临时地址），白名单建议写前缀网段而不是单个地址。
- **订阅端只认白名单**：只 dial 自己 `forward` 里写死的 `target`，未映射的 `port` 直接拒绝——服务端入口端口被人乱连也打不进内网。**`forward[].port` 填的是服务端 `forward.listen` 的入口端口号**（比如 `:2224` 就填 `2224`），不是内网真实服务的端口（比如 RDP 的 `3389`）——两者混淆是最常见的配错。这条拒绝的原因会经 `METHOD_CLOSE` 带回服务端，体现在服务端 `nat forward closed ... reason=peer close: no forward target for entry port N` 这一行里，不用再去订阅端本地日志找；老版本 anyproxy 没有这个回传，服务端只看得到症状（`up=19 down=0 dur=0s reason=...connection reset by peer`，客户端发了握手包却什么都没收到，很快自己断开）。
- **UDP 中继的第一个包会慢一拍**：上行是收到第一个数据报才建的，头一个包要等 B→C→B 一个来回。RDP 会自己重试，不用管；自己写的 UDP 应用如果不重试就要注意。
- **UDP 中继只在 `protocol: udp|both` 时才起**：默认 `tcp`，光配 `client.forward` 是不够的，入口那条规则也得写 `protocol`。
- **路径 A 的 `CONNECT` 不支持**：HTTP 头订阅路径只处理非 `CONNECT` 的 HTTP 请求。
- **直连打洞失败没有中继回落**：A 的入口连接会直接被关掉，日志打 `nat direct entry ... failed: no path to <email>: <每条候选卡在哪>`。这是设计如此，不是 bug——直连和中继是两条独立路径，互不兜底；要经中继就配 `server.forward`，不要指望 `direct` 失败会自动退回去。
- **`-send` 打洞失败同理，退出码非零、一个字节都不传**：常见原因是双方都在严格 NAT/CGNAT 后面、三类候选（反射器 v4/v6、端口映射）全部失败——终端上会打印 `send: direct connect to <email> failed, nothing was sent: ...`，带着每条候选的失败原因。
- **收文件的一端没配 `receive.dir`**：发送端会收到 `peer does not accept files (websocket.client.receive.dir is not set)` 并非零退出；这不是打洞失败，是对端明确拒绝，检查 C 的配置而不是查网络。
- **`receive.allow` 里 email 对了，但 `uuid` 没抄对**：直连报 `email %s is not in websocket.client.receive.allow, or its uuid does not match`；中继因为 uuid 直接是加密密钥，对不上会在解密阶段失败（错误信息不会明说"uuid 不对"，因为中继路径这一步本来就无法区分"密钥错"和"数据被篡改"，两者都必须一律拒绝）。去发送方的启动日志确认 `websocket.client.uuid` 到底是什么，跟接收方 `receive.allow[].uuid` 逐字比对。
- **`receive.allow` 留空**：现在语义是"谁都不接受"，不是旧版的"不限制"——uuid 缺失时没法做身份比对，也没法给中继派生密钥，没有"不限制"这个选项了，必须显式配对方。

## 示例

见 [config-examples.md](config-examples.md) 第 8 节（8.1 HTTP 头订阅、8.2 裸 TCP 内网穿透）。
