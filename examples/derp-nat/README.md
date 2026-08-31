# derp-nat：给 websocket 订阅穿透探路的可行性验证

只是一个独立的可行性验证程序，**不接入 anyproxy 主代码**。目的：验证能否借用 croc v11
的 DERP 打洞机制（`github.com/shayne/derphole`，croc 用的是 `github.com/schollz/derphole`
fork），给 [../../docs/websocket.md](../../docs/websocket.md) 里的 websocket 订阅穿透加一条
"数据面走直连 UDP、不占服务端带宽"的路径。

## 现状 vs 想法

现在 anyproxy 的 websocket 订阅（不管是路径 A 的 HTTP 头订阅还是路径 B 的裸 TCP 转发）**控制面和数据面是同一条连接**：订阅端主动回连服务端，之后所有被转发的流量都经这条 websocket 长连接原样转发，服务端要转发多少内网流量就要吃多少带宽。

设想是：websocket 长连接继续当**控制面**（鉴权、订阅、选路都不变），但每条实际转发的连接建立时，双方用这条已认证的 websocket 通道交换一个 DERP token（就像本程序里手动复制粘贴的那个 token），尝试打洞出一条订阅端 ⇄ 对端的直连 UDP/QUIC 路径；打通了数据就走直连，服务端只剩控制面的心跳量；打不通就照旧退回现在的 websocket 转发，行为不比现状差。

本程序只验证"打洞这一步本身是否可行"，不碰 anyproxy 的连接管理/鉴权/配置。

## 独立 go.mod

这个目录**故意用了自己的 `go.mod`**，没有并入仓库根 `go.mod`。原因：`derphole` 传递依赖了完整的 Tailscale 技术栈（wireguard-go、netlink、DERP 客户端等），`go mod tidy` 后 `go.sum` 会新增近百行、几十个间接依赖——这些和 anyproxy 本体完全无关，不该污染主模块。等真要落地到 `nat/` 包时再决定要不要合并依赖。

## 怎么跑

**关键：两端必须在两个不同的真实网络下测试**（比如你的家庭宽带 + 一台云主机，或者两个不同的 4G/宽带出口）。同一局域网或者同一台机器测试意义不大——同网段本来就没有 NAT 穿透的难度，测不出真实小区宽带/双层 NAT 场景下打不打得通。

```bash
# 机器 A：扮演 anyproxy 的"订阅端"(NAT 内网侧)
cd examples/derp-nat
go run . -mode=listen
# 打印一个 TOKEN，复制给机器 B

# 机器 B：扮演 anyproxy 的"服务端"(公网侧，或另一个不同网络)
go run . -mode=dial -token=<粘贴上面的 TOKEN>
```

跑完两边各自打印一份 `AttachGroupStats`，重点看：

- `path`：`direct` = 真打通了点对点 UDP/QUIC，服务端此后不用转发这条流量的字节；`relay` = 打洞失败，退回 DERP 中继转发字节，效果上等价于现在 anyproxy 走 websocket 转发
- `punch` / `candidate exchange` 阶段耗时：如果长期是 0 或者报错，说明双方 UDP 出站被完全封死（比如公司防火墙只放行 TCP 443）
- `fallback reason`：常见是对称型 NAT 导致端口映射猜不中

`-force-relay=1` 可以强制走纯中继路径，作为"打洞失败时最差情况"的对照组。

**跨机器手动复制粘贴 token 会吃掉超时预算**：`-timeout` 是从进程启动那一刻开始计时的，不是从粘贴 token 那一刻开始。如果你复制 token、切窗口、粘贴这一套动作花了一两分钟，`-mode=listen` 那边的 `Accept()` 预算可能已经所剩无几，会在对端刚 `claimed`/`connected-relay` 时就报 `context deadline exceeded`——这只是超时预算不够，不代表打洞失败。默认已经调到 10 分钟；如果还遇到这种情况，看两边日志的时间戳：只要一边在另一边真正发起 dial **之前**就已经超时退出了，这次结果就不作数，加大 `-timeout` 重跑一次，两边日志里都出现 `connected-direct`（或都稳定停在 `connected-relay` 且不再报错）才是有效结果。

## 本地冒烟测试的结果（同机跑，只验证代码链路，不代表真实 NAT 场景）

在本机同时起 listen/dial 两个进程跑通过一次，仅用于确认代码调用没写错、DERP 公共信令可达、echo 数据确实经打通的连接收发成功：

```
path:              direct
punch:              734ms / 898ms
raw path count:     0
fallback reason:    "raw-selection-timeout"
```

`path: direct` 表示两个进程之间用的 QUIC 连接（`AttachGroup.Connections()` 拿到的那些 `net.Conn`）已经切到了打洞出来的直连 UDP 路径，不是走 DERP 转发字节——这是 croc 里真正决定"是否省服务端带宽"的那个信号。`raw path count: 0` 是另一层更激进的优化（`derphole` 给大文件多流传输额外叠加的批量 UDP 直发路径，本程序只开了 1 条流，用不上它，超时属正常，不代表打洞失败）。

**但这次测试没有跨网络**，双方在同一个网络出口，几乎不存在 NAT 复杂度，不能当作"anyproxy 真实场景下能穿透"的证据——只证明了这条链路本身没写错、能跑通。要判断真实可行性，需要你在两个不同网络（尤其是你实际会部署订阅端的那种家庭/办公网络）上按上面的步骤实测一次，看 `path` 是不是稳定落在 `direct`。

## 依赖公共基础设施

`UsePublicDERP: true` 用的是 Tailscale 运营的公共 DERP 服务器集群，不需要自建；代价是候选交换、打洞失败后的中继转发都经第三方服务器，且受制于对方的可用性/限速策略。真要生产化，可以评估自建 DERP 节点（`derphole`/Tailscale 都支持指定自定义 DERP map）。

## 跨网络实测成功的条件（已验证）

在两个不同真实网络下跨机实测打洞成功（`mode: raw-direct` / `raw path count: 4`，两端 `local`/`remote` 都是真实公网映射地址），前提是下面两条**同时**满足：

**1. 用 `DERPHOLE_DERP_SERVER` 指向自建 derper 节点**

```bash
# 公网机器上起自建 DERP 节点
go run tailscale.com/cmd/derper@v1.96.5 -hostname=<你的域名> -certmode=letsencrypt -a=:443

# 两端测试机都设这个环境变量后再跑 derp-nat
export DERPHOLE_DERP_SERVER=https://<你的域名>
```

`derphole` 读到这个环境变量后会把该节点注册成一个自定义 region（`pkg/derpbind/route.go`），DERP 端口取 URL 里的端口，**STUN 端口固定用默认的 3478**——所以自建节点的防火墙除了 TCP 443，还必须放行 **UDP 3478**，否则候选收集（`candidate gather` 阶段）拿不到公网映射地址，打洞必然失败。

用公共 DERP 集群时曾遇到 `connect derp client: derphttp.Client.Connect connect to https://derp1c.tailscale.com/derp: context deadline exceeded`；自建节点可以绕开这类第三方节点可达性问题。(也可能是下面坑4相同原因，需要绑定host)

**2. 测试机关闭 anyproxy 的 TUN 模式**

TUN 开启（autoRoute 生效）时，derp-nat 作为一个普通第三方进程，它的出站 UDP 会命中 TUN 的兜底策略路由（`tun/route_linux.go` 的 `ip rule pref 120`）被吸进 `anytun0`，由 anyproxy 的 `udpForwarder`（`tun/udp.go`）用另一个 socket 重新发出去。表现是 derp-nat 打印的本地地址变成 TUN 的虚拟地址（如 `local=10.9.0.1:58496`）而不是物理网卡地址。

Linux 上 anyproxy 并**不会**主动丢弃这些包（`udpDirectBlocked` 在非 darwin 平台恒为 false，见 `tun/udp_dynroute.go`），所以打洞不是必然失败、而是**时好时坏**：多出来的这层用户态 NAT 转发（进 TUN → gVisor 解析 → 查/建 session → 从物理网卡重发 → 回包再构造 IP 包写回 TUN）推高了每条 lane 的 RTT 和抖动，网络稍差就压不进 derphole 那 1200ms 的打洞观测窗口（`externalV2RawDirectPunchWait`），报 `raw-punch-insufficient-paths` 回退 manager 模式。

把对端 IP 加进 `bypassIPs` 并不能解决：候选地址是拿**同一个 socket** 去 STUN 探测反射出来的，给对端 IP 开了直连例外、探测流量却仍走 TUN 的话，上报的候选地址和实际发包呈现的公网地址对不上，反而更糟。

## 排查记录：这些诡异报错都是环境干扰，不是打洞本身失败

跟"打洞成不成功"没关系，纯粹是"在装了 anyproxy TUN 模式的机器上测 derp-nat"这个组合本身会踩到的坑，单独整理一下，免得下次又当成打洞失败去分析。下面域名/IP 全部替换成示例值。

### 坑 1：环境变量意外劫持了 DERP 服务器地址

`derphole` 支持 `DERPHOLE_DERP_SERVER` 环境变量指定自定义 DERP 节点(见上面"自建 derper"那节，是我们主动用的功能)。但如果这个变量是**宿主机环境里本来就有的**(比如云厂商在系统里预置了这个变量，给他们自己别的内部工具用)，会在你完全没主动配置的情况下，把 derp-nat 悄悄劫持到一个跟你毫无关系、当前也未必可达的自定义节点上，报错看起来像是打洞环境的问题，其实是环境变量污染：

### 坑 2：Windows 上没有"TUN 帮忙整容 NAT"这个效应

上面"测试机必须关闭 anyproxy TUN 模式"那节说的用户态 UDP 转发(`tun/udp.go` 的 `udpForwarder`)，NAT 表**只按源端口建键、不按目标区分**，相当于把物理网卡背后真实的 NAT 类型在应用层伪装成了 Full-cone——这份代码文件头是 `//go:build !windows`，**Linux 和 macOS 共用同一份实现，Windows 完全没有**。

Windows 用的是 WinDivert 引擎(`tun/wdengine/`)，抓包规则只处理 `udp.DstPort == 53`(DNS)和可选的 `udp.DstPort == 443`(QUIC，且只是丢弃逼回退 TCP)，除此之外的 UDP(包括 derp-nat 打洞用的随机高位端口)根本不会被 anyproxy 碰到，直接走物理网卡原生 NAT 出去。所以同一套 derp-nat 测试，在 Linux/macOS 上开着 TUN 模式测出来的打洞成功率，不能直接套到 Windows 订阅端头上——Windows 上开不开 TUN 对打洞结果没有影响，纯粹看真实路由器的 NAT 类型。

### 坑 3：手动加路由绕过 TUN，打洞反而失败了(实测案例)

内网机器 A(Linux，装着 anyproxy TUN 模式 + `derp-nat -mode=dial`)访问服务器 B(公网 IP 203.0.113.20，`derp-nat -mode=listen`)：

```bash
# A 机器上
sudo ip route add 203.0.113.20 via 192.168.1.1 dev enp3s0   # 加了这条，打洞失败
sudo ip route del 203.0.113.20 via 192.168.1.1 dev enp3s0   # 删掉这条，打洞恢复正常
```

这条路由把"去 B 的流量"从 TUN 默认路由里挖出来，强制走物理网卡直连，看起来应该更容易打洞，实测却相反——正是坑 2 提到的机制：不走 TUN 就没有那层"整容"过的 Full-cone NAT，直接暴露出物理网卡背后路由器真实的(大概率对称型的)NAT，打洞反而更难成功。这跟坑 2 是同一个原理的两个角度，一个是理论(代码怎么写的)，一个是实测(真的复现了)。

### 坑 4：DNS 能解析、ping 能通，但拨自定义 DERP 服务器的 TCP 一直超时

同样是"内网机器开着 anyproxy TUN 模式 + 测试用了自定义 DERP 服务器(`DERPHOLE_DERP_SERVER`)"这个组合下遇到的：

```
[root@example-host derp-nat]$ ./derp-nat -mode=dial -token=<...>
dial: connect custom DERP derp1.example.com:443: connect derp client: derphttp.Client.Connect connect to derp1.example.com:443: dial tcp6 derp1.example.com:443: dial tcp6: lookup derp1.example.com on 198.51.100.53:53: no such host
dial tcp4 derp1.example.com:443: context deadline exceeded

[root@example-host derp-nat]$ ping derp1.example.com
PING derp1.example.com (203.0.113.10) 56(84) bytes of data.
64 bytes from 203.0.113.10: icmp_seq=1 ttl=53 time=163 ms
```

`ping` 能正常解析域名、收到真实回包(163ms，走的是真实公网路径)，但 `dial tcp4` 却是 `context deadline exceeded`(完全没收到回应，不是 `connection refused` 那种明确拒绝)——DNS 和 TCP 这两层在 TUN 模式下走的不是同一套处理逻辑，只看 DNS/ICMP 通不通判断不了 TCP 通不通：

- DNS(UDP/53)走 `tun/udp.go` 的 `dnsRelay`，直接中继真实解析结果
- TCP 连接一旦被 TUN 捕获，会先被 gVisor 用户态协议栈本地接住(`tun/stack.go` 的 `handleTCP`)，再交给 anyproxy 自己的 `proto.ForwardTCP` 去做 SNI 嗅探/路由规则匹配/实际拨号——这中间任何一步卡住(比如没有匹配的路由规则、SNI 嗅探对这个特殊的 TLS 握手识别有问题)，derp-nat 那头看到的现象就是连接一直不进不出，直到自己的 context 超时，跟真实网络可达性没关系

这条**还没有确认到底是哪一步卡住的**(需要在那台机器上开 anyproxy 的 debug 日志、看 `tun capture tcp` 那行日志和 `ForwardTCP` 具体走到哪一步才能实锤)，先记录现象和大致方向，排查建议：

```bash
# 1. 确认 TUN 模式是不是真开着
# 2. 开 anyproxy debug 日志，看这条连接有没有被 tun/stack.go 的 handleTCP 打印出来
# 3. 如果确认是 TUN 模式导致，最直接的绕过方式跟坑 3 类似：
sudo ip route add <derp1.example.com 解析出的真实IP> via <网关> dev <物理网卡>
# 但注意：这样绕过后，UDP 打洞会退回坑 2/3 描述的"没有整容 NAT"状态，两个坑会同时出现，
# 得自己权衡先解决哪个
```

## 注意：`path` 字段在 raw-direct 模式下不可信

`printStats` 里的 `path` 来自 `manager.PathState()`，而这个 `manager` 是走 DERP 做候选协商/控制信令的**另一条并行连接**，和真正承载数据的 raw UDP/QUIC 连接是两回事。raw-direct 握手成功后只会调 `manager.StopDirectReads()` 停掉这条并行通道的读取，并不会把它的 path 状态刷成 direct，所以它的残留值是相对独立甚至偶然的——实测出现过打洞明明成功、一端却显示 `path: relay`，两端还互相矛盾的情况。

**判断打洞是否成功要看 `mode == raw-direct && raw path count > 0`**（再辅以两端打印的 `local`/`remote` 是真实公网地址、echo 数据确实收发成功），不要看 `path`。同理，`logConnAddrs` 只在 raw-direct 模式下打印地址，就是因为 manager 模式下 `RemoteAddr()` 返回的是硬编码哨兵值 `127.0.0.1:1`，读不出任何信息。
