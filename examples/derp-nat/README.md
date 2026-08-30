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
