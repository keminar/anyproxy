# Windows WinDivert 逃逸机制（环路防护）

本文档专门说明 anyproxy 在 Windows 上如何让自己的出站连接**逃过 WinDivert 捕获**、
避免自环，以及为什么 IPv4 和 IPv6 的处理方式不同。

配套文档：
- [windows-windivert-redirect.md](windows-windivert-redirect.md) — 重定向主链路（捕获→NAT→本地代理→转发）
- [windows-winDivert.md](windows-winDivert.md) — 运行依赖（驱动放置、管理员权限）

## 问题：anyproxy 自己的出站也会被捕获

WinDivert 在 NETWORK 层拦截所有 outbound TCP 80/443 并折叠进本地代理。但
**anyproxy 自己拨出去的连接（Leg 2）** 同样是本机出站、同样是 80/443，无法
与普通应用流量区分。如果不做任何处理：

```
应用 → WinDivert 捕获 → 本地代理 → anyproxy 出站(Leg 2)
                                        ↓
                              WinDivert 再次捕获 → 本地代理 → 出站 → …
                                        ↓ 无限循环
```

这就是"自环"：`app→proxy→egress→重抓→proxy→…`，直到端口池耗尽、连接 RST。
历史上这个环路**只在 IPv6 直连时被稳定复现**，IPv4 却能正常工作——本文解释
原因，以及根治方案。

## 逃逸手段总览（按 process() 判断顺序）

`Engine.process()`（`redirect.go`）对每个捕获的包逐层放行：

| 层 | 机制 | 放行条件 | 代码位置 |
|----|------|----------|----------|
| impostor | 自己注入的回程包 | `addr.Impostor()` | redirect.go:197 |
| 回程 | 代理 → 应用 | `srcPort == ProxyPort` | redirect.go:227 |
| loopback | 直奔本地代理 | loopback 且 `dstPort == ProxyPort` | redirect.go:233 |
| 上游排除 | 到上游代理的连接 | 命中 `SocksExcludeIP:Port` | redirect.go:239 |
| IP 排除 | `tun.bypassIPs` 命中的目标 | `isExcludedIP` | redirect.go:245 |
| **egress 段** | **anyproxy 出站专用源端口段** | **`srcPort ∈ [40001, 49151]`** | **redirect.go:257** |
| SOCKS Guard | 兜底：回退拨号/外部代理进程 | `guard.ownsPort(srcPort)` | redirect.go:263 |
| isDirect | loopback/skipPort/私网 | `isDirect` | redirect.go:296 |

> 前两层（impostor、回程）解决的是"**重定向注入本身**"的再捕获；
> 后几层解决的是"**anyproxy 自己拨号**"的自环。本文聚焦后者。

## 旧方案：SOCKS 层进程 Guard（IPv4 能逃逸的实现）

网络层包不携带进程身份，所以旧方案借用 WinDivert 的 **SOCKET 层**（`LayerSocket`
+ `SNIFF|RECV_ONLY`）——该层为每个 TCP 连接事件上报 **PID**：

1. guard 打开 SOCKET 层，监听连接事件（`socksguard.go` 的 `loop()`）
2. **LISTEN/ACCEPT 发生在代理端口 `:ProxyPort`** → 把该进程的可执行文件名
   学进 `family`（按进程名而非 PID，兼容 GUI+core 分离的代理套件）
3. **CONNECT 来自 family 内进程** → 记录该连接的**本地源端口**到 `egress` map
4. NETWORK 层 `process()` 捕获包时：`guard.ownsPort(p.srcPort)` 命中 → 原样放行

时序上，这条链路依赖一个隐含假设：**SOCKET 层的 CONNECT 事件，必须赶在
SYN 被 NETWORK 层捕获之前被 guard 处理完毕**。IPv4 下实测成立，所以能逃逸。

## 为什么 IPv6 用同一套就失效

竞态的根源是两条处理路径的速度差异：

```
                anyproxy 发起 connect()
                        │
        ┌───────────────┴───────────────┐
        ▼                               ▼
 NETWORK 层 (同步)                 SOCKET 层 (异步)
 SYN 包被捕获 → 立即判断           CONNECT 事件 → 排队
        │                                │
        ▼                                ▼
 process() 查 ownsPort()           guard 查 PID → 解析进程名
 (此刻 egress 表可能还没写入)      → 写入 egress[srcPort]
        │                                │
        ▼                                ▼
  ┌─────┴──────┐                  ┌──────┴──────┐
  │IPv4: guard │                  │IPv6: SYN 先 │
  │先完成→命中 │                  │到→未命中    │
  │→ 放行     │                  │→ 重定向自环 │
  └────────────┘                  └─────────────┘
```

- **NETWORK 层同步**：`Recv()` 捕获到 SYN 的瞬间，`process()` 立刻执行 `ownsPort`
- **SOCKET 层异步**：事件先进 WinDivert 队列，guard goroutine 阻塞在 `RecvSocket()`
  上，读到事件后还要 `QueryFullProcessImageName` 解析进程名（系统调用），**之后**
  才写入 `egress` map

两条路径谁先完成本就不确定。实测结果（`proto/egress.go` 注释原文）：

> The loop was observed **specifically for IPv6 direct connections**, where the
> SOCKET-layer loop guard **loses the race against the outbound SYN and never
> excludes the egress port in time**.

注意是 **never**——IPv6 下不是概率性漏网，而是**系统性输掉竞态**：IPv6 的
CONNECT 事件到达 guard 的时间，总是晚于 SYN 被 NETWORK 层捕获的时间
（Windows 对 IPv6 连接的事件上报时序与 IPv4 不同，具体内核细节未在代码中
记录，但现象稳定可复现）。结果 `ownsPort` 未命中 → `rewriteForward` 把 SYN
折叠回代理 → 代理再拨号 → 再被捕获 → 死循环。

## 新方案：egress 源端口段（确定性识别）

提交 `4a5eec4 "ipv6请求连接逃逸问题"` 引入。思路从"**被动记录**"（等事件来发现
端口）改为"**主动声明**"（拨号前把源端口钉进专用段）：

### 端口空间布局

```
0 ────────── 10000 ──────── 40000 ─── 40001 ────── 49151 ── 49152 ────── 65535
│ 固定/系统  │  NAT 池      │ Egress 段 │ Windows 动态端口（真实应用流量）│
              (引擎伪造的    (anyproxy
               回环源端口)    自身出站专用)
```

| 区间 | 用途 | 冲突？ |
|------|------|--------|
| `[10000, 40000]` | NAT 池：引擎给被重定向连接伪造的环回源端口 | 与 egress 段不重叠 |
| `[40001, 49151]` | **Egress 段**：anyproxy 自身出站专用源端口 | 刻意避开两侧 |
| `[49152, 65535]` | Windows 动态/临时端口（普通应用出站） | 与 egress 段不重叠 |

### 三处配合

**1. 拨号前绑定（`proto/dialer_windows.go` 的 `tunDial`）**

```go
d := &net.Dialer{Timeout: timeout, LocalAddr: &net.TCPAddr{Port: int(nextEgressPort())}}
conn, err := d.Dial(network, addr)
```

- `nextEgressPort()` 在 `[40001, 49151]` 内轮换（`egress.go` 常量）
- 绑定发生在 `connect` 发 SYN **之前**，源端口在包发出时就已确定
- `LocalAddr.IP` 为 nil → 绑定该协议族的通配地址（`0.0.0.0` / `::`），
  **tcp4/tcp6 一套代码通用**
- 绑定冲突（WSAEADDRINUSE）→ 换下一槽位重试，最多 16 次；整段耗尽才回退
  普通拨号（那条可能自环，但被按目标限流器兜住）

**2. NETWORK 层一眼认出（`redirect.go` 的 `process()`）**

```go
if p.srcPort >= proto.EgressPortLo && p.srcPort <= proto.EgressPortHi {
    return true // anyproxy 自己的出站，放行
}
```

读 TCP 头里的源端口做**纯数值比较**，不需要任何异步状态，包到达瞬间即可判定。

**3. SOCKS Guard 降级为兜底**

只兜两种情况：① egress 段耗尽时的无绑定回退拨号；② 通过 `SocksProcessNames`
配置的外部代理进程（不经 anyproxy 拨号器）。

### 为什么这能根治

| 维度 | 旧：SOCKET Guard | 新：egress 源端口段 |
|------|------------------|---------------------|
| 源端口来源 | OS 随机分配，靠异步事件去"发现" | anyproxy 主动绑定到专用段 |
| 识别时机 | 依赖事件先于 SYN 到达 | 绑定在 connect 之前，SYN 发出时端口已定 |
| 识别方式 | 查进程 → 查 map（异步状态） | `srcPort ∈ [40001,49151]` 纯数值判断 |
| IP 版本 | 依赖 SOCKET 层事件时序（IPv6 稳定失败） | 与 IP 版本无关，IPv4/IPv6 完全一致 |

一句话：旧方案靠"SOCKET 事件刚好先到"的运气，IPv6 下运气稳定失效；新方案
把识别变成确定性的端口段判断，不依赖任何时序，IPv6 自环随之根除。

## 关键代码索引

| 文件 | 职责 |
|------|------|
| `proto/egress.go` | `EgressPortLo=40001` / `EgressPortHi=49151` 常量，及设计说明 |
| `proto/dialer_windows.go` | `tunDial`：connect 前把源端口绑进 egress 段，冲突换槽 |
| `tun/wdengine/redirect.go` | `process()`：源端口段检查（主）+ `ownsPort`（兜底） |
| `tun/wdengine/socksguard.go` | SOCKET 层进程 guard：记录/放行代理族出站源端口 |
| `tun/wdengine/pidtable.go` | `GetExtendedTcpTable` 端口→PID 快照（诊断用） |
| `tun/wdengine/procimage.go` | PID → 可执行文件名解析（缓存 + TTL） |

## 相关提交

- `4a5eec4 "ipv6请求连接逃逸问题"` — 引入 egress 源端口段，根治 IPv6 直连自环
