# Windows WinDivert 重定向原理

本文档说明 anyproxy 在 Windows 上通过 WinDivert 实现透明代理的内部机制：
数据包如何被捕获、NAT 重写、交付给本地代理、再恢复原始目的地转发。

运行依赖（驱动文件放置、管理员权限等）见 [windows-winDivert.md](windows-winDivert.md)。

## 架构总览

```
应用程序 (浏览器等)
    │  原始出站包: src=NIC_IP:clientPort → dst=server_IP:443
    ▼
┌─────────────────────────────────────┐
│  WinDivert 内核驱动 (NETWORK 层)     │
│  拦截 outbound TCP (80/443/...)       │
│  拦截 outbound UDP/53 (DNS 劫持)     │
│  拦截 outbound UDP/443 (QUIC 屏蔽)   │
└──────────────┬──────────────────────┘
               │ 捕获的原始包
               ▼
┌─────────────────────────────────────┐
│  Engine.process() (redirect.go)     │
│  解析包 → 判断是否重定向 → NAT 改写  │
└──────────────┬──────────────────────┘
               │ 改写后的包: src=NIC_IP:natPort → dst=NIC_IP:ProxyPort
               ▼
┌─────────────────────────────────────┐
│  本地代理监听 :ProxyPort (proxy.go)  │
│  Accept 连接 → 查 NAT 表恢复目的地  │
│  → proto.ForwardTCP 路由/嗅探/转发   │
└─────────────────────────────────────┘
```

## 重定向流程（逐步）

### 1. WinDivert 捕获出站包

WinDivert 在 Windows 内核网络层注册过滤器，拦截所有 outbound 的 TCP 包
（以及 UDP/53 DNS、UDP/443 QUIC）。过滤器由 `candidateFilters()` 生成，
从最优化的到最简的逐级尝试，确保兼容不同 WinDivert 版本。

非 all-ports 模式下，过滤器只捕获目标端口在 `RedirectPorts`（默认 80、443）
的 TCP 包，以及源端口等于 `ProxyPort` 的回程包（代理→应用的返回流量）。

### 2. process() 判断与分类

`Engine.process()` 对每个捕获的包做分类（redirect.go:193）：

| 判断条件 | 处理 |
|----------|------|
| impostor（自己注入的包） | 直接放行，避免捕获循环 |
| UDP/53 且命中 hosts 劫持 | 本地构造 DNS 应答注入，丢弃原查询 |
| UDP/443 且目标 IP 是 hosts 劫持 IP | 丢弃，逼 QUIC 回退 TCP |
| 源端口 == ProxyPort | 回程包，走 `rewriteReturn` 恢复 |
| 目标端口 == ProxyPort 且是 loopback | 放行（自身流量不重定向） |
| 上游代理地址 | 放行（避免环路） |
| ExcludeIPs 中的地址 | 放行（bypass 配置） |
| socksGuard 认领的源端口 | 放行（anyproxy 自己的出站连接） |
| isDirect（loopback / skipPort / 私网） | 放行 |
| shouldRedirect 且在范围内 | 走 `rewriteForward` 重定向 |

### 3. rewriteForward：出站包 → 本地代理

`rewriteForward()`（redirect.go:324）把应用程序的出站包改写为发往本地代理的包：

```
原始包:  src=NIC_IP:clientPort  →  dst=server_IP:443

改写后:  src=NIC_IP:natPort     →  dst=NIC_IP:ProxyPort
         addr.SetLoopback(true)
```

关键操作：
- **分配 natPort**：从 NAT 表 `[10000, 40000]` 范围内分配唯一端口，
  作为此连接在代理侧的标识
- **改写源端口** → natPort（让代理能通过远端端口反查目的地）
- **改写目的 IP** → `p.srcIP`（即本机 NIC IP，不是 127.0.0.1）
- **改写目的端口** → ProxyPort
- **标记 loopback**：`addr.SetLoopback(true)` 让 WinDivert 走环回路径注入
- **重算校验和**

### 4. 本地代理接收并恢复目的地

`proxyServer`（proxy.go）监听 `:ProxyPort`，Accept 连接后：

1. 从连接的 `RemoteAddr().Port`（即 natPort）查 NAT 表，恢复出：
   - `dstIP` / `dstPort`（原始目的地）
   - `srcIP`（客户端源 IP，用于日志统计）
2. 按目的地 IP 做速率限制（`MaxConnPerDomainPerSec`）
3. 交给 `proto.ForwardTCP`，由 anyproxy 的规则引擎做：
   - SNI/Host 嗅探还原域名
   - router.yaml 规则匹配
   - 直连或转发到上游代理

### 5. rewriteReturn：回程包 → 恢复原始来源

代理返回的数据包（srcPort == ProxyPort）需要改写回"看起来来自原始服务器"：

```
原始回程:  src=NIC_IP:ProxyPort  →  dst=NIC_IP:natPort

改写后:   src=server_IP:443      →  dst=NIC_IP:clientPort
          addr.SetLoopback(false)
          addr.SetOutbound(false)  (注入为入站包)
          addr.SetIfIdx(...)       (恢复到原始网卡)
```

应用程序看到的连接，就像是在直接和 server_IP:443 通信。

## 为什么监听 `:port` 而不是 `127.0.0.1`

这是 WinDivert 重定向机制的核心设计决定。

### 原因

`rewriteForward` 把目的 IP 改写为 **原始包的源 IP**（即本机 NIC IP），
而不是 `127.0.0.1`：

```go
setDstIP(pkt, p.isIPv4, p.srcIP) // loop back to this host
```

因此到达 TCP 协议栈的包，目的地址是类似 `192.168.1.100:ProxyPort`，
而非 `127.0.0.1:ProxyPort`。如果监听器只绑在 `127.0.0.1` 上，
协议栈不会把这些包交给它，连接就建立不起来。

必须绑 `:port`（即 `0.0.0.0:port` / `[::]:port`，全接口 dual-stack）才能接收。

### 为什么不把目的 IP 改写成 127.0.0.1

用 `p.srcIP` 做目的地址有一个关键好处：**天然保留 IP 协议族**。

- 应用通过 IPv4 发起连接 → 源 IP 是 IPv4 → 重写后走 IPv4 协议栈
- 应用通过 IPv6 发起连接 → 源 IP 是 IPv6 → 重写后走 IPv6 协议栈

如果固定改写成 `127.0.0.1`，IPv6 流量无法处理，需要额外加一套 `::1` 逻辑。

用 `p.srcIP` 一行代码同时兼容 IPv4 和 IPv6，无需额外分支判断。

## NAT 表

NAT 表（nat.go）是重定向的核心数据结构，维护"应用程序视角的连接"与
"代理侧的 natPort"之间的映射。

### 数据结构

```
natEntry {
    natPort    uint16      // 代理侧唯一标识 (10000-40000)
    clientPort uint16      // 应用程序的原始源端口
    srcIP      netip.Addr  // 原始源 IP (本机 NIC IP)
    dstIP      netip.Addr  // 原始目的地 IP
    dstPort    uint16      // 原始目的地端口
    ifIdx      uint32      // 网卡索引 (回程注入用)
    subIfIdx   uint32      // 子网卡索引
    last       time.Time   // 最后活跃时间
    closed     time.Time   // 代理连接结束时间 (用于快速回收)
}
```

### 双向查找

| 方向 | 查找键 | 用途 |
|------|--------|------|
| forward（出站） | `clientPort + dstIP + dstPort` | 找到或创建 NAT 条目，分配 natPort |
| lookupNat（回程） | `natPort` | 通过代理连接的远端端口恢复目的地 |

### natPort 范围

- 范围：`[10000, 40000]`，共 30000 个可用
- 刻意低于 Windows 默认动态端口范围（49152-65535），避免与系统自身的
  临时端口冲突
- 采用滚动游标分配，用完一圈从头扫描

### 生命周期与回收

| 事件 | 操作 |
|------|------|
| 首次出站包 | 分配 natPort，创建条目 |
| 后续包 | 更新 `last` 时间 |
| 代理连接结束 (FIN) | `markClosed()`，标记 `closed` 时间，保留条目供 FIN/ACK 握手 |
| RST 包 | `release()`，立即回收 natPort |
| GC 周期 (5s) | 已关闭超过 10s 的条目回收；空闲超过 10min 的条目回收 |

保留已关闭条目一小段是为了让 TCP 关闭握手（FIN → ACK → FIN → ACK）
能正常完成，不会因为过早回收导致回程包找不到映射而被丢弃。

## 环路防护

WinDivert 拦截的是所有 outbound TCP，包括 anyproxy 自己发出的连接。
如果不加防护，会形成死循环：

```
应用 → WinDivert 拦截 → 本地代理 → anyproxy 出站 → WinDivert 拦截 → 本地代理 → ...
```

### 多层防护

| 层 | 机制 | 代码 |
|----|------|------|
| SOCKS Guard | 监听 WinDivert SOCKET 层，记录代理进程的出站源端口，process() 中放行 | socksguard.go |
| 上游排除 | `SocksExcludeIP` / `SocksExcludePort` 排除到上游代理的连接 | redirect.go:299 |
| IP 排除 | `ExcludeIPs`（tun.bypassIPs）排除指定 IP/CIDR | redirect.go:309 |
| loopback 放行 | 目的端口 == ProxyPort 且 loopback 的包直接放行 | redirect.go:232 |
| 速率限制 | `MaxConnPerDomainPerSec` 限制单目的地连接速率，作为最后兜底 | proxy.go:89 |

### SOCKS Guard 工作原理

网络层包不携带进程信息，所以 SOCKS Guard 使用 WinDivert 的 SOCKET 层
（需要较新版本 WinDivert 支持）：

1. 监听 SOCKET 事件（CONNECT / LISTEN / ACCEPT / CLOSE）
2. 当某个进程 LISTEN/ACCEPT 在 ProxyPort 上时，记录其进程名（如 `anyproxy.exe`）
3. 当该进程名发起 CONNECT 时，记录其源端口
4. process() 中检查源端口是否在 egress 集合中，是则放行

支持多进程代理套件（如 GUI + core 分离的 clash），通过进程名而非
单个 PID 来识别整个代理家族。可通过 `SocksProcessNames` 追加额外进程名。

如果 SOCKET 层不可用（旧版 WinDivert），Guard 被禁用，
仅依赖速率限制器作为环路兜底。

## IPv4/IPv6 处理

| 配置 | 行为 |
|------|------|
| `IPv6: true`（默认） | IPv4 和 IPv6 出站包都会被重定向到本地代理 |
| `IPv6: false` | IPv4 正常重定向；IPv6 在范围内但会被**丢弃**（防止绕过代理） |

IPv6 的支持得益于"目的 IP = 源 IP"的设计：
IPv6 出站包的源 IP 是本机 IPv6 地址，重写后目的地址也是本机 IPv6 地址，
天然走 IPv6 协议栈，无需特殊处理。监听器绑 `:port`（dual-stack）同时
接收 IPv4 和 IPv6 连接。

## 涉及的源码文件

| 文件 | 职责 |
|------|------|
| `redirect.go` | WinDivert 捕获循环、包分类、forward/return NAT 改写 |
| `proxy.go` | 本地代理监听器、Accept 连接、查 NAT 表、交付 ForwardTCP |
| `nat.go` | NAT 连接表：分配/查找/回收 natPort |
| `packet.go` | IP/TCP/UDP 包解析与原地改写辅助函数 |
| `socksguard.go` | SOCKS 环路防护：SOCKET 层进程识别 |
| `engineconfig.go` | WinDivert 引擎配置结构体 |
| `dns.go` | DNS (UDP/53) 劫持应答 |
