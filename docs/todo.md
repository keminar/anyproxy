# 待办 / 待确认

来源：PR #22（todo → master）合并前的代码审查。下列是审查发现、但当次未处理、**等待确认后再改**的项。每条给出位置、影响、建议改法与现状。

> 已处理的审查项不在此列（如嗌探超时分档、`-mode` 帮助补 `tcpcopy` 等已改）。

---

## 1. 透明代理(iptables)路径首包嗅探：`Peek(1)` 无读超时

- **位置**：[proto/stream.go](../proto/stream.go) `sniffPeekDomain`（`r.Peek(1)` 处，约 47 行）
- **影响（正确性）**：`sniffPeekDomain` 的首个 `r.Peek(1)` **没有读超时**（超时只在确认是 TLS `0x16` 之后才设）。若用 iptables 把「服务端先说话」的协议(SSH:22 / SMTP:25 / MySQL:3306 / IMAP 等)**全端口**重定向到 anyproxy，客户端在等服务端 banner、不先发数据，`Peek(1)` 会一直阻塞，代理永不拨后端 → **连接卡死**。
  - 触发面窄：文档化的 iptables 只重定向 80/443（客户端先说话），常规部署碰不到；仅「全端口透明代理 + 服务端先说话协议」才会中招。
- **建议改法**：参照 TUN 路径 [proto/forward.go](../proto/forward.go) `sniffClientHead` 的做法——**读之前先 `SetReadDeadline`**，超时即回退按 IP 转发。见下面第 2 条的统一方案，可一并解决。
- **现状**：待确认。

---

## 2. 两条首包嗅探实现分叉；`bufio` 变体较脆弱

- **位置**：[proto/stream.go](../proto/stream.go) `sniffPeekDomain`（bufio `Peek` 变体） vs [proto/forward.go](../proto/forward.go) `sniffClientHead`（读入缓冲再补发，稳健）
- **影响（架构/正确性）**：同一个「嗅探首包取 SNI/Host」功能有两套实现：
  - TUN 路径 `forward.go`：先设超时 → `Read` 读入首包 → 之后把首包**补发**给服务端。稳健。
  - 透明路径 `stream.go`：在共享的 `bufio.Reader` 上 `Peek`，且超时是「后置」的。
  - 除第 1 条的阻塞外，还有一个隐患：ClientHello 分片/慢时 `Peek` 超时，会在 `bufio.Reader` 里**缓存一个 i/o 超时错误**，随后第一次真正读取转发数据时把它返回一次，可能**误伤连接**。
  - 另外，透明路径在嗅探时**还没拿到目标端口**（端口是随后 `GetOriginalDstAddr` 才取），所以它没法像 TUN 路径那样对 80/443 用长超时——443 嗅探目前固定 200ms。
- **建议改法**：把 `stream.go` 的嗅探统一到 `forward.go` 那套「先设超时 → 读首包 → 补发」。一处改动可同时消掉第 1 条（阻塞）、本条（bufio 缓存错误 + 实现分叉），并让透明路径也能按端口用长/短超时。
- **现状**：待确认（改动相对大，涉及透明路径的读取/补发时序）。

---

## 3. `HostBlocksUDP` 在 QUIC 热路径上按 hosts 线性扫描

- **位置**：[utils/dnsutil/dns.go](../utils/dnsutil/dns.go) `HostBlocksUDP`（约 189 行）；调用点 [tun/wdengine/redirect.go](../tun/wdengine/redirect.go) `process()`（约 216 行）
- **影响（效率）**：每个出站 UDP/443 包都会**线性遍历** `conf.RouterConfig.Hosts` 做字符串比较，判断是否要 drop 该 QUIC。hosts 列表大 + QUIC 流量密集时，是捕获快路径上的每包开销。
- **建议改法**：启动/配置热重载时预建一个 `map[string]struct{}`（配了 `ip` 的 host 的 IP 集合），`HostBlocksUDP` 改为 O(1) 查表。
- **现状**：待确认（性能优化，非功能问题；hosts 少时影响可忽略）。

---

## 备注

- 第 1、2 条本质是同一块代码（透明代理路径的嗌探），建议合并成一次改动处理。
- 确认要改哪些后，从本文件移除对应条目。
