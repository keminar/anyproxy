# 概述与架构

anyproxy 是一个跨平台的 TCP 流量转发器 / 代理。它按域名把每条连接分流：或本地直连，或转发到下一级代理（tunneld / socks5 / http）。既能当 Linux 下的透明代理客户端（配合 iptables 或 TUN 网卡），也能作为服务端（tunneld）接收其它 anyproxy 的请求。

配套文档：

- [命令行参数](cli.md)
- [配置文件参考 router.yaml](configuration.md)
- [路由与代理规则](routing.md)
- [运行模式（proxy / tunnel / tcpcopy / websocket）](modes.md)
- [部署与运维](deployment.md)
- [TUN 全局代理特性](tun-features.md)
- [同机多实例死循环防护](multi-instance-loop.md)

## 能做什么

- **按域名分流**：不同域名走不同出口（本地直连 / 上级代理 / 禁止）。
- **多级转发**：anyproxy → tunneld → socks5 → Internet 任意串联。
- **透明代理**：Linux 用 iptables 重定向，或全平台用 TUN 虚拟网卡（tun2socks 等价物）接管全局流量。
- **域名嗅探**：透明代理只拿得到目标 IP，程序从首包嗅探 TLS SNI / HTTP Host 还原域名，让域名规则生效。
- **内网穿透**：通过 websocket 把 HTTP 请求从公网带回内网（见 [modes.md](modes.md)）。
- **端口转发（tcpcopy）**：把本机端口桥接到另一地址端口（如连容器内 mysql）。
- **流量统计**：上下行分别计数。

## 数据链路

```
+----------+      +----------+      +----------+
| Computer | <==> | anyproxy | <==> | Internet |
+----------+      +----------+      +----------+

# 经服务端 tunneld 出网（跨内网访问）
+----------+      +----------+      +---------+      +----------+
| Computer | <==> | anyproxy | <==> | tunneld | <==> | Internet |
+----------+      +----------+      +---------+      +----------+

# 转发到 socks5
+----------+      +----------+      +---------+      +----------+
| Computer | <==> | anyproxy | <==> | socks5  | <==> | Internet |
+----------+      +----------+      +---------+      +----------+

# 串联
+----------+   +----------+   +---------+   +---------+   +----------+
| Computer |=> | anyproxy |=> | tunneld |=> | socks5  |=> | Internet |
+----------+   +----------+   +---------+   +---------+   +----------+

# websocket 内网穿透
+----------+   +---------+   +-----------+  ws  +-----------+   +---------+
| Computer |=> | Nginx A |=> | anyproxy S|  ==> | anyproxy C|=> | Nginx B |
+----------+   +---------+   +-----------+      +-----------+   +---------+
```

## 一条连接的处理流程

1. **入口**：连接从监听端口（普通/透明代理）或 TUN 虚拟网卡（gVisor 用户态协议栈）进入。
2. **取目标**：普通请求解析出目标域名/IP；透明代理/TUN 只有目标 IP，程序嗅探首包 TLS SNI / HTTP Host 还原域名，嗅探不到则回退按 IP 匹配。
3. **匹配规则**：先按 `hosts` 逐条比对域名（`match` 决定比对方式），命中则用该条规则；否则用 `default`。
4. **决策出口**：由 `target` / `proxy` / `dns` / `ip` / `port` 决定本地直连、走哪个代理、用哪个 DNS、是否改写 IP/端口，详见 [routing.md](routing.md)。
5. **转发**：建立到出口的连接，双向拷贝并统计上下行流量。

## 运行模式总览

模式由单个 `-mode`（或配置 `mode`）决定，四个取值互斥：

| 取值 | 含义 |
|------|------|
| `proxy`（默认） | 客户端/代理模式，仅按监听端口收流 |
| `tunnel` | 服务端 tunneld，带 token 验证，只处理 anyproxy 请求 |
| `tun` | 建 TUN 虚拟网卡做全局代理（需管理员/root） |
| `bypass` | 不建网卡，仅把出向连接绑定物理网卡（逃出同机另一实例的 TUN） |

另有两个独立开关：`tcpcopy`（端口转发模式，开启后 hosts 规则失效）与 `websocket`（内网穿透），见 [modes.md](modes.md)。

## 进程模型（重要）

- **前台运行**：直接启动即前台运行，日志同时输出到 stdout 和日志文件。
- **后台化 `-daemon`**：程序会 fork 一个子进程、父进程立即退出，真正干活的是**子进程（新 PID）**。用外部程序管理 anyproxy 时要注意：`-daemon` 下父进程 PID 转瞬即逝，须以实际运行的子进程 PID 为准。
- **平滑重启（Linux）**：`kill -HUP <pid>` 会 fork 新进程接管监听 fd，老进程 drain 后退出。
- **TUN 清理**：TUN 模式下收到 `SIGINT/SIGTERM` 会先取消 context、关闭虚拟网卡并回收 `0.0.0.0/1`、`128.0.0.0/1` 路由，再退出。**强杀（`kill -9` / `taskkill /F`）不会触发清理**，会残留路由/网卡。
- **Windows**：`ensureEagerRSS()` 为空操作（不 re-exec）；TUN 需管理员权限与 `wintun.dll`。进程停止相关注意事项见 [deployment.md](deployment.md)。
