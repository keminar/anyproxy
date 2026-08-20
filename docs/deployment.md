# 部署与运维

## 编译

需 Go 环境并设置 GOPROXY：

```bash
# Go >= 1.13
go env -w GOPROXY=https://goproxy.cn,direct

git clone https://github.com/keminar/anyproxy.git
cd anyproxy
make all
```

> 交叉编译各平台/架构（含路由器 MIPS、ARM、Windows 的 WinDivert 复制）见 [build.md](build.md)。

## 启动与后台

```bash
# 前台
./anyproxy

# 后台守护进程（fork 子进程，父进程退出）
./anyproxy -daemon

# 以专用用户启动（配合 iptables owner 规则）
sudo -u anyproxy ./anyproxy -daemon
```

## 平滑重启（Linux）

发送 `SIGHUP`，程序 fork 新进程接管监听 fd，老进程 drain 后退出：

```bash
kill -HUP <pid>
```

> `listen: off`（纯 websocket 穿透，无主监听 fd 可交接）下 `SIGHUP` 也支持，但走的是「**先起新进程、老进程再退出**」：websocket 服务自带绑定重试，老进程退出释放端口后新进程接管，订阅端会自动重连（会有极短暂的连接中断，不是零感知交接）。

## 进程停止与清理

- **普通模式**：`SIGINT`(Ctrl+C) / `SIGTERM` 关闭监听、drain 连接后退出。
- **TUN 模式**：`SIGINT/SIGTERM` 会先取消 context、关闭虚拟网卡、回收 `0.0.0.0/1`+`128.0.0.0/1` 路由再退出。**强杀（`kill -9` / `taskkill /F`）跳过清理**，会残留路由与网卡，需手动删除。

## Linux iptables 全局代理

```bash
# 新建不可登录用户，用它启动 anyproxy，避免自身流量再被转发成环路
sudo useradd -M -s /sbin/nologin anyproxy
sudo iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner anyproxy -j RETURN
sudo -u anyproxy ./anyproxy -daemon

# root 账号本地网段不走代理
sudo iptables -t nat -A OUTPUT -p tcp -d 192.168.0.0/16 -m owner --uid-owner 0 -j RETURN
sudo iptables -t nat -A OUTPUT -p tcp -d 172.17.0.0/16 -m owner --uid-owner 0 -j RETURN
# root 账号 http/https 走代理
sudo iptables -t nat -A OUTPUT -p tcp -m multiport --dport 80,443 -m owner --uid-owner 0 -j REDIRECT --to-port 3000
```

删除规则：

```bash
sudo iptables -t nat -L -n --line-number   # 看行号
sudo iptables -t nat -D OUTPUT 2           # 删 OUTPUT 第 2 条
```

> Linux iptables 透明代理是 Linux 专属功能，Windows/macOS 版精简掉了这部分，改用 TUN 实现全局代理。

## Docker

```bash
docker build -t anyproxy:latest .
docker run anyproxy:latest
docker run -p 3000:3000 anyproxy:latest -p '127.0.0.1:3001'
```

## Windows 注意事项

- **`mode: tun` 需管理员权限**。Windows **不建虚拟网卡**，改用 **WinDivert** 在网络层劫持数据包（取代旧的 wintun）。需把 `WinDivert.dll` + `WinDivert64.sys`（32 位系统另需 `WinDivert32.sys`）与 `anyproxy.exe` 放**同一目录**（路径含空格/中文可能导致驱动加载失败）。详见 [windows-winDivert.md](windows-winDivert.md)。
- `ensureEagerRSS()` 在 Windows 是空操作，**不会 re-exec**。
- **进程管理要盯住真实 PID**：`-daemon` 下父进程 fork 出子进程后立即退出，真正在跑的是子进程（新 PID）。用外部程序（如托盘 UI）启停 anyproxy 时，若按启动时拿到的父 PID 或"按 exe 名扫描"去杀，可能杀错对象、导致"杀不掉"。建议以实际监听进程的 PID 为准，或不加 `-daemon`（交给外部程序做后台隐藏）。
- **停止**：Windows 的 WinDivert 模型不改路由表、不建网卡，退出时关闭 WinDivert 句柄即停止重定向，无路由/网卡残留（与 Linux/macOS 的 TUN 路由清理不同）。

## 性能调优

启动前建议把可用文件句柄数调到至少 65535：

```bash
ulimit -n 65535
```

> 与 `loopGuard.minActive` 相关：环路会在全局在传连接数刚过 `minActive` 时被切断，每条连接约占 2 个 fd，故 `minActive×2` 必须远小于 `ulimit -n`，否则会先撞 `too many open files`。见 [multi-instance-loop.md](multi-instance-loop.md)。

其它内核参数：追加到 `/etc/sysctl.conf` 后执行 `sysctl -p`（完整列表见 `./anyproxy -h`）。含开启 **BBR** 拥塞控制（需内核 ≥ 4.9）：

```bash
cat >> /etc/sysctl.conf << EOF
# TCP BBR congestion control
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# TCP/IP tuning
fs.file-max = 1000000
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 4096
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 524288
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_rmem = 4096 131072 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
EOF
sysctl -p
```

验证 BBR：

```bash
sysctl net.ipv4.tcp_congestion_control   # => net.ipv4.tcp_congestion_control = bbr
lsmod | grep bbr                          # => 含 tcp_bbr
```

也可用内置命令自动检查/应用（仅 Linux）：

```bash
./anyproxy -check          # 对照建议值报告 sysctl/ulimit/BBR 是否达标(只读)
sudo ./anyproxy -check-fix # 一键写入 /etc/sysctl.d/99-anyproxy.conf 并 sysctl -p 应用
```

> `-check-fix` 只处理 sysctl；文件句柄（`ulimit -n`）因环境而异需另配：交互式登录改 `/etc/security/limits.conf`，systemd 服务在 unit 里设 `LimitNOFILE=65535`。

## 调试

```bash
./anyproxy -debug 2            # 调试级别 0~3
./anyproxy -pprof :5001        # 浏览器访问 http://:5001/debug/pprof/
```
