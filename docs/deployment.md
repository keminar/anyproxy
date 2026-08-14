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

- **TUN 模式需管理员权限**，且需 `wintun.dll`（https://www.wintun.net/ ）：放程序同目录（同架构），或按架构放到 `wintun\<arch>\wintun.dll`（arch: amd64/arm64/x86/arm）。
- `ensureEagerRSS()` 在 Windows 是空操作，**不会 re-exec**。
- **进程管理要盯住真实 PID**：`-daemon` 下父进程 fork 出子进程后立即退出，真正在跑的是子进程（新 PID）。用外部程序（如托盘 UI）启停 anyproxy 时，若按启动时拿到的父 PID 或"按 exe 名扫描"去杀，可能杀错对象、导致"杀不掉"。建议以实际监听进程的 PID 为准，或不加 `-daemon`（交给外部程序做后台隐藏）。
- **优雅停止**：在程序自己的控制台里 `Ctrl+C`（`SIGINT`）能触发 TUN 路由/网卡清理；`taskkill /F` 是强杀，不清理。

## 性能调优

启动前建议把可用文件句柄数调到至少 65535：

```bash
ulimit -n 65535
```

> 与 `loopGuard.minActive` 相关：环路会在全局在传连接数刚过 `minActive` 时被切断，每条连接约占 2 个 fd，故 `minActive×2` 必须远小于 `ulimit -n`，否则会先撞 `too many open files`。见 [multi-instance-loop.md](multi-instance-loop.md)。

其它内核参数（`sysctl`，见 `./anyproxy -h`）：

```
net.core.somaxconn = 1024
net.core.rmem_max = 16777216
net.core.wmem_max = 16777216
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.ip_local_port_range = 2000 65000
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_congestion_control = cubic
```

## 调试

```bash
./anyproxy -debug 2            # 调试级别 0~3
./anyproxy -pprof :5001        # 浏览器访问 http://:5001/debug/pprof/
```
