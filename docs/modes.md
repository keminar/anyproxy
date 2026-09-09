# 运行模式

anyproxy 的运行模式由单个 `-mode`（或配置 `mode`）决定，**取值互斥**：`proxy`（默认）/ `tunnel` / `tun` / `bypass`（仅 Linux）/ `tcpcopy`。

`websocket`（内网穿透）**不是 `-mode` 取值**，而是独立开关——服务端由 `websocket.server.listen`（或 `-ws-listen`）开启；客户端由 `websocket.client.connect` / `websocket.clients[]` 开启（无命令行等价，只能配置文件）。在 mode 判定之前启动，**与任一 mode 同进程共存**（通常搭配默认的 proxy）。

## proxy 模式（默认）

客户端/代理模式。监听端口收流，按 [routing.md](routing.md) 的规则本地直连或转发到上级代理（tunnel/socks5/http）。

```bash
./anyproxy                         # 读 conf/router.yaml
./anyproxy -p 'socks5://127.0.0.1:10000'
```

配合流量接管方式：
- Linux iptables 透明代理，见 [deployment.md](deployment.md#linux-iptables-全局代理)。
- 全平台 TUN 虚拟网卡，见 [tun-features.md](tun-features.md)。

## tunnel 模式（tunneld 服务端）

`-mode tunnel` 启动 tunneld，部署在服务器上，接收 anyproxy 的请求并代理发出，或再转给下一级 tunneld。**带 token 验证，非 anyproxy 请求一概拒绝**。用于跨内网访问资源。

```bash
./anyproxy -mode tunnel
```

- `token`：与客户端 anyproxy 通信的密钥，两端必须一致且**长度为 16 位**。
- 客户端用 `-p 'tunnel://<tunneld-ip>:3001'` 或 `hosts[].proxy: tunnel://...` 指向它。
- 可多级串联：anyproxy → tunneld A → tunneld B → Internet。

## tun 模式（TUN 全局代理）

Linux/macOS 建 TUN 虚拟网卡接管全局流量，内部用 gVisor 用户态协议栈解析 TCP 再走代理规则，等价 tun2socks。**Windows 例外**：不建虚拟网卡，改用 **WinDivert** 在网络层劫持重定向，需 `WinDivert.dll` + `WinDivert64.sys`（见 [windows-winDivert.md](windows-winDivert.md)）。均需管理员/root。跨平台特性、autoRoute、QUIC 拦截、UDP 行为详见 [tun-features.md](tun-features.md)。

```bash
sudo ./anyproxy -mode tun -p 'socks5://127.0.0.1:10000'
```

## bypass 模式（物理网卡绕行，仅 Linux）

不建网卡，只把本进程出向连接绑定物理网卡，用于**同机已有另一个 anyproxy TUN 进程**时，让本进程 `target=local` 的请求逃出对方 TUN 的 `0/1` 路由，避免死循环。**仅 Linux 支持**（macOS/Windows 已移除：macOS 入站回包用 `tun.inboundPorts`，Windows 用 WinDivert 的 `tun.windows.excludeProcs/bypassIPs`）。详见 [multi-instance-loop.md](multi-instance-loop.md)。

```yaml
mode: bypass
tun:
  linux:
    device: eth0   # 留空则自动探测默认路由网卡
```

## tcpcopy（端口转发）

把本机监听端口的连接原样桥接到另一个地址端口。**开启后 hosts 域名代理规则全部失效**，`allowIP` 仍生效。

典型用途：本机是 192 网段、容器内是 10 网段，用本机端口访问容器内的 tcp 服务（如 mysql）。

用 `mode: tcpcopy` 开启（运行模式之一，与 proxy/tunnel/tun/bypass 互斥）。

```yaml
# conf/tcpcopy.yaml
watcher: true
listen: 192.168.1.2:3306
allowIP:
  - 192.168.1.2
mode: tcpcopy
tcpcopy:
  ip: 10.0.0.2
  port: 3306
```

```bash
./anyproxy -c conf/tcpcopy.yaml
# 或命令行指定模式
./anyproxy -c conf/tcpcopy.yaml -mode tcpcopy
```

> 旧写法 `tcpcopy.enable: true` 仍兼容（等价 `mode: tcpcopy`）。

## websocket（内网穿透）

通过 websocket 长连接把流量从公网带回内网，内网侧主动回连。分服务端与订阅端两个角色，可与 proxy 模式同进程共存。有两条路径：**HTTP 头订阅转发**（限非 CONNECT 的 HTTP 请求）和**裸 TCP 端口转发**（内网穿透 / 暴露任意内网 TCP 服务）。原理与字段详解见 [websocket.md](websocket.md)。

- **服务端**：配 `websocket.server.{listen,users}`（或 `-ws-listen`）。`users` 是数组，每条 `{user,pass,disable}`，支持多个订阅端各用各的账号，也能单独停用某个账号。接收公网侧流量。裸 TCP 转发再配 `server.forward[].{listen,email}`。
- **订阅端**：配 `websocket.client.{connect,user,pass,email}`（同时订阅多台 server 用 `websocket.clients[]`，见 [websocket.md](websocket.md)）。未配 `connect`/`user`/`email` 则不发起连接。裸 TCP 转发再配 `client.forward[].{port,target}`。
- 服务端 `users[].user`/`pass` 要与订阅端 `client.user`/`pass` **对应一致**（`pass` 参与 token）；`email` 用于定位/辨别订阅端，不参与 token；`subscribe` 为 HTTP 路径的订阅头部。

```yaml
websocket:
  server:                     # 服务端
    listen: :3002
    users:
      - user: someuser
        pass: somepass
  client:                     # 客户端（另一台/另一进程）
    connect: ws-server-ip:3002
    host: ws.example.com
    user: someuser
    pass: somepass
    email: user@example.com
    subscribe:
      - key: X-Env
        val: test
```

> 典型案例（HTTPS 抓包）：公网把 https 请求打到服务器，服务器解证书加特定头部转到 anyproxy websocket 服务端，本地另起一个 websocket 客户端接收并把 HTTP 请求转发到 Charles。见 [README](../README.md) 使用案例 3。
