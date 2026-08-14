# 运行模式

anyproxy 的运行模式由单个 `-mode` 决定，四个取值互斥：`proxy`（默认）/ `tunnel` / `tun` / `bypass`。此外有两个独立开关：`tcpcopy` 与 `websocket`。

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

建 TUN 虚拟网卡接管全局流量，内部用 gVisor 用户态协议栈解析 TCP 再走代理规则，等价 tun2socks。需管理员/root，Windows 另需 `wintun.dll`。跨平台特性、autoRoute、QUIC 拦截、UDP 行为详见 [tun-features.md](tun-features.md)。

```bash
sudo ./anyproxy -mode tun -p 'socks5://127.0.0.1:10000'
```

## bypass 模式（物理网卡绕行）

不建网卡，只把本进程出向连接绑定物理网卡，用于**同机已有另一个 anyproxy TUN 进程**时，让本进程 `target=local` 的请求逃出对方 TUN 的 `0/1` 路由，避免死循环。详见 [multi-instance-loop.md](multi-instance-loop.md)。

```yaml
mode: bypass
bypass:
  device: eth0   # macOS 必填
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

通过 websocket 把 HTTP 请求从公网带回内网（限 HTTP 的非 CONNECT 请求）。分服务端与客户端两个角色，可与 proxy 模式同进程共存。

- **服务端**：配 `websocket.listen` + `user` + `pass`（或 `-ws-listen`）。接收公网侧带特定头部的请求。
- **客户端**：配 `websocket.connect` + `user` + `email`（或 `-ws-connect`）。未配 `connect`/`user`/`email` 则不发起连接。
- `email` 用于定位/辨别在线用户，不参与鉴权；`subscribe` 为订阅头部信息。

```yaml
websocket:
  # 服务端
  listen: :3002
  user: someuser
  pass: somepass
  # 客户端（另一台/另一进程）
  connect: ws-server-ip:3002
  host: ws.example.com
  email: user@example.com
  subscribe:
    - key: X-Env
      val: test
```

> 典型案例（HTTPS 抓包）：公网把 https 请求打到服务器，服务器解证书加特定头部转到 anyproxy websocket 服务端，本地另起一个 websocket 客户端接收并把 HTTP 请求转发到 Charles。见 [README](../README.md) 使用案例 3。
