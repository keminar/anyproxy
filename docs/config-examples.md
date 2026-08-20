# 配置示例（router.yaml）

按场景给出可直接改用的 `conf/router.yaml` 片段。字段含义见 [configuration.md](configuration.md)，路由规则见 [routing.md](routing.md)。

> 约定：示例里 `<上级代理IP>`、`<VPN服务器IP>`、`en0`/`eth0` 等尖括号/网卡名按你的环境替换。TUN 相关配置按系统分块写（`tun.linux` / `tun.darwin` / `tun.windows`），程序按当前系统取对应块。

---

## 1. 最简：本机全局代理，转发到上级代理

本机所有 TCP 流量经 TUN 接管，转发到一个上级 socks5（或 tunnel/http）。三平台通用骨架：

```yaml
listen: :3000
log:
  dir: ./logs/

# 全局默认出口：走上级代理
default:
  target: remote
  tcpTarget: remote
  proxy: socks5://127.0.0.1:10000      # 上级代理，也可用 -p 传参

# 开 TUN 全局代理
mode: tun
tun:
  linux:
    addr: 10.9.0.1/24
    autoRoute: true
    bypassIPs: [<上级代理IP>]           # 上级代理必须直连，否则环路断网
  darwin:
    addr: 10.9.0.1/24
    autoRoute: true
    bypassIPs: [<上级代理IP>]
  windows:
    bypassIPs: [<上级代理IP>]           # Windows 上 bypassIPs = 排除捕获(直连)
```

> 以 **IP** 指定的上级代理（`-p`/`default.proxy`/`hosts[].proxy`）**会自动并入 `bypassIPs`**，上面示例里手动写 `bypassIPs: [<上级代理IP>]` 只是为了直观，可省略。若上级代理是**域名**，程序无法在此确定其 IP，仍需手动把 IP 填进 `bypassIPs`（或改用 IP 指定代理）。

---

## 2. 按域名分流

大部分直连、少数域名走代理、个别禁止。不开 TUN 时用系统代理/浏览器指向 `:3000`；开 TUN 时同样生效。

```yaml
listen: :3000
default:
  target: auto          # 默认：本地能连就本地，不能连转远程
  tcpTarget: remote
  dns: local

hosts:
  # 后缀通配：*.google.com 全走上级 tunnel 代理，远程 DNS
  - name: "*google.com"
    target: remote
    dns: remote
    proxy: tunnel://<上级IP>:3001

  # 指定走本地 8888(如 Charles)，连不通则本地直连
  - name: "*github.com"
    target: remote
    proxy: http://127.0.0.1:8888 local

  # 直接禁止
  - name: "*doubleclick.net"
    target: deny

  # 换 IP + 换端口，仅允许某客户端访问
  - name: dev.example.com
    ip: 127.0.0.1
    port:
      - from: 80
        to: 8080
    allowIP:
      - 172.17.0.12
```

`name` 通配：`*x` 后缀、`x*` 前缀、`*x*` 包含、无星号精确；详见 [routing.md](routing.md)。

---

## 3. Windows：同机跑 OpenVPN（防死循环）

Windows 用 WinDivert，若同机 OpenVPN 走 TCP 传输会被捕获→死循环。把 OpenVPN 进程排除即可：

```yaml
mode: tun
tun:
  windows:
    excludeProcs:
      - openvpn.exe          # 首选：按进程逃逸，与服务器 IP 无关
    bypassIPs:
      - <VPN服务器IP>        # 可选叠加：按 IP 排除捕获
    blockQUIC: true
```

原理与排查见 [tun-dns-vpn-coexist.md](tun-dns-vpn-coexist.md)。

### 3.1 Windows：访问虚拟机 / 内网主机

Windows 上 `tun.windows.bypassPrivate` **不配默认 `true`**：私网/LAN/链路本地（含 VirtualBox/VMware/Hyper-V/WSL2 网段）一律直连、不进引擎，所以访问虚拟机/内网主机**默认就直连**，通常无需额外配置。

只有两种情况才需要动它：

```yaml
mode: tun
tun:
  windows:
    # 想让某个私网目标改按 router 规则走代理时，关掉一刀切直连：
    bypassPrivate: false
    # 再用 bypassIPs 精确放行仍要直连的网段（其余私网则进引擎按规则）：
    bypassIPs:
      - 192.168.56.0/24      # 例：VirtualBox host-only 网段直连
```

- 默认（`bypassPrivate: true`）：整段私网直连，最省心；
- 想**代理某个私网目标**：`bypassPrivate: false`（私网 80/443 进引擎按规则）；
- 想**只精确放行某几段**、其余私网仍按规则：`bypassPrivate: false` + `bypassIPs` 列出要直连的网段。

判定细节见 [windows-windivert-redirect.md](windows-windivert-redirect.md) 的「两条连接与直连判定」。

---

## 4. macOS：这台 Mac 要能被外网 SSH 登录

macOS 无源策略路由，用 pf 放行入站服务端口的回包（需 root）：

```yaml
mode: tun
tun:
  darwin:
    addr: 10.9.0.1/24
    autoRoute: true
    inboundPorts:
      - 22                   # 外网 SSH
      - 443                  # 若这台 Mac 还对外提供 https
    bypassIPs: [<上级代理IP>]
```

> Linux 上入站回包由内置的 `ip rule` 源策略路由**自动**放行，无需配置。Windows(WinDivert) 也无需。

---

## 5. Linux 服务器：iptables 透明全局代理（不用 TUN）

用 iptables 把本机流量重定向到 anyproxy，比 TUN 更适合服务器：

```yaml
listen: :3000
default:
  target: auto
  tcpTarget: remote
  proxy: tunnel://<上级IP>:3001
# 不配 mode，靠 iptables 引流
```

配套 iptables（见 [deployment.md](deployment.md)）：

```bash
sudo useradd -M -s /sbin/nologin anyproxy
sudo iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner anyproxy -j RETURN
sudo -u anyproxy ./anyproxy -daemon
sudo iptables -t nat -A OUTPUT -p tcp -m multiport --dport 80,443 -j REDIRECT --to-port 3000
```

---

## 6. tunneld 服务端

部署在出口服务器，接收 anyproxy 的请求。用 `-mode tunnel` 启动。

```yaml
listen: :3001
token: anyproxyproxyany       # 必须 16 位，两端一致
allowIP:                      # 可选：限制来源
  - 203.0.113.0/24
default:
  target: auto
  tcpTarget: remote
```

启动：`./anyproxy -mode tunnel -c conf/tunneld.yaml`。客户端用 `proxy: tunnel://<本机IP>:3001` 指向它。

---

## 7. tcpcopy：端口转发（如连容器内 mysql）

开启后 hosts 规则失效，`allowIP` 仍有效。

```yaml
watcher: true
listen: 192.168.1.2:3306
allowIP:
  - 192.168.1.2
mode: tcpcopy
tcpcopy:
  ip: 10.0.0.2                # 目标(容器内)
  port: 3306
```

启动：`./anyproxy -c conf/tcpcopy.yaml`。（旧写法 `tcpcopy.enable: true` 仍兼容）

---

## 8. websocket 内网穿透

服务端（公网侧）监听，订阅端（内网侧）**主动回连**。可与代理同进程。有两条转发路径，原理与字段详解见 [websocket.md](websocket.md)。

> `user`/`pass` **两端必须一致**（`pass` 参与 token 校验，订阅端漏配会鉴权失败）；`email` 用于辨别/定位订阅端，本身不参与 token。

### 8.1 HTTP 头订阅转发（按请求头把公网请求送进内网）

公网侧带 `Anyproxy-Action: websocket` 头、且头部命中某订阅端 `subscribe` 的 HTTP 请求，被转发给该订阅端；订阅端用**本机代理**再向内网发起。

```yaml
# 服务端（公网）
websocket:
  server:
    listen: :3002
    user: someuser
    pass: somepass
```

```yaml
# 订阅端（内网另一台/另一进程）
websocket:
  client:
    connect: <服务端IP>:3002
    host: ws.example.com
    user: someuser
    pass: somepass              # 与服务端一致（算 token，必填）
    email: user@example.com     # 定位订阅端
    subscribe:
      - key: X-Env              # 公网请求头命中 key=val 才转发给本端
        val: test
```

### 8.2 裸 TCP 端口转发（SSH 打洞 / 暴露内网 TCP 服务）

服务端起裸 TCP 监听端口，按 `email` 桥接到订阅端，订阅端 dial 写死的内网目标。

```yaml
# 服务端（公网）
listen: off                   # 纯穿透不需要本机代理监听，可关掉（不写则默认 :3000）
websocket:
  server:
    listen: :3002
    user: someuser
    pass: somepass
    forward:
      - listen: :2222         # 公网入口端口（裸TCP监听）
        email: home@example.com # 转发给此 email 的订阅端
```

```yaml
# 订阅端（内网，email 与服务端 forward.email 对应）
listen: off                   # 订阅端做纯裸TCP转发时也不需要本机代理监听
websocket:
  client:
    connect: <服务端IP>:3002
    host: ws.example.com
    user: someuser
    pass: somepass
    email: home@example.com
    forward:
      - port: 2222            # 对应服务端入口端口
        target: 127.0.0.1:22  # 收到该端口的连接就 dial 内网真实目标（本机 sshd）
    # 纯裸TCP转发无需 subscribe：email 命中 forward 规则即允许空订阅
```

用法：`ssh -p 2222 youruser@<服务端IP>` → 打到内网机器的 22。订阅端只会 dial 自己 `forward` 列出的 `target`，未列端口拒绝（天然白名单）。多目标就加多条 `forward`，不同内网机器用不同 `email` 区分。

> `listen: off`（或 `-l off`）关闭本机代理监听，只跑 websocket 后台，适合纯穿透。**注意**：只有「裸 TCP 转发」能这么用；websocket 的「HTTP 头订阅」路径（8.1）依赖本机代理端口，关掉后不生效。

---

## 9. 同机双实例：A 开 TUN + B 作出口（防死循环，Linux）

A 做全局代理并转给同机 B，B 普通模式出口。**B 必须 `mode=bypass` 逃出 A 的 TUN**，否则死循环。
bypass 模式仅 Linux 支持（macOS/Windows 已移除）。

```yaml
# A: conf/a.yaml —— 全局代理，转发给同机 B
mode: tun
tun:
  linux: { addr: 10.9.0.1/24, autoRoute: true, bypassIPs: [127.0.0.1] }
default:
  target: remote
  proxy: socks5://127.0.0.1:11000    # B 的监听
```

```yaml
# B: conf/b.yaml —— 出口，绑物理网卡逃出 A 的 TUN（仅 Linux）
listen: :11000
mode: bypass
tun:
  linux:
    device: eth0                      # 留空则自动探测默认路由网卡
loopGuard:
  minActive: 1000                     # 兜底熔断器，默认已开
  ratio: 80
```

详见 [multi-instance-loop.md](multi-instance-loop.md)。

---

## 附：命令行覆盖

`listen`/`proxy`/`mode` 等可用命令行覆盖配置（命令行优先），便于同一份配置跑不同实例：

```bash
./anyproxy -c conf/router.yaml -l :3001 -p 'socks5://127.0.0.1:10000'
./anyproxy -c conf/router.yaml -mode tun
```

完整参数见 [cli.md](cli.md)。
