# 客户端接入与使用

anyproxy 有三种「把流量交给它」的方式。前两种在 `mode: proxy`（默认）下用同一个监听端口，第三种是全局接管。

## 一、显式代理（同端口 HTTP + SOCKS5，自动识别）

监听端口（默认 `:3000`）上，anyproxy 对每条连接**按首包自动识别协议**（[proto/request.go](../proto/request.go)）：

1. **HTTP 代理**：识别标准方法（`GET/POST/PUT/HEAD/OPTIONS/DELETE/TRACE` 与 `CONNECT`）。HTTPS 走 `CONNECT` 隧道。
2. **SOCKS5 代理**：识别 SOCKS5 握手。
3. 都不是 → 回退**原始 TCP**（供透明代理/TUN 使用，见下）。

也就是说，**同一个 `:3000` 既是 HTTP 代理，也是 SOCKS5 代理**，客户端按需选用即可。

### 怎么把客户端指过来

```bash
# 环境变量(大多数 CLI 工具通用)
export http_proxy=http://127.0.0.1:3000
export https_proxy=http://127.0.0.1:3000
export all_proxy=socks5://127.0.0.1:3000

# curl(HTTP 代理 / SOCKS5 代理二选一)
curl -x http://127.0.0.1:3000   https://example.com
curl -x socks5://127.0.0.1:3000 https://example.com

# git
git config --global http.proxy http://127.0.0.1:3000

# Docker 拉官方镜像(给 dockerd 配代理，或用环境变量)
# 见 README 使用案例1
```

浏览器/系统代理：把 HTTP(S) 代理或 SOCKS5 代理指向 `127.0.0.1:3000` 即可（Chrome 可用 SwitchyOmega 之类的插件按域名切换）。

> 访问控制：入站受 `allowIP`（全局）与 `hosts[].allowIP`（按域名）约束，见 [routing.md](routing.md#allowip访问控制)。本机回环与 TUN 自身流量默认放行。

### HTTP/1.1 keep-alive 多域名复用

一条 HTTP keep-alive 连接上，客户端可能对**不同域名**发多个请求（浏览器/IE 常见）。anyproxy 会按每个请求的实际目标分别路由，而不是把整条连接绑死到第一个域名（[proto/keep.go](../proto/keep.go)、[proto/http.go](../proto/http.go)）。

## 二、透明代理（Linux iptables）

不改客户端配置，用 iptables 把本机出站流量 REDIRECT 到 anyproxy 的监听端口；anyproxy 从 `SO_ORIGINAL_DST` 取真实目标，并从首包嗅探 TLS SNI / HTTP Host 还原域名。配置见 [deployment.md](deployment.md#linux-iptables-全局代理)。

## 三、全局接管（TUN / WinDivert）

`mode: tun`：Linux/macOS 建 TUN 虚拟网卡、Windows 用 WinDivert 网络层重定向，接管几乎所有 TCP。无需逐个客户端配置。详见 [tun-features.md](tun-features.md)、[windows-winDivert.md](windows-winDivert.md)。

## 选哪种？

| 方式 | 客户端要配置吗 | 适用 |
|------|----------------|------|
| 显式代理(HTTP/SOCKS5) | 要（指向 `:3000`） | 单应用/浏览器、容器、CLI 工具 |
| 透明代理(iptables) | 不要 | Linux 服务器整机/某用户的出站 |
| 全局(TUN/WinDivert) | 不要 | 桌面整机全局代理（需管理员/root） |

三种方式命中同一套 `default`/`hosts` 路由规则（[routing.md](routing.md)、[proxy-decision.md](proxy-decision.md)），行为一致。
