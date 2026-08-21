# websocket 内网穿透

anyproxy 内置一套基于 websocket 长连接的内网穿透：**内网侧主动回连公网侧**，之后公网侧把流量经 websocket 送进内网。适合内网在 NAT 后、没有公网 IP 的场景（远程访问家里/公司的机器、暴露内网服务）。

代码在 [nat/](../nat/) 包；配置在 `router.yaml` 的 `websocket` 段（[utils/conf/router.go](../utils/conf/router.go)）。

## 两个角色

| 角色 | 怎么判定 | 职责 |
|------|----------|------|
| **服务端**（公网侧） | 配了 `websocket.server.listen`（或 `-ws-listen`） | 起 websocket 监听 `/ws`，等订阅端接入；对外接收流量并经 ws 转发 |
| **订阅端**（内网侧） | 配了 `websocket.client.connect` / `websocket.clients[]`（无命令行等价，只能配置文件） | 主动回连服务端、鉴权、订阅；收到服务端来的连接后 dial 内网目标；可同时回连多台服务端，见下文「同时订阅多台 server」 |

一个进程可同时是普通代理 + 服务端/订阅端（同进程复用监听端口）。方向永远是**订阅端 → 服务端**发起长连接。

> **纯穿透不想起代理监听**：把 `listen` 设为 `off`（或 `-l off`），进程只跑 websocket 后台、不绑本机代理端口。适用于只做**裸 TCP 转发**的场景；**HTTP 头订阅路径依赖本机代理端口，关闭后失效**。见文末「配置字段」。

## 两条转发路径

服务端把每条转发标了类型（`nat/message.go` 的 `ConnHTTP` / `ConnTCP`），两路的连接 ID 各自从 1 采番，互不串扰。

### 路径 A：HTTP 头订阅转发（`ConnHTTP`，旧路径）

按 **HTTP 请求头**把公网侧的请求送进某个订阅端，再由订阅端的**本机代理**向内网发起。

```
公网 client ──HTTP 请求(带 Anyproxy-Action: websocket + 命中订阅的头)──▶ 服务端 :3000 代理入口
                                                                        │ 按头部匹配订阅端
                                                                        ▼ (websocket 长连接)
                                            订阅端 ──dial 本机代理 127.0.0.1:ListenPort──▶ 内网目标
```

- 触发：请求经服务端的**代理监听端口**进来，带头部 `Anyproxy-Action: websocket`（`proto/http.go` 的 `response()`）。`CONNECT` 请求不支持这条路径。
- 选订阅端：服务端用请求头去匹配各订阅端的 `subscribe`（`nat/client_hub.go` 的 `GetClient`，`header.Get(key) == val` 命中即选中）。匹配不到就回退普通转发。
- 落地：订阅端收到后 dial **自己的本地代理**（`127.0.0.1:ListenPort`，`nat/handler.go` 的 `dialProxy`），把原始 HTTP 请求原样重放，由订阅端的 router 规则决定后续（直连/再代理）。
- 适合：把「带特定标记的公网请求」定向送进某内网环境走它的代理。

### 路径 B：裸 TCP 端口转发（`ConnTCP`，新路径）

在服务端开一个**裸 TCP 入口端口**，整条 TCP 连接经 ws 桥接到订阅端，订阅端 dial 一个**写死的内网目标**。就是反向隧道，即内网穿透。

```
任意 client ──TCP──▶ 服务端 :2222 (裸TCP监听)
                        │ 按 email 选订阅端
                        ▼ (websocket 长连接)
     订阅端 ──dial 写死的 target 127.0.0.1:22──▶ 内网 sshd
```

- 服务端：`websocket.server.forward[].listen` 每条起一个裸 TCP 监听（`nat/forward.go` 的 `StartForward`/`listenForward`），每个进来的连接按该规则的 `email` 找订阅端（`GetClientByEmail`）桥接。
- 订阅端：`websocket.client.forward[].port → target` 建映射（`nat/forward.go` 的 `buildForward`，每台 server 连接各自一份）。收到服务端「入口端口 Port」来的连接时，dial 对应 `target`；**Port 未在本地映射则拒绝**（`nat/forward.go` 的 `dialForCreate`）——天然白名单。
- 适合：暴露内网 Web/DB 等任意 TCP 服务（如远程 SSH、内网 Web）。

## 配置字段

`websocket` 段（[router.go](../utils/conf/router.go) 的 `Websocket`）按角色分 `server` / `client` 两块：

`websocket.server`（服务端，`WsServer`）：

| 字段 | 说明 |
|------|------|
| `listen` | websocket 监听地址，如 `:3002`（订阅端连它的 `/ws`）。等价 `-ws-listen` |
| `users` | 鉴权账号数组，每条 `{user, pass, disable}`；不同订阅端各用各的账号，可单独停用某个，见下文「多用户鉴权」 |
| `allowIP` | 可接入的客户端 IP 白名单（CIDR/单 IP），为空不限制。按**真实 TCP 来源**（`r.RemoteAddr`）判定，不信任 `X-Real-IP` 等可伪造头部；loopback 始终放行。命中即拒绝、连 upgrade 都不做 |
| `forward` | 裸 TCP 转发入口规则数组（路径 B），每条 `{listen, email}`，见下 |

### 多用户鉴权

服务端只有一种写法：`websocket.server.users` 数组，每项 `{user, pass}`（没有单用户的简写）。只有一个订阅端时也要写成长度为 1 的数组：

```yaml
websocket:
  server:
    listen: :3002
    users:
      - user: dmit
        pass: 1ab2d964
      - user: office
        pass: 9f3c7a21
        disable: true   # 临时停用该账号: 鉴权直接拒绝, 不用删配置/改密码
```

订阅端各自在自己的 `websocket.client.user`/`pass`（或 `clients[].user`/`pass`）填对应账号即可，鉴权时服务端按订阅端发来的 `user` 查 `users` 里对应的账号信息算 token（`nat/conn.go` 的 `serveWs` 调用 `utils/conf/router.go` 的 `WsServer.LookupUser`）。

**停用某个账号**：给对应条目加 `disable: true` 即可，不用删掉整条配置或改密码——`user` 还能查到这条记录，但鉴权会直接拒绝（服务端日志打 `user %s is disabled`，返回给订阅端的错误和"查无此人"一样都是 `user err`，不额外暴露账号是否存在）。这个字段热加载生效（下次订阅端重连时就会被拒），不用重启服务端；订阅端本身仍会按自己的退避策略反复重试，只是连不上。

`websocket.client`（订阅端，`WsClient`）：

| 字段 | 说明 |
|------|------|
| `connect` | 要回连的服务端 ws 地址，如 `<公网IP>:3002`。无命令行等价，只能配置文件 |
| `host` | `connect` 用的 `Host` 头/域名（走 TLS 网关时需要；无则可填服务端 IP） |
| `user` | 鉴权用户，**与服务端一致** |
| `pass` | 鉴权密码，**与服务端一致**；参与 token 计算，漏配会鉴权失败 |
| `email` | 本订阅端身份，用于服务端定位/选择（HTTP 路径辅助、TCP 路径按它匹配 `server.forward.email`）。非空且不参与 token |
| `subscribe` | HTTP 头订阅规则数组，每条 `{key, val}`；路径 A 用 |
| `forward` | 裸 TCP 转发目标规则数组（路径 B），每条 `{port, target}`，见下 |

### 同时订阅多台 server

一个订阅端进程可以同时回连多台 server，每台账号/订阅规则/端口转发表可以完全不同。用 `websocket.clients`（复数，数组）代替单个 `websocket.client`，数组每个元素就是一个完整的 `WsClient` 块（字段同上表）：

```yaml
websocket:
  clients:
    - connect: 1.2.3.4:3002
      host: ws1.example.com   # 可选, 走 TLS 网关时用
      user: someuser
      pass: somepass
      email: home
      subscribe:               # 可选, HTTP 头订阅路径(路径A)用, 裸TCP转发不需要
        - key: X-Env
          val: home
      forward:
        - port: 2222
          target: 127.0.0.1:22
    - connect: 5.6.7.8:3002
      user: anotheruser
      pass: anotherpass
      email: office
      forward:
        - port: 2222          # 入口端口号可以和上一台重复, 互不冲突(各连接独立的转发表)
          target: 192.168.1.10:3389
```

每个元素就是一个完整独立的 `WsClient`（和单个 `websocket.client` 用的是同一个结构体），`host`/`subscribe`/`forward` 这些字段和单块 `client` 写法一样都能用，只是上面第二条示例省略了没写（省略的字段就是空/不启用，不代表不支持）。

`nat.ConnectServer` 对每台 server 各自维护一份独立的 websocket 连接、请求 ID 计数、桥接表(`Bridge`)和端口转发映射（[nat/handler.go](../nat/handler.go) 的 `wsClientConn`），互不串扰；日志每行会带 `[connect地址]` 前缀，方便区分是哪条连接。

**与旧 `client` 字段的关系**：`clients` 与旧的单块 `client` 二选一 —— 配了 `clients` 就只用 `clients`（`client` 被忽略）；不配 `clients` 时退化为旧行为（`client` 块包装成单元素列表）。

`server.forward` 每条（`ServerForward`）/ `client.forward` 每条（`ClientForward`）：

| 字段 | 角色 | 说明 |
|------|------|------|
| `listen` | 服务端 | 裸 TCP 入口监听地址，如 `:2222` |
| `email` | 服务端 | 把该入口端口的连接转发给此 `email` 的订阅端 |
| `port` | 订阅端 | 对应服务端入口端口号（如 `2222`） |
| `target` | 订阅端 | 收到该端口来的连接时 dial 的内网真实目标，如 `127.0.0.1:22` |

## 鉴权与握手

订阅端连服务端的 `/ws`，随后发 `AuthMessage`（`nat/handler.go` 的 `auth`）：

- `token = md5(user | pass | xtime)`，`xtime` 为当前秒级时间戳；
- 服务端（`nat/conn.go`）校验：`email` 非空、`user` 在 `server.users` 里能查到且未被 `disable`（`LookupUser`）、`|now - xtime| <= 300`（防重放，**两端时钟需大致同步**）、`token` 与用**该 user 对应的 pass** 算出的一致；
- 之后订阅端发 `subscribe`（可为空）。若 `subscribe` 为空，仅当该 `email` 命中某条服务端 `forward` 规则时才放行（`isForwardEmail`）——即**纯裸 TCP 转发的订阅端不需要 `subscribe`**。

失败会断开并退避重连（订阅端自带重连循环）。

## 命令行等价

| 参数 | 配置项 |
|------|--------|
| `-ws-listen` | `websocket.server.listen` |

> 订阅端(客户端)**没有命令行参数**，`connect`/`user`/`pass`/`email`/`subscribe`/`forward` 都只能写在配置文件里；同时订阅多台 server 也只能用 `websocket.clients[]`。所以裸 TCP 转发（依赖 `forward`）和订阅端相关配置只能用配置文件。

## 常见坑

- **`user`/`pass` 两端不一致** → 订阅端 token 校验失败、连不上。`pass` 必须两端都配（旧文档示例曾漏配订阅端 `pass`）；订阅端的 `user` 要能在服务端 `server.users` 里查到、且该条没设 `disable: true`，否则报 `user err`。
- **`email` 对不上** → 裸 TCP 转发时服务端日志 `no forward ... no subscriber for email ...`。服务端 `server.forward.email` 必须等于某订阅端的 `client.email`。
- **时钟漂移 > 300s** → `xtime is error` 鉴权失败。保证两端时间同步。
- **订阅端只认白名单**：只 dial 自己 `forward` 里写死的 `target`，未映射的 `port` 直接拒绝——服务端入口端口被人乱连也打不进内网。
- **路径 A 的 `CONNECT` 不支持**：HTTP 头订阅路径只处理非 `CONNECT` 的 HTTP 请求。

## 示例

见 [config-examples.md](config-examples.md) 第 8 节（8.1 HTTP 头订阅、8.2 裸 TCP 内网穿透）。
