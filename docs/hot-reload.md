# 配置热加载（watcher）

配置文件顶层设 `watcher: true` 后，anyproxy 会监听 `router.yaml` 所在**目录**的文件变化，
改动后自动重载。本文列出哪些配置支持热加载、哪些需要重启。

## 机制

热加载的实现很简单：文件变更时，重新 `LoadRouterConfig` 并**整体替换 `RouterConfig` 指针**
（[utils/conf/config.go](../utils/conf/config.go) 的 `reload`）。因此判定标准只有一条：

- **每次请求/连接都实时读 `conf.RouterConfig.X` 的消费者 → 热加载生效**
- **启动时只读一次、取值到变量或用于初始化的消费者 → 不生效（需重启）**

监听的是目录而非文件本身，以兼容编辑器「写临时文件再 rename 覆盖」的原子保存（否则 Linux 下
inode 变化会导致 watch 失效）。短时间多次事件用 200ms 防抖合并，只重载一次。

> 重载只影响**之后新建的请求/连接**，已在传的连接不受影响。

## 支持热加载（下一个请求/连接起生效）

| 配置 | 参照位置 |
|------|----------|
| `hosts`（全部规则：name/target/dns/proxy/ip/port/allowIP/match） | `proto/tunnel.go`、`utils/dnsutil/dns.go` |
| `default.target` / `dns` / `tcpTarget` / `match` / `localPort` | `proto/tunnel.go`、`proto/websocket.go` |
| `default.proxy` | `proto/tunnel.go`（**仅当启动时未用 `-p` 指定**；用了 `-p` 则固定，命令行优先） |
| `allowIP`（顶层，代理客户端白名单） | `proto/tunnel.go` 的 `isAllowed` |
| `loopGuard.minActive` / `ratio` | `proto/loopguard.go`（每次 `allow()` 实时读） |
| `firstLine.host` / `custom` | `proto/http.go` |
| `token` | `proto/request.go` |
| `tcpcopy.ip` / `port` / `enable` | `proto/request.go`、`proto/tcpcopy.go`（重载会重新归一 `mode: tcpcopy`） |
| `tun.blockQUIC` | `utils/dnsutil/dns.go`（新的 DNS 查询起生效） |
| `websocket.server.users`（含每条的 `disable`） / `allowIP` | `nat/conn.go`（**新接入连接**的鉴权时实时读，`LookupUser` 按 user 查 `users`；已连接不变，改/停用某账号只影响它之后的新连接） |
| `websocket.client.user` / `pass` / `host` / `email` / `subscribe`（含 `clients[]` 数组内同名字段） | `nat/handler.go` 的 `liveAuthCfg`（**下次重连时**生效；`clients[]` 按下标定位对应条目，重载后**数组顺序不要变**，否则可能读到别的 server 的账号） |

## 不支持热加载（启动时确定，需重启）

| 配置 | 原因 |
|------|------|
| `listen` / `network` | 启动时绑定监听。变更靠 **`kill -HUP`（SIGHUP 平滑重启）**生效，watcher 本身不会重新绑定 |
| `log.dir` | 启动时初始化日志 |
| `mode` | 启动时选定 proxy/tunnel/tun/bypass/tcpcopy |
| `tun.*`（除 `blockQUIC`：name/addr/mtu/autoRoute/bypassIPs/bypassPrivate/excludeProcs/inboundPorts/windivertDir/excludeNics/device） | 启动时构建 TUN / bypass |
| `geo` / `geoip` / `geosite` | `loadGeo()` 启动时执行一次；换 `.dat` 需重启 |
| `websocket.server.listen` / `client.connect` / `clients[].connect`（**是否启动**/连**哪台**服务端） | 启动时决定拉起哪些连接；增删条目、改 `connect` 地址都需重启（内部鉴权参数则是热的，见上表） |
| `websocket.server.forward` / `client.forward`（含 `clients[].forward`） | `StartForward` / `buildForward` 启动时各执行一次 |
| `watcher` 自身 | 启动时决定是否开启监听 |

## 三个易混点

1. **`listen` 是「SIGHUP 重启」而非「watcher 热加载」。** 两者是不同路径：改 `listen` 后需
   `kill -HUP <pid>` 触发平滑重启（起新进程接管监听、退旧进程），watcher 只换配置指针、不重绑端口。
2. **websocket 的「参数」热、「是否启动」冷。** `users`/`allowIP` 在新连接/重连时生效，但
   `listen`/`connect` 从空改成有值不会自动拉起服务，需重启。
3. **热加载只对新连接生效**，已在传的连接沿用建立时的配置。
