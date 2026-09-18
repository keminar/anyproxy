# 命令行参数

用 `./anyproxy -h` 可查看完整帮助。下表为全部启动参数及其配置文件等价项。

| 参数 | 说明 | 配置文件等价项 | 优先级 |
|------|------|----------------|--------|
| `-l ADDRPORT` | 监听地址端口，如 `:3000` 或 `127.0.0.1:3000`；设为 `off`（或 `none`/`-`）**关闭代理监听**，仅跑 websocket/tun 等后台服务（纯内网穿透用） | `listen` | 命令行 > 配置 > `:3000` |
| `-p PROXIES` | 上级代理，如 `tunnel://10.2.2.2:3001` / `socks5://10.2.2.2:3128` / `http://10.1.1.1:80`；支持逗号分隔多代理与末尾 `local`/`deny` 后缀（见 [routing.md](routing.md#proxy-字段)） | `default.proxy` | 命令行 > 配置 |
| `-c FILEPATH` | 配置文件路径，默认 `conf/router.yaml` | — | — |
| `-mode` | 运行模式（互斥）：`proxy`（默认）/ `tunnel`(tunneld 服务端) / `tun`(TUN 全局代理) / `bypass`(物理网卡绕行, 仅 Linux) / `tcpcopy`(端口转发) | `mode` | 命令行 > 配置 |
| `-ws-listen` | websocket 监听地址端口（内网穿透服务端） | `websocket.server.listen` | 命令行 > 配置 |
| `-daemon` | 后台守护进程运行（fork 子进程，父进程退出） | — | — |
| `-debug` | 调试级别 `0/1/2/3`，越大日志越详细 | — | — |
| `-pprof` | pprof 端口，留空关闭；浏览器访问 `http://<port>/debug/pprof/` | — | — |
| `-genconf` | 生成一份带注释的配置模板后退出（新机器上没有配置、不知道格式时用）：内容按 `-mode` 裁剪，输出路径取 `-c`（默认**程序目录**下 `conf/router.yaml`，写 `-` 则打到标准输出）；**已存在的文件不覆盖**，同时会建出默认日志目录 | — | — |
| `-geo-extract` | 从 `.dat` 提取类别成小文件后退出，配 `-geo-in`/`-geo-cat`/`-geo-out`（见 [geo.md](geo.md)） | — | — |
| `-geo-in` / `-geo-cat` / `-geo-out` | geo-extract 的源 `.dat` / 类别(逗号分隔) / 输出路径 | — | — |
| `-v` | 显示编译版本信息 | — | — |
| `-h` | 显示帮助 | — | — |
| `-genkey` | 生成一对 websocket 鉴权密钥并退出（私钥填 `websocket.client.key`，公钥填 `websocket.server.users[].key`） | `websocket.client.key` / `websocket.server.users[].key` | CLI 一次性 |
| `-send PATH` | 把文件/目录发给另一个订阅端并退出（可跟多个路径）；接收端需开 `direct.accept`，端到端加密 | — | CLI 一次性 |
| `-to EMAIL[:subdir]` / `DIR` | `-send`：接收方 email（scp 风格 `:subdir` 落到 `receive.dir/subdir`）；`-recv`：本机存放目录（默认当前目录） | — | CLI 一次性 |
| `-via direct\|relay\|VPS的email` | `-send`/`-recv`：直连打洞(`direct`，打不通直接失败)、经服务端 B 中继(`relay`，无需打洞)，或填一台公网 VPS 的 email（该机需开 `direct.relay`）盲转发中继打洞（双方都在 CGNAT 后无法直连时用，详见 [direct-relay-design.md](direct-relay-design.md)）；均端到端加密 | `websocket.client.direct.relay`(VPS 侧) | CLI 一次性 |
| `-recv EMAIL:PATH` | 从另一个订阅端取回文件/目录并退出（scp 风格，路径相对对方 `receive.dir`） | — | CLI 一次性 |
| `-parallel N` | `-send`/`-recv`：单个大文件按字节区间切最多 N 块并行传（默认 1，小文件不切） | — | CLI 一次性 |
| `-direct-plain-udp` | 直连(NAT 打洞)连接：跳过 quic-go 批量/ECN 快速 UDP 路径，回落逐包 I/O；高丢包、拥塞窗口卡死时尝试 | `websocket.client.direct.plainUdp` | 命令行 > 配置 |
| `-check` | 对照建议值只读检查系统调优（sysctl/ulimit/BBR）并退出 | — | CLI 一次性 |
| `-check-fix` | 一键写入 `/etc/sysctl.d/99-anyproxy.conf` 并 `sysctl -p` 应用推荐内核参数（需 root） | — | CLI 一次性 |

> 文件传输（`-send`/`-recv` 及 `-to`/`-via`/`-parallel`/`-direct-plain-udp`）的完整用法、鉴权与排查见 [websocket.md](websocket.md#文件传输-send--recv--receive)；系统调优（`-check`/`-check-fix`）的完整建议项见 [deployment.md](deployment.md#系统调优)。

## 优先级规则

对于同时能在命令行与配置文件里指定的项（`listen` / `proxy` / `mode` / websocket 等），**命令行参数优先于配置文件**，配置文件优先于内置默认值。TUN 网卡名/地址只能经配置 `tun.name` / `tun.addr` 指定。

## 新机器初始化配置

新机器上还没有 `conf/router.yaml` 时，不用照着文档手抄，先生成一份带注释的骨架再改：

```bash
# 生成到程序目录下的 conf/router.yaml（顺带建出默认日志目录），生成完不带 -c 就能启动
./anyproxy -genconf

# 按运行模式生成（模板只保留该模式用得到的字段）：tunnel 服务端 / tun 全局代理 / tcpcopy 端口转发 …
./anyproxy -genconf -mode tunnel

# 指定输出路径
./anyproxy -genconf -c /etc/anyproxy/router.yaml

# 先看一眼不落盘
./anyproxy -genconf -mode tun -c -
```

模板里只有本模式用得到的字段是打开的，示例规则一律注释掉，生成后直接能启动；改哪几个值会在命令输出的“接下来”里列出来。目标文件已存在时**不覆盖**，直接报错，避免手滑冲掉正在跑的配置。完整字段仍以仓库 [conf/router.yaml](../conf/router.yaml)、[configuration.md](configuration.md) 与 [config-examples.md](config-examples.md) 为准。

## 常用启动示例

```bash
# 前台以普通代理启动（读 conf/router.yaml）
./anyproxy

# 后台运行
./anyproxy -daemon

# 启动 tunneld 服务端
./anyproxy -mode tunnel

# 把请求转给上级 tunneld / socks5
./anyproxy -p 'tunnel://127.0.0.1:3001'
./anyproxy -p 'socks5://127.0.0.1:10000'

# 指定配置文件（端口转发模式）
./anyproxy -c conf/tcpcopy.yaml

# TUN 全局代理（需管理员/root，网卡名/地址经配置 tun.name / tun.addr 指定）
sudo ./anyproxy -mode tun -p 'socks5://127.0.0.1:10000'
```

> 上级代理协议前缀支持 `tunnel://`、`socks5://`、`http://`。**不写 `://` 前缀时默认按 `tunnel://` 处理**（全局 `-p`/`default.proxy` 与 `hosts[].proxy` 一致）。注：`-h` 帮助里"裸地址按 http"的旧描述与当前实现不符，以此为准。详见 [routing.md](routing.md)。
