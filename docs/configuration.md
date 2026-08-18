# 配置文件参考（router.yaml）

配置文件默认路径 `conf/router.yaml`（可用 `-c` 指定）。查找顺序：当前工作目录 `conf/` → 程序目录 `conf/` → 源码目录 `conf/`。

`default` 与 `hosts` 支持热加载（`watcher: true` 时改文件即生效），其余项需重启。

本页按配置段逐项说明。路由语义（`target`/`proxy`/`match`/`dns` 等）的细节见 [routing.md](routing.md)；TUN/bypass/loopGuard 见 [tun-features.md](tun-features.md) 与 [multi-instance-loop.md](multi-instance-loop.md)。

## 顶层

| 字段 | 类型 | 默认 | 说明 |
|------|------|------|------|
| `listen` | string | `:3000` | 监听地址端口，优先级低于 `-l` |
| `network` | string | `tcp` | 监听协议：`tcp`(v4+v6) / `tcp4` / `tcp6` |
| `watcher` | bool | false | 是否监听配置文件变化并热加载 `default`/`hosts` |
| `token` | string | — | 与 tunneld 通信的加密密钥，**必须 16 位长度** |
| `allowIP` | []string | 空=不限制 | 允许访问的客户端 IP，支持 CIDR |
| `mode` | string | `proxy` | 运行模式（五者互斥）：`proxy` / `tunnel` / `tun` / `bypass`（仅 Linux）/ `tcpcopy`，优先级低于 `-mode`。websocket 内网穿透不是 mode 取值，独立开关、与任一 mode 共存 |

## log

| 字段 | 默认 | 说明 |
|------|------|------|
| `log.dir` | `./logs/` | 日志目录 |

## firstLine（HTTP 首行域名处理）

非 CONNECT 的 HTTP 请求，当首行域名与 Host 头相同时是否删首行域名。一般 vue 本地项目要把域名配成 `off`。

| 字段 | 默认 | 说明 |
|------|------|------|
| `firstLine.host` | `on` | 是否带 Host：`on` 带 / `off` 不带 |
| `firstLine.custom` | — | 按域名覆盖：`on`/`off`，其它用默认。**注意**：域名与端口间的冒号改为点，如 `localhost:5173` 写成 `localhost.5173` |

```yaml
firstLine:
  host: on
  custom:
    localhost.5173: off
```

## tcpcopy（端口转发模式）

用 `mode: tcpcopy` 开启（是运行模式之一，与 proxy/tunnel/tun/bypass 互斥）。开启后 **hosts 域名代理规则不再生效**，`allowIP` 仍有效。详见 [modes.md](modes.md#tcpcopy-端口转发)。

| 字段 | 默认 | 说明 |
|------|------|------|
| `mode` | `proxy` | 设为 `tcpcopy` 开启端口转发 |
| `tcpcopy.ip` | — | 转发目标 IP |
| `tcpcopy.port` | — | 转发目标端口 |
| `tcpcopy.enable` | false | **已废弃**，改用 `mode: tcpcopy`；为 true 时向后兼容（等价 `mode: tcpcopy`） |

```yaml
mode: tcpcopy
tcpcopy:
  ip: 10.0.0.2
  port: 3306
```

## geo（geoip/geosite 数据集）

按「类别 → 文件」配置，配了才启用 `hosts` 的 `geoip:xx` / `geosite:xx` 匹配。文件按扩展名区分：`.dat`（protobuf 数据集，取同名类别）或纯文本列表（整文件即该类别）。详见 [geo.md](geo.md)。

| 字段 | 类型 | 说明 |
|------|------|------|
| `geo.ip` | map[类别]文件 | 每个类别一个 geoip 文件（`.dat` 或 CIDR 文本列表） |
| `geo.site` | map[类别]文件 | 每个类别一个 geosite 文件（`.dat` 或域名文本列表，如 `direct-list.txt`） |

```yaml
geo:
  ip:
    cn: ./geoip-cn.dat        # .dat 取 cn 类别; 也可 ./china-cidr.txt(文本)
  site:
    cn: ./direct-list.txt     # 文本域名列表; 也可 ./geosite-cn.dat
hosts:
  - name: geoip:cn
    target: local        # 国内 IP 直连
  - name: geosite:cn
    target: local        # 国内域名直连
```

## default（默认路由，可热加载）

未命中任何 `hosts` 条目时使用。

| 字段 | 默认 | 说明 |
|------|------|------|
| `default.target` | `auto` | HTTP 默认出口：`local`/`remote`/`deny`/`auto` |
| `default.tcpTarget` | `remote` | TCP 默认出口：`auto`/`local`/`remote`/`deny`/`localport` |
| `default.localPort` | 空(默认 21/22) | `tcpTarget=localport` 时走本地直连的端口列表；**一旦配置则完全以此为准（覆盖而非追加）** |
| `default.dns` | `local` | DNS 服务器：`local` 当前环境 / `remote` 远程（仅 `target=remote` 有效） |
| `default.match` | `equal` | 默认域名比对方式：`contain`/`equal`（仅 `name` 无星号且未显式配 `match` 时生效） |
| `default.proxy` | 空 | 全局代理服务器，优先级低于 `-p`；支持多代理与 `local`/`deny` 后缀，见 [routing.md](routing.md#proxy-字段) |

## hosts（域名规则列表，可热加载）

按顺序逐条比对，命中即用该条。字段含义详见 [routing.md](routing.md)。

| 字段 | 说明 |
|------|------|
| `name` | 域名关键字；首/尾 `*` 通配（`*X` 后缀 / `X*` 前缀 / `*X*` 包含 / 无星号精确），详见 [routing.md](routing.md) |
| `match` | 可选，显式指定比对方式：`contain` 包含 / `equal` 完全相等（配了则 `name` 原样不解析星号，兼容旧配置） |
| `target` | `local`/`remote`/`deny`/`auto`（同 default.target） |
| `dns` | `local`/`remote`，仅 `target=remote` 有效 |
| `ip` | 本地解析 IP：命中则强制目标 IP 为该值（换 IP） |
| `port` | 目标端口转换列表，元素为 `{from, to}` |
| `proxy` | 指定代理服务器，支持多值与 `local`/`deny` 后缀，见 [routing.md](routing.md#proxy-字段) |
| `allowIP` | 允许访问该域名的客户端 IP 列表 |

```yaml
hosts:
  - name: github
    match: contain
    target: remote
    dns: remote
    proxy: http://127.0.0.1:8888, http://127.0.0.1:7777 local
  - name: dev.example.com
    ip: 127.0.0.1
    port:
      - from: 80
        to: 88
    allowIP:
      - 172.17.0.12
```

## tun（mode=tun 时生效）

Windows 与 Linux/macOS 底层是两套引擎（Windows=WinDivert 重定向、无虚拟网卡；Linux/macOS=gVisor 虚拟网卡），所以字段的生效范围不同。**推荐按系统分块写**：在 `tun.linux` / `tun.darwin` / `tun.windows` 下各只填该系统用得到的字段，程序按当前系统取对应块（整块覆盖顶层扁平字段）。

```yaml
tun:
  linux:
    addr: 10.9.0.1/24
    autoRoute: true
    bypassIPs: [192.168.199.1]
  darwin:
    addr: 10.9.0.1/24
    inboundPorts: [22]        # 外网 SSH 回包放行(pf)
    bypassIPs: [192.168.199.1]
  windows:
    excludeProcs: [openvpn.exe]  # 逃同机 OpenVPN 死循环
    bypassIPs: [203.0.113.10]
```

> **兼容**：旧的扁平写法（直接在 `tun:` 下写 `name/addr/...`，三平台通用）仍有效；配了对应系统块则以系统块为准。

### 字段与生效平台

| 字段 | 默认 | 生效平台 | 说明 |
|------|------|----------|------|
| `enable` | false | — | **已废弃**，改用顶层 `mode: tun` |
| `name` | 平台默认 | Linux/macOS | 网卡名（Linux `anytun0` / macOS `utunN`）；Windows 无网卡，忽略 |
| `addr` | `10.9.0.1/24` | Linux/macOS | 接口地址 CIDR；Windows 忽略 |
| `mtu` | 1500 | Linux/macOS | MTU；Windows 忽略 |
| `autoRoute` | **true** | Linux/macOS | 自动加/清理路由；`false` 只打印命令；Windows 忽略 |
| `bypassIPs` | 空 | 三平台 | 这些目标直连（Linux/macOS 加 `/32` 路由；Windows 排除捕获）。**以 IP 指定的上级代理（`-p`/`default.proxy`/`hosts[].proxy`）会自动并入，无需手动填**；只有域名指定的代理或 VPN 服务器 IP 等才需要在此手动列出 |
| `blockQUIC` | **true** | 三平台 | drop 命中 hosts(配 ip) 域名的 UDP443，逼 QUIC 回退 TCP |
| `bypassPrivate` | **true** | **仅 Windows** | 私网/LAN/链路本地（含虚拟机/VM 网段、`10/8`、`172.16/12`、`192.168/16`、`169.254/16`）一律直连、不进引擎。显式 `false` 才让私网 80/443 进引擎按 router 规则走；`loopback` 始终直连。Linux/macOS 直连子网靠路由天然直连，无需此项 |
| `excludeProcs` | 空 | **仅 Windows** | 这些进程(exe 名)出向不重定向，逃同机隧道(如 `openvpn.exe`)死循环 |
| `inboundPorts` | 空 | **仅 macOS** | pf reply-to 放行入站服务回包(如外网 SSH 22)。Linux 自动、Windows 无需 |
| `windivertDir` | 空(exe 同目录) | **仅 Windows** | `WinDivert.dll`+`WinDivert64.sys` 所在目录。可把驱动放到无空格/中文的干净路径(如 `C:\wd`)，exe 原地不动，绕开中文/空格路径导致的驱动加载失败 |

详见 [tun-features.md](tun-features.md)、VPN 共存见 [tun-dns-vpn-coexist.md](tun-dns-vpn-coexist.md)。

## bypassLinux（mode=bypass 时生效，仅 Linux）

配置 key 为 `bypassLinux`，与 `mode=bypass` 配套。

| 字段 | 默认 | 说明 |
|------|------|------|
| `bypassLinux.device` | 空(自动探测) | 手动指定绑定的物理网卡名（如 `eth0`） |
| `bypassLinux.excludeNics` | 平台默认 TUN 名 | 采集直连子网时排除的网卡名（通常填另一实例的 TUN 网卡名） |

macOS/Windows 已移除 bypass 模式：macOS 入站回包用 `tun.inboundPorts`；Windows 逃逸靠
`tun.windows.excludeProcs`/`bypassIPs`。详见 [multi-instance-loop.md](multi-instance-loop.md)。

## loopGuard（死循环兜底熔断器）

同机 A(tun)+B(bypass, 仅Linux) 场景下，bypass 失效时的最后防线。默认开启。

| 字段 | 默认 | 说明 |
|------|------|------|
| `loopGuard.minActive` | 1000 | 全局在传连接数达到此值才启用占比检查；`0`=默认1000；`<0`=关闭。需 `ulimit -n` 远大于其 2 倍 |
| `loopGuard.ratio` | 80 | 单目标占全局在传连接的百分比阈值；`<=0` 用默认 80 |

详见 [multi-instance-loop.md](multi-instance-loop.md#第二层兜底loopguard-熔断器)。

## websocket（内网穿透）

服务端需配 `listen`/`user`/`pass`；客户端需配 `connect`/`user`/`email`（缺一不发起连接）。详见 [modes.md](modes.md#websocket-内网穿透)。

| 字段 | 说明 |
|------|------|
| `websocket.listen` | 服务端监听地址端口 |
| `websocket.connect` | 客户端连接的地址端口 |
| `websocket.host` | connect 的域名 |
| `websocket.user` | 认证用户名 |
| `websocket.pass` | 认证密码 |
| `websocket.email` | 用于定位用户，不鉴权 |
| `websocket.subscribe` | 订阅头部信息列表，元素为 `{key, val}` |
