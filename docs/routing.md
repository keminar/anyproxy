# 路由与代理规则

本页说明 anyproxy 如何为一条连接决定出口。核心逻辑在 `proto/tunnel.go` 的 handshake 阶段。

## 匹配流程

1. 得到目标域名（普通请求直接有；透明代理/TUN 从首包嗅探 TLS SNI / HTTP Host；嗅不到用 IP）。
2. 按顺序遍历 `hosts`，用每条的 `match` 方式与 `name` 比对域名，**第一条命中**即采用该条规则。
3. 没有命中 `hosts`，使用 `default`。
4. 用命中规则的 `target` / `proxy` / `dns` / `ip` / `port` 决定出口。

## 域名比对方式

推荐用 `name` 的首/尾 `*` 通配，无需再配 `match`（去掉星号的部分记为 X）：

| `name` 写法 | 含义 | 示例（X=`google.com`） |
|----|------|------|
| `google.com` | 完全相等 | 仅 `google.com` |
| `*google.com` | 末尾一致（后缀） | `www.google.com` 命中；`www.google.com.hk` 不命中 |
| `google.com*` | 开头一致（前缀） | `google.com` / `google.com.hk` 命中；`www.google.com` 不命中 |
| `*google.com*` | 子串包含 | 含 `google.com` 的任意位置都命中 |

> YAML 中以 `*` 开头的值需加引号，如 `name: "*google.com"`。

也可显式写 `match`（旧写法，`name` 原样不解析星号，兼容存量配置）：

| `match` | 含义 |
|----|------|
| `contain` | 域名包含 `name` 关键字 |
| `equal` | 域名与 `name` 完全相等 |

优先级：显式 `match` > `name` 首/尾 `*` > `default.match` > `equal`。
`hosts[].match` 与 `name` 都不带星号时才用 `default.match`（默认 `equal`）。

## target（出口策略）

HTTP 用 `hosts[].target`（缺省用 `default.target`，默认 `auto`）；纯 TCP 用 `default.tcpTarget`（默认 `remote`）。

| 值 | 含义 |
|----|------|
| `local` | 本地直连（当前环境出网）。**优先级最高**，即使配了 `proxy` 也直连 |
| `remote` | 走代理（全局代理或该条 `proxy`） |
| `auto` | 先本地 dial，通了走本地；不通则回退 remote（并强制远程 DNS）。适合优化"IP ping 不通"的场景 |
| `deny` | 中断请求，禁止访问 |
| `localport` | 仅 `tcpTarget` 可用：命中 `default.localPort` 的端口走本地直连，其余走代理 |

### auto 的细节

`auto` 是**本地优先**：先本地直连（2s 超时），通了就复用该连接走本地；不通才转 remote（并强制远程 DNS），同时把该域名标记为“直连失败”**短缓存 20s**（有效期内后续请求跳过直连直接走代理，过期再试直连以便恢复）。有些"IP 能连通但收不到数据"的情况 auto 判断不了，需在规则里显式写 `remote`。

> `target` 与 `proxy`、多代理、`local`/`deny` 兜底的**完整判定逻辑**见 [proxy-decision.md](proxy-decision.md)。

### localport 的默认端口

`tcpTarget: localport` 且未配 `default.localPort` 时，默认本地直连端口为 **21(ftp) / 22(ssh)**。一旦配置 `localPort`，则完全以配置为准（覆盖，不追加）。

```yaml
default:
  tcpTarget: localport
  localPort:
    - 22
    - 3306
```

## dns（解析来源）

| 值 | 含义 |
|----|------|
| `local` | 用本机 DNS 解析（默认） |
| `remote` | 由远程代理端解析。**仅当 `target=remote` 有效** |

用途：某些域名本机解析出的 IP 不通，改用远程 DNS 拿到代理端可达的 IP。

> TUN 连接的目标 IP 已由内核路由确定，不再本地重新解析。

## ip（换 IP）

`hosts[].ip` 非空时，强制把目标 IP 替换为该值，等价于本机 hosts 绑定。用于本机解析到的 IP 不通、又拿不到远程 DNS 时手动指定：

```yaml
hosts:
  - name: golang.org
    match: contain
    ip: 216.239.37.1   # 本机解析的 180.97.235.30 不通，手动换一个可达 IP
```

> `ip` 也是 TUN 模式 `blockQUIC` 的判定依据：配了 `ip` 的域名，其 UDP443(QUIC) 会被 drop 以逼客户端回退 TCP。见 [tun-features.md](tun-features.md)。

## port（换端口）

`hosts[].port` 是 `{from, to}` 列表，目标端口等于某个 `from` 时改写为对应 `to`：

```yaml
hosts:
  - name: dev.example.com
    ip: 127.0.0.1
    port:
      - from: 80
        to: 88
```

## proxy 字段

指定该条规则走哪个代理，覆盖全局代理。支持三种协议，**不写 `://` 前缀默认 `tunnel://`**：

- `tunnel://host:port`（默认）
- `socks5://host:port`
- `http://host:port`

### 多代理与后缀操作

- **逗号分隔多个代理**，按顺序取第一个能连通的用：
  ```yaml
  proxy: http://127.0.0.1:8888, http://127.0.0.1:7777
  ```
- **后缀 `local`**：全部自定义代理都连不通时，走本地直连（把代理置空）：
  ```yaml
  proxy: http://127.0.0.1:8888, http://127.0.0.1:7777 local
  ```
- **后缀 `deny`**：全部连不通时中断请求：
  ```yaml
  proxy: http://127.0.0.1:8888 deny
  ```

> 全局代理（`default.proxy` 与命令行 `-p`）也支持完全相同的「多代理 + `local`/`deny` 后缀」写法。
> 普通单代理的全局代理走无探测快路径；一旦配成多代理或带后缀，则每个请求会按连通性挑选（含 300ms 拨号探测），与单域名 `proxy` 行为一致。
>
> **不可用缓存**：某个代理探测失败后会被标记为不可用并缓存 20s，有效期内后续请求对它直接跳过拨号（多代理时立即尝试下一个），不再每次白等 300ms；探测成功则立即清除标记。这样代理挂掉时不会拖慢每个请求，恢复后也能及时重新启用。

### target 与 proxy 的优先级

| target | proxy | 结果 |
|--------|-------|------|
| `local` | 有 | **本地直连**，proxy 被忽略（显式 local 优先级最高） |
| `remote` | 有 | 走该定制 proxy |
| `auto` | 有可用 proxy | **先直连**，直连不通再走该 proxy（本地优先） |
| `remote`/`auto` | 无 | 走全局代理 / auto 自动选择 |
| `deny` | — | 中断请求 |

要点：`auto` 无论代理配在 host 还是全局，都是「先直连、不通再走代理」，不会因为配了 proxy 就强制走代理；想强制走代理请用 `target: remote`。`proxy` 字段只回答"走代理时用哪个代理"。

## allowIP（访问控制）

- 顶层 `allowIP`：全局允许访问的客户端 IP（空=不限制），支持 CIDR。
- `hosts[].allowIP`：限制哪些客户端 IP 能访问该域名。

## 一个综合示例

```yaml
default:
  dns: local
  target: auto        # HTTP 默认 auto
  tcpTarget: remote   # 纯 TCP 默认走代理
  match: equal
  proxy:              # 全局代理留空

hosts:
  # 走本地 8888 代理，连不通则本地直连
  - name: github
    match: contain
    target: remote
    dns: remote
    proxy: http://127.0.0.1:8888 local

  # dial 通就本地，不通转远程
  - name: golang.org
    match: contain
    target: auto
    dns: remote

  # 直接禁止
  - name: google
    match: contain
    target: deny

  # 换 IP + 换端口，仅允许某客户端
  - name: dev.example.com
    ip: 127.0.0.1
    port:
      - from: 80
        to: 88
    allowIP:
      - 172.17.0.12
```
