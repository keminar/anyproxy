# 同机多实例死循环防护

本文档说明同机部署两套 anyproxy 时的死循环成因、根治与兜底方案。

## 场景与成因

同机部署两套 anyproxy：

- **A**：开 `mode=tun`，做全局代理，把请求转给上游 B
- **B**：普通模式，作为出口

```
Client ──▶ A(TUN 全局代理) ──▶ B(出口) ──▶ Internet
                 ▲                    │
                 └──── B 的出向被 A 的 TUN 再次抓走 ───┘   ← 死循环
```

A 的 TUN 会把 `0.0.0.0/1`、`128.0.0.0/1` 全量流量吸进来。A 自己的出向已用绑定物理网卡的方式逃出
TUN，但 **B 的出向流量没逃**，被 A 的 TUN 再次抓走 → A → B → …… 无限循环，句柄不断堆积。

> 同机源 IP 相同，无法用「源 IP=B」或 `ip rule from` 区分 B 的流量；HTTPS/CONNECT 又无法塞
> loop-detection 头部。因此同机场景只能靠下面两层手段。

## 第一层（根治）：B 用 mode=bypass（仅 Linux）

让 B 以 `mode=bypass` 运行，B 的出向连接会绑定物理网卡、逃出 A 的 TUN 路由，从路由层根治环路。
**bypass 模式仅 Linux 支持**；macOS/Windows 已移除（见文末「平台差异」）。

```yaml
# B 的 conf/router.yaml
mode: bypass
tun:
  linux:
    # 自动探测不到物理网卡时手动指定
    device: eth0
```

**务必检查 B 的启动日志**：

```
bypass-only: device="eth0" ip="192.168.1.10" exclude=[...]
```

`device` 与 `ip` 非空才算 bypass 生效。若为空，说明自动探测失败、bypass 会**静默退回普通拨号而失效**，
此时必须用 `tun.linux.device` 手动指定网卡名。

## 第二层（兜底）：loopGuard 熔断器

作为最后防线，防止 bypass 失效时把机器句柄打爆。判定基于**在传连接占比**，而非每秒请求数：

- **便宜的闸门**：仅当整个进程的在传连接数达到 `minActive` 时才启用检查；常态只做一次 `int` 比较，零额外开销
- **占比判定**：闸门开启后，若某个 `host:port` 占用的在传连接超过 `total * ratio%`（句柄都堆在一个目标上＝环路特征），拒绝其新连接
- **自愈**：拒绝新连接后，上游 B 对该目标的连接被 A 拒绝而失败，环路解开，存量连接 drain，闸门自动重新放开，无需熔断计时

```yaml
loopGuard:
  minActive: 1000  # 全局在传连接达到此值才启用占比检查; 0=用内置默认1000(默认开启); <0=关闭
  ratio: 80        # 单目标占全局在传连接的百分比阈值(如80=80%); <=0 用默认80
```

触发时日志形如：

```
loopguard: circuit open for example.com:443 (in-flight 960/1000, suspected proxy loop)
```

loopGuard 是兜底，不是主方案——环路的根治仍靠 B 的 `mode=bypass` 真正生效。

### minActive 与 ulimit -n 的关系（重要）

环路里流量几乎 100% 集中到一个目标，因此环路会在**全局在传连接数刚越过 `minActive` 时**就被切断——
`minActive` 约等于「环路被切断前最多堆积的在传连接数」。每条代理连接约占 **2 个文件描述符**
（客机侧 + 上游侧），所以：

> **`minActive × 2` 必须远小于 `ulimit -n`**，否则进程会先撞 `too many open files`，
> 熔断器根本来不及触发、形同虚设。

- anyproxy 建议 `ulimit -n 65535`（见 `-h` 帮助）。此前提下默认 `minActive=1000`（约 2000 fd）留有充足余量，
  且把误伤阈值提高到「单目标并发 800」，正常的大批量下载/爬取也很难触发。
- **若 ulimit 仍是默认 1024**：`minActive=1000` 会让进程在 ~512 并发时先耗尽 fd，务必把 `minActive`
  调小（如 200），或先按建议抬高 ulimit。

## 平台差异

### loopGuard —— 三平台完全一致

`proto/loopguard.go` 是纯 Go、无 build tag、无系统调用，挂载点也都是跨平台文件。Windows / Mac /
Linux 行为完全相同、默认同样开启。

（`transferConn` 是 TUN 路径，Mac 不支持建 TUN 网卡故不会走到；但普通代理路径 `transfer` 照常计数，
loopGuard 在 Mac 依然有效。）

### bypass —— 仅 Linux；macOS/Windows 已移除

| 平台 | bypass 模式 | 替代方案 |
|------|------------|----------|
| **Linux** | ✅ 支持。`SO_BINDTODEVICE` 按网卡名硬绑，最可靠；自动探测 `ip route show default` | — |
| **macOS** | ❌ 已移除 | 入站服务回包被 TUN 吸走 → `mode=tun` + `tun.inboundPorts`（pf reply-to） |
| **Windows** | ❌ 已移除 | WinDivert 模型无 0/1 路由概念；逃逸靠 TUN 进程的 `tun.windows.excludeProcs`/`bypassIPs` + egress 源端口段（见 [windows-windivert-escape.md](windows-windivert-escape.md)） |

> Linux 上若自动探测失败（`bypass-only: device=""`），用 `tun.linux.device` 手动指定网卡名。
> 另外，Windows/macOS 上 B（anyproxy 进程）的出向仍会被 A 的捕获/路由接管：macOS 无 0/1 路由时不适用；
> Windows 上 B 出向靠 egress 源端口段被 A 天然放行（同为 anyproxy 时），无需 bypass 模式。

## 配置速查

| 配置项 | 默认 | 说明 |
|--------|------|------|
| `mode` | `proxy` | `proxy` / `tunnel` / `tun` / `bypass`（bypass 仅 Linux）；同机 A 用 tun、B 用 bypass |
| `tun.linux.device` | 空(自动探测) | 手动指定物理网卡名（仅 Linux, mode=bypass） |
| `tun.linux.excludeNics` | 平台默认 TUN 名 | 采集直连子网时排除的网卡名（仅 Linux, mode=bypass） |
| `loopGuard.minActive` | 1000 | 在传连接闸门；`<0` 关闭 |
| `loopGuard.ratio` | 80 | 单目标占比阈值(%) |
