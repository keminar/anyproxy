# Windows WinDivert 运行依赖

Windows 上 anyproxy 的全局代理(`mode: tun`)改用 **WinDivert** 在网络层劫持数据包
(取代旧的 wintun 虚拟网卡)。运行前需满足:

## 1. 放置驱动文件

把本目录下的两个文件与 `anyproxy.exe` **放在同一目录**:

- `WinDivert.dll`
- `WinDivert64.sys`（64 位 Windows；32 位系统另需 `WinDivert32.sys`）

程序启动时会做 preflight 检查，缺文件会打印缺失的**绝对路径**。

## 2. 以管理员身份运行

WinDivert 需要加载内核驱动，必须**以管理员权限**启动 `anyproxy.exe`，否则会报
`access denied — run as Administrator`。

## 3. 路径避免空格 / 非 ASCII

WinDivert 通过绝对 ImagePath 注册 `.sys` 驱动，路径含**空格或中文**常导致驱动加载
失败(表现为 `file not found`，即使文件存在)。建议放到纯英文、无空格的路径，如 `C:\anyproxy`。

## 行为说明(与 Linux/macOS 的差异)

- **TCP(80/443)**：透明重定向到本地端口，复用 anyproxy 的 `router.yaml` 路由/上游逻辑。
- **DNS(UDP/53)**：继续按 hosts 配置劫持解析(命中 `ip` 返回该 IP、`target=deny` 返回
  NXDOMAIN)，未命中放行由系统解析。
- **QUIC(UDP/443)**：仅对命中 hosts `ip` 的目标丢弃，逼其回退 TCP 走代理（`tun.blockQUIC`，默认开）。
- **bypass 模式**：Windows 上无实际意义(WinDivert 集中捕获)，会打印忽略日志。

驱动/加载问题的诊断，见程序启动失败时打印的 WinDivert diagnostics，以及
`https://reqrypt.org/windivert.html`。
