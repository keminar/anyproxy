# 构建与交叉编译

anyproxy 是纯 Go（`CGO_ENABLED=0`），一台机器即可交叉编译出各平台/架构的静态二进制。

## 用构建脚本

```bash
# Linux/macOS: scripts/build.sh <目标>
./scripts/build.sh all        # 全部目标
./scripts/build.sh linux      # 单个目标(见下表)
./scripts/build.sh mips       # 路由器 mips + mipsle

# Windows: 双击或在 cmd/PowerShell 运行 build.bat(仅出 windows/amd64)
build.bat
```

脚本用 `-trimpath`（不嵌入本机源码路径）并通过 `-ldflags` 注入版本号/Git 提交（`anyproxy -v` 可见）。产物在 `dist/`。

## 目标一览

| `build.sh` 参数 | GOOS / GOARCH | 产物 | 说明 |
|-----------------|---------------|------|------|
| `linux` | linux / amd64 | `anyproxy-amd64-<VER>` | 常规 64 位 Linux |
| `alpine` | linux / amd64 (`-tags netgo`) | `anyproxy-alpine-amd64-<VER>` | 纯 Go DNS 解析，适配 musl/Alpine、容器 |
| `mac` | darwin / amd64 | `anyproxy-darwin-amd64-<VER>` | macOS |
| `windows` | windows / amd64 | `anyproxy-windows-amd64-<VER>.exe` | 另把 `WinDivert-2.2.2-A/` 下 `.dll`/`.sys` 复制到 `dist/`（TUN 模式需与 exe 同目录） |
| `mips` | linux / mips + mipsle（`GOMIPS=softfloat`） | `anyproxy-mips`、`anyproxy-mipsle` | 路由器等 MIPS 设备，见下 |

`all` 会依次构建以上全部。

## 路由器（MIPS）

MIPS 设备（OpenWrt 路由器、部分 NAS/盒子）出两个二进制，区别是 **CPU 字节序**，**不通用**：

| 产物 | GOARCH | 字节序 | 典型芯片 |
|------|--------|--------|----------|
| `anyproxy-mips` | `mips` | **大端 (MSB)** | Atheros/高通 AR71xx·AR9xxx、多数 Broadcom |
| `anyproxy-mipsle` | `mipsle`（le=little-endian） | **小端 (LSB)** | Ralink/联发科 MT7620·7628·7621 等 |

### 怎么选大端/小端

在目标设备上看一个现成可执行文件的字节序：

```sh
file /bin/busybox
#  ...MSB...  → 大端 → 用 anyproxy-mips
#  ...LSB...  → 小端 → 用 anyproxy-mipsle
```

或看 `cat /proc/cpuinfo` 认芯片型号。选错会「非法指令 / 段错误」跑不起来；不确定就两个各拷一次试，能跑的即对。

### 为什么 `GOMIPS=softfloat`

多数 MIPS 路由器**没有硬件浮点单元(FPU)**，Go 默认 `hardfloat` 会在设备上因非法指令崩溃。用 `softfloat`（软件浮点）兼容性最广，是路由器场景的标准做法。若确认设备有 FPU，可去掉 `GOMIPS=softfloat` 换默认 hardfloat（体积/性能略优）。

### 部署到路由器

```sh
# 传上去(scp/优盘等)后
chmod +x anyproxy-mipsle
./anyproxy-mipsle -c router.yaml
```

路由器上内存/句柄有限，注意：
- TUN 全局代理需 root；OpenWrt 上按 [tun-features.md](tun-features.md) 手动配路由或用 autoRoute。
- 低配设备把 `loopGuard.minActive` 调小（见 [multi-instance-loop.md](multi-instance-loop.md)），并适当降低连接数。

## 手动交叉编译（不用脚本）

```bash
# 通用形式
CGO_ENABLED=0 GOOS=<os> GOARCH=<arch> [GOMIPS=softfloat] \
  go build -trimpath -o anyproxy-<tag> .

# 例：ARM 路由器/树莓派
CGO_ENABLED=0 GOOS=linux GOARCH=arm   GOARM=7 go build -trimpath -o anyproxy-armv7 .
CGO_ENABLED=0 GOOS=linux GOARCH=arm64        go build -trimpath -o anyproxy-arm64 .
# 例：MIPS 64 位
CGO_ENABLED=0 GOOS=linux GOARCH=mips64le GOMIPS64=softfloat go build -trimpath -o anyproxy-mips64le .
```

> Windows 目标额外需要把 `WinDivert.dll` + `WinDivert64.sys`（32 位系统再加 `WinDivert32.sys`）与 exe 放同目录，或用 `tun.windows.windivertDir` 指定，见 [windows-winDivert.md](windows-winDivert.md)。其它平台无额外运行时依赖。

## 相关

- 运行/部署见 [deployment.md](deployment.md)、[usage.md](usage.md)。
- `-trimpath` 与二进制不含本机路径的说明见 build 脚本注释。
