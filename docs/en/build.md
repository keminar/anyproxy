# Build and cross-compilation

anyproxy is pure Go (`CGO_ENABLED=0`); a single machine can cross-compile static binaries for each platform/architecture.

## Using the build script

```bash
# Linux/macOS: scripts/build.sh <target>
./scripts/build.sh all        # All targets
./scripts/build.sh linux      # A single target (see table below)
./scripts/build.sh mips       # Router mips + mipsle

# Windows: double-click or run build.bat in cmd/PowerShell (only windows/amd64)
build.bat
```

The script uses `-trimpath` (does not embed the local source path) and injects the version number / Git commit via `-ldflags` (visible with `anyproxy -v`). Output goes to `dist/`.

## Target list

| `build.sh` param | GOOS / GOARCH | artifact | note |
|-----------------|---------------|----------|------|
| `linux` | linux / amd64 | `anyproxy-amd64-<VER>` | regular 64-bit Linux |
| `alpine` | linux / amd64 (`-tags netgo`) | `anyproxy-alpine-amd64-<VER>` | pure-Go DNS resolution, for musl/Alpine, containers |
| `mac` | darwin / amd64 | `anyproxy-darwin-amd64-<VER>` | macOS |
| `windows` | windows / amd64 | `anyproxy-windows-amd64-<VER>.exe` | also copy the `.dll`/`.sys` from `WinDivert-2.2.2-A/` into `dist/` (TUN mode requires it in the same dir as the exe) |
| `mips` | linux / mips + mipsle (`GOMIPS=softfloat`) | `anyproxy-mips`, `anyproxy-mipsle` | MIPS devices such as routers, see below |

`all` builds all of the above in sequence.

## Routers (MIPS)

MIPS devices (OpenWrt routers, some NAS/boxes) produce two binaries, differing in **CPU byte order**, and are **not interchangeable**:

| artifact | GOARCH | byte order | typical chip |
|------|--------|--------|----------|
| `anyproxy-mips` | `mips` | **big-endian (MSB)** | Atheros/Qualcomm AR71xx·AR9xxx, most Broadcom |
| `anyproxy-mipsle` | `mipsle` (le=little-endian) | **little-endian (LSB)** | Ralink/MediaTek MT7620·7628·7621, etc. |

### How to choose big-endian / little-endian

On the target device, check the byte order of an existing executable:

```sh
file /bin/busybox
#  ...MSB...  → big-endian → use anyproxy-mips
#  ...LSB...  → little-endian → use anyproxy-mipsle
```

Or read `cat /proc/cpuinfo` to identify the chip model. Choosing wrong gives "illegal instruction / segmentation fault" and won't run; if unsure, copy both and try each — the one that runs is correct.

### Why `GOMIPS=softfloat`

Most MIPS routers have **no hardware floating-point unit (FPU)**, and Go's default `hardfloat` would crash on the device with an illegal instruction. Using `softfloat` (software floating point) has the widest compatibility and is the standard practice for router scenarios. If you confirm the device has an FPU, you can drop `GOMIPS=softfloat` and use the default hardfloat (slightly smaller/faster).

### Deploy to router

```sh
# After transferring up (scp/USB, etc.)
chmod +x anyproxy-mipsle
./anyproxy-mipsle -c router.yaml
```

Router memory/file-handle limits are tight, note:
- TUN global proxy requires root; on OpenWrt configure routing manually per [tun-features.md](tun-features.md) or use autoRoute.
- Lower `loopGuard.minActive` on low-end devices (see [multi-instance-loop.md](multi-instance-loop.md)), and reduce the connection count appropriately.

## Manual cross-compilation (without the script)

```bash
# General form
CGO_ENABLED=0 GOOS=<os> GOARCH=<arch> [GOMIPS=softfloat] \
  go build -trimpath -o anyproxy-<tag> .

# Example: ARM router / Raspberry Pi
CGO_ENABLED=0 GOOS=linux GOARCH=arm   GOARM=7 go build -trimpath -o anyproxy-armv7 .
CGO_ENABLED=0 GOOS=linux GOARCH=arm64        go build -trimpath -o anyproxy-arm64 .
# Example: MIPS 64-bit
CGO_ENABLED=0 GOOS=linux GOARCH=mips64le GOMIPS64=softfloat go build -trimpath -o anyproxy-mips64le .
```

> Windows targets additionally require putting `WinDivert.dll` + `WinDivert64.sys` (plus `WinDivert32.sys` on 32-bit) in the same dir as the exe, or specify it via `tun.windows.windivertDir`, see [windows-winDivert.md](windows-winDivert.md). Other platforms have no extra runtime dependencies.

## Binary size

linux/amd64, `CGO_ENABLED=0`, measured with the same Go toolchain (unstripped):

| version | size | vs. previous |
|------|------|-----------|
| v1.9 | 11.8 MB | - |
| v2.0 | 15.7 MB | +3.8 MB |
| 2.1 | 19.3 MB | +3.7 MB |

Both increases correspond to real new features, not accidental bloat:

- **v1.9 → v2.0**: added `gvisor.dev/gvisor` user-space TCP/IP stack, used by `mode=tun` to parse TUN NIC traffic on Linux/macOS (Windows uses WinDivert, unaffected, tiny increment).
- **v2.0 → 2.1**: added `github.com/quic-go/quic-go` (incl. indirect deps like `golang.org/x/crypto`), used by the `nat` module's file-transfer feature for QUIC hole-punching/relaying.

Size has no impact on functionality. To slim down, add `-ldflags "-s -w"` at build time (strip the debug symbol table/DWARF) — measured to cut another ~30% (e.g. 2.1 from 19.3MB to 13.4MB), at the cost of losing symbol info: function names in panic stacks become unreadable, and you can no longer use `delve`/`addr2line` to locate crash addresses; the version number etc. injected via `-X` ldflags variables are unaffected. The current `build.sh`/`build.bat` do not add this option.

## Related

- Run/deploy see [deployment.md](deployment.md), [usage.md](usage.md).
- Notes on `-trimpath` and binaries not containing the local path see the build script comments.
