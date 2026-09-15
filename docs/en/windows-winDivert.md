# Windows WinDivert runtime dependencies

On Windows, anyproxy's global proxy (`mode: tun`) uses **WinDivert** to hijack packets at the network layer (replacing the old wintun virtual NIC). Before running, the following must be satisfied:

## 1. Place the driver files

Put these two files in the **same directory** as `anyproxy.exe`:

- `WinDivert.dll`
- `WinDivert64.sys` (64-bit Windows; 32-bit systems additionally need `WinDivert32.sys`)

At startup the program does a preflight check and prints the missing **absolute path** if a file is absent.

## 2. Run as administrator

WinDivert needs to load a kernel driver, so `anyproxy.exe` must be started **with administrator privileges**, otherwise it reports `access denied — run as Administrator`.

## 3. Path avoid spaces / non-ASCII

WinDivert registers the `.sys` driver via an absolute ImagePath; a path with **spaces or Chinese** often causes driver load failure (manifests as `file not found`, even though the file exists). Put it on a pure-English, no-space path like `C:\anyproxy`.

### Use `windivertDir` to specify the driver dir (exe can stay in place)

If `anyproxy.exe` must live in a Chinese/space-containing directory, don't move the exe — put `WinDivert.dll` + `WinDivert64.sys` in a clean path (e.g. `C:\wd`) and point to it via config:

```yaml
mode: tun
tun:
  windows:
    windivertDir: C:\wd     # Dir holding WinDivert.dll + WinDivert64.sys; empty = same dir as exe
```

The program **preloads `WinDivert.dll` by full path** from that dir, and the `.sys` driver is found there too.
Note: `windivertDir` itself must still be a **pure-ASCII, no-space** path, and `.dll` and `.sys` must be in the **same** directory. The startup log's `WinDivert.dll actually loaded from` confirms the actual load location.

## Behavior notes (differences from Linux/macOS)

- **TCP (80/443)**: transparently redirected to a local port, reusing anyproxy's `router.yaml` routing/upstream logic.
- **DNS (UDP/53)**: still hijacked and resolved per hosts config (hit on `ip` returns that IP, `target=deny` returns NXDOMAIN); miss is passed to the system resolver.
- **QUIC (UDP/443)**: only drops targets whose hosts `ip` is hit, forcing fallback to TCP through the proxy (`tun.blockQUIC`, on by default).
- **bypass mode**: removed on Windows (WinDivert captures centrally, no 0/1 route concept). Escape relies on `tun.windows.excludeProcs`/`bypassIPs` + egress source-port ranges, see [windows-windivert-escape.md](windows-windivert-escape.md).

For driver/load diagnostics, see the WinDivert diagnostics printed when the program fails to start, and `https://reqrypt.org/windivert.html`.
