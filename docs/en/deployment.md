# Deployment and operations

## Build

Requires a Go environment with GOPROXY set:

```bash
# Go >= 1.13
go env -w GOPROXY=https://goproxy.cn,direct

git clone https://github.com/keminar/anyproxy.git
cd anyproxy
make all
```

> For cross-compilation for various platforms/architectures (including router MIPS, ARM, and Windows WinDivert copying), see [build.md](build.md).

## Start and background

```bash
# foreground
./anyproxy

# background daemon (forks a child process; parent exits)
./anyproxy -daemon

# start as a dedicated user (paired with iptables owner rules)
sudo -u anyproxy ./anyproxy -daemon
```

## Graceful restart (Linux)

Send `SIGHUP`; the program forks a new process to take over the listening fd, and the old process exits after draining:

```bash
kill -HUP <pid>
```

> `listen: off` (pure websocket penetration, no main listening fd to hand over) also supports `SIGHUP`, but goes through "**start new process first, old process exits later**": the websocket service has built-in bind retry, so after the old process exits and releases the port the new process takes over, and subscribers auto-reconnect (there is a very brief connection interruption, not a zero-downtime handover).

## Process stop and cleanup

- **Normal mode**: `SIGINT`(Ctrl+C) / `SIGTERM` closes the listener, drains connections, then exits.
- **TUN mode**: `SIGINT/SIGTERM` first cancels the context, closes the virtual network interface, reclaims the `0.0.0.0/1`+`128.0.0.0/1` routes, then exits. **Force kill (`kill -9` / `taskkill /F`) skips cleanup**, leaving residual routes and the interface that must be deleted manually.

## Linux iptables global proxy

```bash
# create a non-login user, use it to start anyproxy, avoiding its own traffic being re-forwarded into a loop
sudo useradd -M -s /sbin/nologin anyproxy
sudo iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner anyproxy -j RETURN
sudo -u anyproxy ./anyproxy -daemon

# root account local subnets don't go through proxy
sudo iptables -t nat -A OUTPUT -p tcp -d 192.168.0.0/16 -m owner --uid-owner 0 -j RETURN
sudo iptables -t nat -A OUTPUT -p tcp -d 172.17.0.0/16 -m owner --uid-owner 0 -j RETURN
# root account http/https go through proxy
sudo iptables -t nat -A OUTPUT -p tcp -m multiport --dport 80,443 -m owner --uid-owner 0 -j REDIRECT --to-port 3000
```

Removing rules:

```bash
sudo iptables -t nat -L -n --line-number   # view line numbers
sudo iptables -t nat -D OUTPUT 2           # delete the 2nd OUTPUT rule
```

> Linux iptables transparent proxy is Linux-only; the Windows/macOS builds drop this part and use TUN for the global proxy instead.

## Docker

```bash
docker build -t anyproxy:latest .
docker run anyproxy:latest
docker run -p 3000:3000 anyproxy:latest -p '127.0.0.1:3001'
```

## Windows notes

- **`mode: tun` requires administrator privileges**. Windows **does not create a virtual network interface**, but uses **WinDivert** to intercept packets at the network layer (replacing the old wintun). You must place `WinDivert.dll` + `WinDivert64.sys` (32-bit systems also need `WinDivert32.sys`) in the **same directory** as `anyproxy.exe` (a path containing spaces/Chinese may cause driver load failure). See [windows-winDivert.md](windows-winDivert.md).
- `ensureEagerRSS()` is a no-op on Windows and **does not re-exec**.
- **Process management must watch the real PID**: under `-daemon` the parent forks a child and exits immediately; the one actually running is the child (new PID). When using an external program (e.g. a tray UI) to start/stop anyproxy, killing by the parent PID obtained at startup or "scanning by exe name" may kill the wrong target and result in "can't kill". It's recommended to use the PID of the actual listening process, or omit `-daemon` (let the external program handle background hiding).
- **Stop**: Windows's WinDivert model doesn't modify the route table or create an interface; on exit it closes the WinDivert handle to stop redirection, leaving no residual routes/interface (unlike the TUN route cleanup on Linux/macOS).

## Performance tuning

Before starting, it's recommended to raise the available file descriptor limit to at least 65535:

```bash
ulimit -n 65535
```

> Related to `loopGuard.minActive`: the loop is cut once the global in-flight connection count just exceeds `minActive`; each connection takes about 2 fds, so `minActive×2` must be far smaller than `ulimit -n`, otherwise it hits `too many open files` first. See [multi-instance-loop.md](multi-instance-loop.md).

Other kernel parameters: append to `/etc/sysctl.conf` then run `sysctl -p` (full list in `./anyproxy -h`). Includes enabling **BBR** congestion control (needs kernel ≥ 4.9):

```bash
cat >> /etc/sysctl.conf << EOF
# TCP BBR congestion control
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr

# TCP/IP tuning
fs.file-max = 1000000
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.core.netdev_max_backlog = 250000
net.core.somaxconn = 4096
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_keepalive_time = 1200
net.ipv4.ip_local_port_range = 10000 65000
net.ipv4.tcp_max_syn_backlog = 8192
net.ipv4.tcp_max_tw_buckets = 524288
net.ipv4.tcp_fastopen = 3
net.ipv4.tcp_window_scaling = 1
net.ipv4.tcp_rmem = 4096 131072 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.ipv4.tcp_mtu_probing = 1
EOF
sysctl -p
```

Verify BBR:

```bash
sysctl net.ipv4.tcp_congestion_control   # => net.ipv4.tcp_congestion_control = bbr
lsmod | grep bbr                          # => contains tcp_bbr
```

You can also use the built-in commands to auto-check/apply (Linux only):

```bash
./anyproxy -check          # report whether sysctl/ulimit/BBR meet recommended values (read-only)
sudo ./anyproxy -check-fix # one-click write to /etc/sysctl.d/99-anyproxy.conf and apply with sysctl -p
```

> `-check-fix` only handles sysctl; file descriptors (`ulimit -n`) vary by environment and must be configured separately: for interactive login edit `/etc/security/limits.conf`, for systemd services set `LimitNOFILE=65535` in the unit.

## Debugging

```bash
./anyproxy -debug 2            # debug level 0~3
./anyproxy -pprof :5001        # access http://:5001/debug/pprof/ in browser
```
