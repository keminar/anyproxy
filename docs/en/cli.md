# Command-line arguments

Use `./anyproxy -h` to view the full help. The table below lists all startup parameters and their config-file equivalents.

| param | description | config-file equivalent | priority |
|------|------|----------------|--------|
| `-l ADDRPORT` | listen address:port, e.g. `:3000` or `127.0.0.1:3000`; set to `off` (or `none`/`-`) to **disable the proxy listener**, running only background services like websocket/tun (pure intranet penetration) | `listen` | CLI > config > `:3000` |
| `-p PROXIES` | upstream proxy, e.g. `tunnel://10.2.2.2:3001` / `socks5://10.2.2.2:3128` / `http://10.1.1.1:80`; supports comma-separated multiple proxies with trailing `local`/`deny` suffix (see [routing.md](routing.md#proxy-field)) | `default.proxy` | CLI > config |
| `-c FILEPATH` | config file path, default `conf/router.yaml` | — | — |
| `-mode` | run mode (mutually exclusive): `proxy` (default) / `tunnel`(tunneld server) / `tun`(TUN global proxy) / `bypass`(physical NIC bypass, Linux only) / `tcpcopy`(port forwarding) | `mode` | CLI > config |
| `-ws-listen` | websocket listen address:port (intranet penetration server) | `websocket.server.listen` | CLI > config |
| `-daemon` | run as background daemon (fork child, parent exits) | — | — |
| `-debug` | debug level `0/1/2/3`, higher = more verbose logs | — | — |
| `-pprof` | pprof port, empty to disable; visit `http://<port>/debug/pprof/` in browser | — | — |
| `-genconf` | generate an annotated config template then exit (for new machines without config / unsure of format): content trimmed by `-mode`, output path from `-c` (default **program dir** `conf/router.yaml`; `-` prints to stdout); **existing file not overwritten**, also creates the default log dir | — | — |
| `-geo-extract` | extract categories from `.dat` into a small file then exit, with `-geo-in`/`-geo-cat`/`-geo-out` (see [geo.md](geo.md)) | — | — |
| `-geo-in` / `-geo-cat` / `-geo-out` | geo-extract source `.dat` / categories (comma-separated) / output path | — | — |
| `-v` | show build version info | — | — |
| `-h` | show help | — | — |
| `-genkey` | generate a pair of websocket auth keys and exit (private key → `websocket.client.key`, public key → `websocket.server.users[].key`) | `websocket.client.key` / `websocket.server.users[].key` | CLI one-shot |
| `-wol MAC[,MAC2,...]` | send Wake-on-LAN magic packets and exit; MAC accepts a comma-separated list, either `AA:BB:CC:DD:EE:FF` or `AA-BB-CC-DD-EE-FF`; reuses `-to`/`-via` (see the next two rows) instead of dedicated flags; with `-via` left at its default (`direct`, i.e. not passed) it broadcasts from this machine, with an explicit subscriber email it instead asks that subscriber to broadcast; a successful send does not guarantee the target woke up | — | CLI one-shot |
| `-send PATH` | send file/dir to another subscriber and exit (multiple paths allowed); receiver needs `direct.accept` on, end-to-end encrypted | — | CLI one-shot |
| `-to EMAIL[:subdir]` / `DIR` | `-send`: receiver email (scp-style `:subdir` lands in `receive.dir/subdir`); `-recv`: local store dir (default current dir); `-wol`: broadcast target `ADDR[:PORT]`, default `255.255.255.255:9` (limited broadcast, local link only, not forwarded by routers; if the target is on a specific subnet, use that subnet's directed broadcast, e.g. `192.168.1.255`) -- this is the address used by whichever machine actually broadcasts (this one, or the `-via` subscriber) | — | CLI one-shot |
| `-via direct\|relay\|email-of-VPS` | `-send`/`-recv`: direct hole-punch (`direct`, fails immediately if can't punch), relay via server B (`relay`, no punch needed), or an email of a public VPS (that host needs `direct.relay` on) for blind-relay hole-punching (used when both ends are behind CGNAT and can't connect directly, see [direct-relay-design.md](direct-relay-design.md)); all end-to-end encrypted. `-wol`: the machine to wake is powered off and cannot run this command itself, so this is the email of **another subscriber already on that machine's LAN** who broadcasts on your behalf (does not accept the `direct`/`relay` keywords -- always relayed through the server B, no NAT punching needed for a 102-byte packet), and requires that subscriber's `receive.allow` to list this machine with an explicit `wol: true` on that entry (default `false`, a permission separate from file transfer, see [configuration.md](configuration.md)) | `websocket.client.direct.relay`(VPS side) | CLI one-shot |
| `-recv EMAIL:PATH` | fetch file/dir back from another subscriber and exit (scp-style, path relative to the other's `receive.dir`) | — | CLI one-shot |
| `-parallel N` | `-send`/`-recv`: split a single large file into at most N byte-range chunks for parallel transfer (default 1, small files not split) | — | CLI one-shot |
| `-direct-plain-udp` | direct (NAT hole-punch) connection: skip quic-go batch/ECN fast UDP path, fall back to per-packet I/O; try under high packet loss / stuck congestion window | `websocket.client.direct.plainUdp` | CLI > config |
| `-check` | read-only check of suggested system tuning (sysctl/ulimit/BBR) values then exit | — | CLI one-shot |
| `-check-fix` | one-click write `/etc/sysctl.d/99-anyproxy.conf` and `sysctl -p` to apply recommended kernel params (needs root) | — | CLI one-shot |

> Full usage, auth and troubleshooting for file transfer (`-send`/`-recv` and `-to`/`-via`/`-parallel`/`-direct-plain-udp`) see [websocket.md](websocket.md#file-transfer--send---recv--receive); full recommended items for system tuning (`-check`/`-check-fix`) see [deployment.md](deployment.md#performance-tuning).

## Priority rules

For items specifiable both on the CLI and in the config file (`listen` / `proxy` / `mode` / websocket, etc.), **the CLI argument takes priority over the config file**, and the config file takes priority over built-in defaults. The TUN NIC name/address can only be set via config `tun.name` / `tun.addr`.

## Initialize config on a new machine

When there is no `conf/router.yaml` on a new machine yet, don't copy by hand from docs — first generate an annotated skeleton then edit:

```bash
# Generate to conf/router.yaml under the program dir (also creates the default log dir); after generation it starts without -c
./anyproxy -genconf

# Generate by run mode (template keeps only fields used by that mode): tunnel server / tun global proxy / tcpcopy port forwarding …
./anyproxy -genconf -mode tunnel

# Specify output path
./anyproxy -genconf -c /etc/anyproxy/router.yaml

# Preview without writing to disk
./anyproxy -genconf -mode tun -c -
```

The template only opens fields used by that mode; example rules are all commented out, and it starts directly after generation; which values to change is listed in the command's "next steps" output. When the target file already exists it is **not overwritten** — it errors out instead, to avoid clobbering a running config by accident. The full field set still follows the repo's [conf/router.yaml](../conf/router.yaml), [configuration.md](configuration.md) and [config-examples.md](config-examples.md).

## Common startup examples

```bash
# Start in foreground as a normal proxy (reads conf/router.yaml)
./anyproxy

# Run in background
./anyproxy -daemon

# Start tunneld server
./anyproxy -mode tunnel

# Forward requests to upstream tunneld / socks5
./anyproxy -p 'tunnel://127.0.0.1:3001'
./anyproxy -p 'socks5://127.0.0.1:10000'

# Specify config file (port forwarding mode)
./anyproxy -c conf/tcpcopy.yaml

# TUN global proxy (needs admin/root; NIC name/address set via config tun.name / tun.addr)
sudo ./anyproxy -mode tun -p 'socks5://127.0.0.1:10000'

# Wake a WOL-enabled machine on this LAN; can wake several at once and target a specific subnet
./anyproxy -wol AA:BB:CC:DD:EE:FF
./anyproxy -wol AA:BB:CC:DD:EE:FF,11:22:33:44:55:66 -to 192.168.1.255:9

# Wake a machine on another subscriber's LAN (that subscriber must allow this machine in
# receive.allow; the target itself is off, so this is another already-on machine on its LAN)
./anyproxy -wol AA:BB:CC:DD:EE:FF -via home@example.com
```

> Upstream proxy protocol prefixes supported: `tunnel://`, `socks5://`, `http://`. **When no `://` prefix is written, it defaults to `tunnel://`** (same for global `-p`/`default.proxy` and `hosts[].proxy`). Note: the old help text in `-h` saying "bare address = http" does not match the current implementation; this doc is authoritative. See [routing.md](routing.md).
