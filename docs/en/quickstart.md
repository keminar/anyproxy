# Quick start

This page collects the most common startup examples: local proxy, tunneld server, forwarding to upstream proxy, port forwarding, graceful restart and Docker deployment. Full run-mode and config docs see [modes.md](modes.md), [configuration.md](configuration.md).

## Generate config file

On a new machine without config and can't recall the field format, first generate an annotated template (trimmed by run mode, existing files not overwritten):

```bash
# Generate to conf/router.yaml under the program dir, and create the default log dir
./anyproxy -genconf

# Generate by mode / specify path / print to screen only
./anyproxy -genconf -mode tunnel
./anyproxy -genconf -c /etc/anyproxy/router.yaml
./anyproxy -genconf -mode tun -c -
```

After generation, change a few values per the output prompt and start; details see [cli.md](cli.md#initialize-config-on-a-new-machine).

## Local startup

```bash
# Example 1. Start as the anyproxy user
sudo -u anyproxy ./anyproxy

# Example 2. Run as a background process
./anyproxy -daemon

# Example 3. Start tunneld (server, with token auth)
./anyproxy -mode tunnel

# Example 4. Start anyproxy and forward requests to tunneld
./anyproxy -p 'tunnel://127.0.0.1:3001'

# Example 5. Start anyproxy and forward requests to socks5
./anyproxy -p 'socks5://127.0.0.1:10000'

# Example 6. Port forwarding (tcpcopy)
./anyproxy -c conf/tcpcopy.yaml

# Other help
./anyproxy -h
```

> Reads `conf/router.yaml` by default (`-c` for another file); default listen port `:3000`, same port auto-detects HTTP / SOCKS5 / raw TCP, clients pick as needed (see [usage.md](usage.md)).

## Graceful restart

```bash
# First find the process pid, then send the HUP signal
kill -HUP pid
```

> SIGHUP graceful restart is implemented by the `grace` package: the new process inherits the listening fd without interrupting existing connections; the TUN device is released then re-taken over, to avoid `EBUSY` on the new process creating a same-named NIC. Config hot reload see [hot-reload.md](hot-reload.md).

## Use Docker

```bash
# Build
docker build -t anyproxy:latest .
# Run
docker run anyproxy:latest
# Expose port and run with arguments
docker run -p 3000:3000 anyproxy:latest -p '127.0.0.1:3001'
```
