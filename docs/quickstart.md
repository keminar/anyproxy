# 快速开始

本页汇总最常用的启动示例：本机代理、tunneld 服务端、转发到上级代理、端口转发、平滑重启与 Docker 部署。运行模式与配置的完整说明见 [modes.md](modes.md)、[configuration.md](configuration.md)。

## 本机启动

```bash
# 示例 1. 以 anyproxy 用户启动
sudo -u anyproxy ./anyproxy

# 示例 2. 以后台进程方式运行
./anyproxy -daemon

# 示例 3. 启动 tunneld（服务端，带 token 验证）
./anyproxy -mode tunnel

# 示例 4. 启动 anyproxy 并将请求转给 tunneld
./anyproxy -p 'tunnel://127.0.0.1:3001'

# 示例 5. 启动 anyproxy 并将请求转给 socks5
./anyproxy -p 'socks5://127.0.0.1:10000'

# 示例 6. 端口转发（tcpcopy）
./anyproxy -c conf/tcpcopy.yaml

# 其它帮助
./anyproxy -h
```

> 默认读 `conf/router.yaml`（`-c` 指定其它文件）；监听端口默认 `:3000`，同一端口自动识别 HTTP / SOCKS5 / 原始 TCP，客户端按需选用即可（见 [usage.md](usage.md)）。

## 平滑重启

```bash
# 首先查到进程 pid，然后发送 HUP 信号
kill -HUP pid
```

> SIGHUP 平滑重启由 `grace` 包实现：新进程继承监听 fd、不中断已有连接；TUN 设备会先释放再接管，避免新进程创建同名网卡 EBUSY。配置热加载另见 [hot-reload.md](hot-reload.md)。

## 使用 Docker

```bash
# 构建
docker build -t anyproxy:latest .
# 运行
docker run anyproxy:latest
# 开放端口并带参数运行
docker run -p 3000:3000 anyproxy:latest -p '127.0.0.1:3001'
```
