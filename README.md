# Any Proxy

anyproxy 是一个部署在Linux系统上的tcp流转发器，可以将收到的请求按域名划分链路发本地请求或者转到下一级代理。可以代替Proxifier做Linux下的客户端， 也可以配合Proxifier当它的服务端。经过跨平台编译，如果只做网络包的转发可以在windows等平台使用。

[下载二进制包](http://cloudme.io/)

tunneld 是一个anyproxy的服务端模式，带密钥验证，部署在服务器上接收anyproxy的请求，并代理发出请求或是转到下一个tunneld。用于跨内网访问资源使用。非anyproxy请求一概拒绝处理

> 📖 完整文档见 [docs/](docs/README.md)：[概述与架构](docs/overview.md)、[命令行参数](docs/cli.md)、[配置参考](docs/configuration.md)、[路由规则](docs/routing.md)、[运行模式](docs/modes.md)、[部署运维](docs/deployment.md)。

# 路由支持

```
+----------+      +----------+      +----------+
| Computer | <==> | anyproxy | <==> | Internet |
+----------+      +----------+      +----------+

# or
+----------+      +----------+      +---------+      +----------+
| Computer | <==> | anyproxy | <==> | tunneld | <==> | Internet |
+----------+      +----------+      +---------+      +----------+

# or
+----------+      +----------+      +---------+      +----------+
| Computer | <==> | anyproxy | <==> | socks5  | <==> | Internet |
+----------+      +----------+      +---------+      +----------+

# or
+----------+      +----------+      +---------+      +---------+      +----------+
| Computer | <==> | anyproxy | <==> | tunneld | <==> | socks5  | <==> | Internet |
+----------+      +----------+      +---------+      +---------+      +----------+

# or
+----------+      +---------+      +-----------+  ws  +-----------+      +---------+
| Computer | <==> | Nginx A | <==> | anyproxy S| <==> | anyproxy C| <==> | Nginx B |
+----------+      +---------+      +-----------+      +-----------+      +---------+
```

# 使用案例
> 案例1:解决Docker pull官方镜像的问题

`使用iptables将本用户下tcp流转到anyproxy，再进行docker pull操作`

> 案例2: 解决相同域名访问网站不同测试环境的问题

`本地通过内网 anyproxy 代理上网，遇到测试服务器域名则跳到外网tunneld转发，网站的nginx根据来源IP进行转发到特定测试环境（有几个环境就需要有几个tunneld服务且IP要不同)`

> 案例3: 解决HTTPS抓包问题

`本地将https请求到服务器，服务器解证书后增加特定头部转到anyproxy websocket服务端，本地另起一个anyproxy的websocket客户端接收并将http请求转发到Charles`

> 案例4： 解决内网tcp端口给外网访问

`假如本机是192网段，容器内是10网段，在本机启动一个程序监听本机端口同时桥接到容器内的应用的端口，这样就可以通过本机端口访问容器内的tcp服务（配置项是tcpcopy）`

# 源码编译

> 安装Go环境并设置GOPROXY

Go环境安装比较简单，这里不做介绍，GOPROXY对不同版本有些差异，设置方法如下
```
# Go 版本>=1.11
export GOPROXY=https://goproxy.cn
# Go 版本>=1.13 
go env -w GOPROXY=https://goproxy.cn,direct
```

> 下载编译
```
git clone https://github.com/keminar/anyproxy.git
cd anyproxy
make all
```

> 本机启动

```
# 示例1. 以anyproxy用户启动
sudo -u anyproxy ./anyproxy

# 示例2. 以后台进程方式运行
./anyproxy -daemon

# 示例3. 启动tunneld
./anyproxy -mode tunnel

# 示例4. 启动anyproxy并将请求转给tunneld
./anyproxy -p 'tunnel://127.0.0.1:3001'

# 示例5. 启动anyproxy并将请求转给socks5
./anyproxy -p 'socks5://127.0.0.1:10000'

# 示例6. 端口转发
./anyproxy -c conf/tcpcopy.yaml

# 其它帮助
./anyproxy -h
```

注：因为本地iptables转发是Linux功能，所以windows系统使用时精简掉了此部分功能

> 平滑重启

```
# 首先查到进程pid，然后发送HUP信号
kill -HUP pid
```


> 使用Docker

```
# 构建
docker build -t anyproxy:latest .
# 运行
docker run anyproxy:latest
# 开放端口并带参数运行
docker run  -p 3000:3000 anyproxy:latest -p '127.0.0.1:3001'
```

# TUN 虚拟网卡全局代理

除了Linux下用iptables转发外，anyproxy 还支持跨平台(Windows/Linux/macOS)全局代理。
Linux/macOS 创建一块 TUN 虚拟网卡，把系统流量路由进来，内部用 gVisor 用户态协议栈解析出TCP连接，
再复用 anyproxy 已有的代理路由(direct/tunnel/socks5/hosts规则)转发出去，等价于 tun2socks。
Windows 不建虚拟网卡，改用 WinDivert 在网络层捕获并重定向出站 TCP，再复用同一套代理逻辑。

> 特性与规则详解（跨平台 utun、autoRoute、QUIC 拦截、target/proxy 优先级）见 [docs/tun-features.md](docs/tun-features.md)

> 说明
* 复用配置文件里 `default` / `hosts` 的全部代理规则(direct/tunnel/socks5/换IP/换端口等)，用法和旧的透明代理一致
* 支持按域名配置不同代理: TUN 只拿得到目标IP，程序会从首包嗅探 TLS SNI / HTTP Host 还原域名，让 `hosts.name` 的域名规则生效；嗅探不到(如服务端先说话的协议)则回退按IP匹配
* 目前只代理 TCP 流量，UDP(含DNS)暂不走隧道。全量接管路由时要给 DNS 服务器加直连例外，否则无法解析域名(或改用 DoH/DoT 这类走TCP的DNS)
* 需要管理员/root 权限运行
* Windows 用 WinDivert：把 `WinDivert.dll` + `WinDivert64.sys`(32位系统另需 `WinDivert32.sys`)与 `anyproxy.exe` 放同一目录(路径含空格/中文可能导致驱动加载失败)。详见 [docs/windows-winDivert.md](docs/windows-winDivert.md)
* Linux/macOS 程序负责创建网卡、分配接口IP并启用；路由采用半自动方式，启动时会打印所需路由命令供确认后执行

> 启动

```
# 命令行开启(配IP默认 10.9.0.1/24)
sudo ./anyproxy -mode tun -p 'socks5://127.0.0.1:10000'

# 网卡名和接口地址通过配置 tun.name / tun.addr 指定
sudo ./anyproxy -mode tun

# 或在 conf/router.yaml 中配置 tun.enable: true 后直接启动
sudo ./anyproxy
```

> 配置全局路由(启动后按打印提示执行, 需管理员/root)

```
# Linux: 接管默认路由前，务必先给上级代理出口IP加直连例外，否则会环路断网
sudo ip route add <上级代理IP>/32 via <原网关> dev <原网卡>
sudo ip route add 0.0.0.0/1 dev anytun0
sudo ip route add 128.0.0.0/1 dev anytun0

# Windows: 同样先给上级代理IP加直连例外
route add <上级代理IP> mask 255.255.255.255 <原网关>
route add 0.0.0.0 mask 128.0.0.0 10.9.0.1
route add 128.0.0.0 mask 128.0.0.0 10.9.0.1
```

# 同机多实例的死循环防护

> bypass 模式仅 Linux 支持（macOS/Windows 已移除），平台替代方案详见 [docs/multi-instance-loop.md](docs/multi-instance-loop.md)

同机部署两套 anyproxy：A 开 `mode=tun` 做全局代理并把请求转给上游 B，B 普通模式作为出口。
A 的 TUN 会把 `0.0.0.0/1`、`128.0.0.0/1` 全量流量吸进来；A 自己的出向已用 `SO_BINDTODEVICE`
绑物理网卡逃出 TUN，但 **B 的出向没逃**，会被 A 的 TUN 再次抓走 → A → B → …… 形成死循环。

## 根治：B 用 mode=bypass（仅 Linux）

让 B 以 `mode=bypass` 运行，B 的出向连接会绑定物理网卡、逃出 A 的 TUN 路由，从路由层根治环路。
同机源 IP 相同，无法用「源 IP=B」或 `ip rule from` 区分，故 bypass 是同机唯一的确定性根治手段。

```
# B 的 conf/router.yaml
mode: bypass
tun:
  linux:
    # 自动探测不到物理网卡时(启动日志 bypass-only: device="")手动指定
    device: eth0
```

* **务必检查 B 的启动日志** `bypass-only: device="..." ip="..."`：`device` 与 `ip` 非空才算 bypass 生效。
  若为空说明 `defaultRoute()` 自动探测失败，bypass 会静默退回普通拨号而失效，此时用 `tun.linux.device` 手动指定网卡名。

## 兜底：loopGuard 熔断器

作为最后防线，防止 bypass 失效时把机器句柄打爆。判定逻辑基于**在传连接占比**而非每秒请求数：

* 便宜的闸门：仅当整个进程的在传连接数达到 `minActive` 时才启用检查，常态下只做一次 `int` 比较，零额外开销
* 占比判定：闸门开启后，若某个 `host:port` 占用的在传连接超过 `total * ratio%`（句柄都堆在一个目标上＝环路特征），拒绝其新连接
* 自愈：拒绝新连接后，上游 B 对该目标的连接被 A 拒绝而失败，环路解开，存量连接 drain，闸门自动重新放开，无需熔断计时

```
# 默认开启, minActive=1000, ratio=80%; 关闭用 minActive: -1
loopGuard:
  minActive: 1000  # 全局在传连接达到此值才启用占比检查; 0=默认1000; <0=关闭
  ratio: 80        # 单目标占全局在传连接的百分比阈值
```

> 环路会在总连接数刚过 `minActive` 时被切断，每条连接约占 2 个文件描述符，故 `minActive*2` 必须
> 远小于 `ulimit -n`（anyproxy 建议 `ulimit -n 65535`），否则进程会先撞 `too many open files`、
> 熔断器来不及触发。低 ulimit 环境请调小 `minActive`。

触发时日志形如：`loopguard: circuit open for <host>:<port> (in-flight 960/1000, suspected proxy loop)`。
loopGuard 是兜底，不是主方案——环路的根治仍靠 B 的 `mode=bypass` 真正生效。

# 代理设置

* 防火墙全局代理

```
#添加一个不可以登录的用户
sudo useradd -M -s /sbin/nologin anyproxy
# uid为anyproxy的tcp请求不转发,并用anyproxy用户启动anyproxy程序
sudo iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner anyproxy -j RETURN
sudo -u anyproxy ./anyproxy -daemon
# 指定root账号本地请求不走代理
sudo iptables -t nat -A OUTPUT -p tcp -d 192.168.0.0/16 -m owner --uid-owner 0 -j RETURN
sudo iptables -t nat -A OUTPUT -p tcp -d 172.17.0.0/16 -m owner --uid-owner 0 -j RETURN
# 指定root账号的http/https请求走代理
sudo iptables -t nat -A OUTPUT -p tcp -m multiport --dport 80,443 -m owner --uid-owner 0 -j REDIRECT --to-port 3000
```

> 如果删除全局代理
```
# 查看当前规则
sudo iptables -t nat -L -n  --line-number

# 输出
 ...以上省略
 Chain OUTPUT (policy ACCEPT)
 num  target     prot opt source               destination
 1    RETURN     tcp  --  0.0.0.0/0            0.0.0.0/0            owner UID match 1004
 2    REDIRECT   tcp  --  0.0.0.0/0            0.0.0.0/0            redir ports 3000
 ...以下省略

# 按顺序依次为OUTPUT的第一条规则，和第二条规则
# 假如想删除net的OUTPUT的第2条规则
sudo iptables -t nat -D OUTPUT 2
```
* 浏览器 [Chrome设置](https://zhidao.baidu.com/question/204679423955769445.html)
* 手机端 [苹果](https://jingyan.baidu.com/article/84b4f565add95060f7da3271.html)  [安卓](https://jingyan.baidu.com/article/219f4bf7ff97e6de442d38c8.html)


# 感谢

<https://github.com/ryanchapman/go-any-proxy.git>

<https://zhuanlan.zhihu.com/p/25510419>

<http://blog.fatedier.com/2018/11/21/service-mesh-traffic-hijack/>

<https://my.oschina.net/mingyuejingque/blog/754089>

<https://github.com/darkk/redsocks>

<https://www.flysnow.org/2016/12/26/golang-socket5-proxy.html>
