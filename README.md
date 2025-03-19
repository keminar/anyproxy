# Any Proxy

anyproxy 是一个部署在Linux系统上的tcp流转发器，可以将收到的请求按域名划分链路发本地请求或者转到下一级代理。可以代替Proxifier做Linux下的客户端， 也可以配合Proxifier当它的服务端。经过跨平台编译，如果只做网络包的转发可以在windows等平台使用。

[下载二进制包](http://cloudme.io/)

tunneld 是一个anyproxy的服务端模式，带密钥验证，部署在服务器上接收anyproxy的请求，并代理发出请求或是转到下一个tunneld。用于跨内网访问资源使用。非anyproxy请求一概拒绝处理

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

# Todo

> ~~划线~~ 部分为已实现功能
* ~~可将请求转发到Tunnel服务~~
* ~~对域名支持加Host绑定~~
* ~~对域名配置请求出口~~
* ~~增加全局默认出口配置~~
* ~~配置文件支持~~
* ~~服务间通信增加token验证可配~~
* ~~日志信息完善~~
* ~~DNS解析增加cache~~
* ~~自动路由模式下可设置检测时间和cache~~
* ~~可以自定义代理server，如果不可用则用全局的~~
* ~~server多级转发~~
* ~~加域名黑名单功能，不给请求~~
* ~~支持转发到socket5服务~~
* ~~支持HTTP/1.1 keep-alive 一外链接多次请求不同域名~~
* ~~修复iptables转发后百度贴吧无法访问的问题~~
* ~~支持windows平台使用~~
* ~~通过websocket实现内网穿透(必须为http的非CONNECT请求)~~
* ~~订阅增加邮箱标识，用于辨别在线用户~~
* ~~与Tunnel功能合并，使用mode区分~~
* ~~启用ws-listen后的平滑重启问题~~
* ~~监听配置文件变化重新加载路由~~
* ~~支持proxy时转换端口号~~
* ~~支持tcpcopy模式，用此转发连mysql~~
* ~~支持socks5协议接入~~
* ~~统计上下行流量~~
* ~~修复不支持http upgrade socket的问题~~
* TCP 增加更多协议解析支持，如rtmp，ftp, socks5, https(SNI)等
* tunel token支持按host配置

# 感谢

<https://github.com/ryanchapman/go-any-proxy.git>

<https://zhuanlan.zhihu.com/p/25510419>

<http://blog.fatedier.com/2018/11/21/service-mesh-traffic-hijack/>

<https://my.oschina.net/mingyuejingque/blog/754089>

<https://github.com/darkk/redsocks>

<https://www.flysnow.org/2016/12/26/golang-socket5-proxy.html>
