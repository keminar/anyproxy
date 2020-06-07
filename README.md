# Any Proxy

anyproxy 是一个tcp转发客户端，可以让不支持通过代理服务器工作的网络程序能通过HTTPS或SOCKS代理。可以代替Proxifier做socks5客户端， 可以代替charles进行手机http抓包(需定制)。它部署在Linux客户机，可以直接将收到的网络请求发出，也可以将tcp流转到tunneld或SOCKS代理。

[下载二进制包](http://cloudme.io/anyproxy)

tunneld 是一个anyproxy的服务端，部署在服务器上接收anyproxy的请求，并代理发出请求或是转到下一个tunneld。用于跨内网访问资源使用

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
| Computer | <==> | anyproxy | <==> | tunneld | <==> | tunneld | <==> | Internet |
+----------+      +----------+      +---------+      +---------+      +----------+

# or
+----------+      +----------+      +---------+      +---------+      +----------+
| Computer | <==> | anyproxy | <==> | tunneld | <==> | socks5  | <==> | Internet |
+----------+      +----------+      +---------+      +---------+      +----------+
```

# 使用案例
> 解决Docker pull官方镜像的问题
![解决Docker pull问题](examples/docker_pull.png)

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
go build anyproxy.git
```

> 本机启动

```
# 示例1. 以anyproxy用户启动
sudo -u anyproxy ./anyproxy

# 示例2. 以后台进程方式运行
./anyproxy -daemon

# 示例3. 启动tunneld
./tunneld

# 示例4. 启动anyproxy并将请求转给tunneld
./anyproxy -p '127.0.0.1:3001'

# 示例5. 启动anyproxy并将请求转给socks5
./anyproxy -p 'socks5://127.0.0.1:10000'

# 其它帮助
./anyproxy -h
```

注：因为用到了Linux系统函数，并不能跨平台编译。对于windows系统用户可以选择在虚拟机中启动或是win10的WSL中启动

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
# 其它用户的tcp请求转发到本地3000端口
sudo iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-port 3000

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
* 根据CIDR做不同出口请求
* 对域名支持加Host绑定并配置请求出口
* 配置文件支持
* 服务间通信增加token验证
* 日志信息完善
* DNS解析增加cache
* 可以支持多个server，如果一个不可用用下一个
* ~~server多级转发~~
* 加域名黑名单功能，不给请求
* 请求Body内容体记录, 涉及安全，可能不会实现
* 服务间通信http请求完全加密（header+body)
* HTTPS的SNI的支持?
* ~~支持转发到socket5服务~~
* TCP 增加更多协议解析支持，如rtmp，ftp等

# 参考

<https://github.com/ryanchapman/go-any-proxy.git>

<https://zhuanlan.zhihu.com/p/25510419>

<http://blog.fatedier.com/2018/11/21/service-mesh-traffic-hijack/>

<https://my.oschina.net/mingyuejingque/blog/754089>

<https://github.com/darkk/redsocks>

<https://www.flysnow.org/2016/12/26/golang-socket5-proxy.html>