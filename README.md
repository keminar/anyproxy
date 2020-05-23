# Any Proxy

anyproxy 是一个tcp转发服务，部署在客户机，可以直接将请求发出，也可以将流转到tunneld

tunneld 是一个anyproxy的服务端，部署在服务器上接收anyproxy的请求，并代理发出或是转到下一个tunneld

anyproxy 到 tunneld 的转发过程可以支持简单双向加密更安全

anyproxy 可以代替charles进行手机抓包进行开发测试

## 代理设置

* 防火墙全局代理

```
#添加一个不可以登录的用户
sudo useradd -M -s /sbin/nologin anyproxy
# uid为anyproxy的tcp请求不转发,并用anyproxy用户启动anyproxy程序
sudo iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner anyproxy -j RETURN
# 其它用户的tcp请求转发到本地3000端口
sudo iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-port 3000
```

* 浏览器 [Chrome设置](https://zhidao.baidu.com/question/204679423955769445.html)
* 手机端 [苹果](https://jingyan.baidu.com/article/84b4f565add95060f7da3271.html)  [安卓](https://jingyan.baidu.com/article/219f4bf7ff97e6de442d38c8.html)

## 服务部署

```
+----------+      +----------+      +----------+
| Computer | <==> | anyproxy | <==> | Internet |
+----------+      +----------+      +----------+

# or
+----------+      +----------+      +---------+      +----------+
| Computer | <==> | anyproxy | <==> | tunneld | <==> | Internet |
+----------+      +----------+      +---------+      +----------+

# or
+----------+      +----------+      +---------+      +---------+      +----------+
| Computer | <==> | anyproxy | <==> | tunneld | <==> | tunneld | <==> | Internet |
+----------+      +----------+      +---------+      +---------+      +----------+
```

## 本机启动

```
# 示例1. 以anyproxy用户启动
sudo -u anyproxy ./anyproxy

# 示例2. 启动tunneld
sudo -u anyproxy ./tunneld

# 示例3. 启动anyproxy并将请求转给tunneld
sudo -u anyproxy ./anyproxy -p '127.0.0.1:3001'
```


## 平滑重启

```
# 首先查到进程pid，然后发送HUP信号
kill -HUP pid
```

## 使用Docker

```
# 构建
docker build -t anyproxy:latest .
# 运行
docker run anyproxy:latest
```

## Todo

* 根据CIDR做不同出口请求
* 对域名支持加Host绑定并配置请求出口
* 配置文件支持
* 服务间通信增加token验证
* 日志信息完善
* DNS解析增加cache
* 可以支持多个server，如果一个不可用用下一个
* server多级转发
* 加黑名单功能，不给请求
* 请求Body内容体记录
* 服务间通信http请求完全加密（header+body)
* HTTPS的SNI的支持?
* 支持转发到socket5服务

## 参考

<https://github.com/ryanchapman/go-any-proxy.git>

<https://zhuanlan.zhihu.com/p/25510419>

<http://blog.fatedier.com/2018/11/21/service-mesh-traffic-hijack/>

<https://my.oschina.net/mingyuejingque/blog/754089>

<https://github.com/darkk/redsocks>

<https://www.flysnow.org/2016/12/26/golang-socket5-proxy.html>