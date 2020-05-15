# Any Proxy

anyproxy 是一个tcp转发服务，部署在客户机，可以直接将请求发出，也可以将流转到tunneld

tunneld 是一个anyproxy的服务端，部署在服务器上接收anyproxy的请求，并代理发出或是转到下一个tunneld

anyproxy 到 tunneld 的转发过程可以支持双向加密

## 防火墙

```
# uid为1000的tcp请求不转发,并用uid 1000启动anyproxy
sudo iptables -t nat -A OUTPUT -p tcp -m owner --uid-owner 1000 -j RETURN
# 其它用户的tcp请求转发到本地3000端口
sudo iptables -t nat -A OUTPUT -p tcp -j REDIRECT --to-port 3000
```

## TCP stream
```
+----------+      +------------+      +-------+
| 个人电脑 | <==> |本地anyproxy| <==> |互联网 |
+----------+      +------------+      +-------+

# 或
+----------+      +------------+      +------------+      +-------+
| 个人电脑 | <==> |本地anyproxy| <==> |远程tunneld | <==> |互联网 |
+----------+      +------------+      +------------+      +-------+
```
## 参考

https://github.com/ryanchapman/go-any-proxy.git

https://zhuanlan.zhihu.com/p/25510419

http://blog.fatedier.com/2018/11/21/service-mesh-traffic-hijack/

https://my.oschina.net/mingyuejingque/blog/754089

https://github.com/darkk/redsocks

https://www.flysnow.org/2016/12/26/golang-socket5-proxy.html