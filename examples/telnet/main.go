package main

import (
	"fmt"
	"net/http"
	"time"
)

func main() {
	http.HandleFunc("/sleep", SleepHandler)
	http.HandleFunc("/", HelloHandler)
	http.ListenAndServe("0.0.0.0:8880", nil)
}

func HelloHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println(time.Now().Unix(), r.Host+r.URL.RequestURI())
	fmt.Fprintf(w, "Hello! %s%s\n", r.Host, r.URL.RequestURI())
	fmt.Println(time.Now().Unix(), "hello end")
}

func SleepHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Println(time.Now().Unix(), r.Host+r.URL.RequestURI())
	time.Sleep(time.Duration(30) * time.Second)
	fmt.Fprintf(w, "Sleep! %s%s\n", r.Host, r.URL.RequestURI())
	fmt.Println(time.Now().Unix(), "sleep end")
}

/*
请求端日志
$ telnet 127.0.0.1 8880
Trying 127.0.0.1...
Connected to 127.0.0.1.
Escape character is '^]'.
GET /sleep HTTP/1.1
HOST: www.example.com

GET / HTTP/1.1
HOST: www.aaa.com

HTTP/1.1 200 OK
Date: Sat, 22 Aug 2020 07:59:49 GMT
Content-Length: 29
Content-Type: text/plain; charset=utf-8

Sleep! www.example.com/sleep
HTTP/1.1 200 OK
Date: Sat, 22 Aug 2020 07:59:49 GMT
Content-Length: 20
Content-Type: text/plain; charset=utf-8

Hello! www.aaa.com/
*/

/*
服务端日志
$ go run main.go
1598108632 www.example.com/sleep
1598108662 sleep end
1598108662 www.aaa.com/
1598108662 hello end
*/

// HTTP层面
// 结论: 从请求端看，第二个www.aaa.com的请求响应一定在第一个www.example.com响应后面
//       从接收端看，第二个www.aaa.com的请求接收在第一个www.example.com响应返回后

// 再结合wireshark.png
// 从wireshark看，第二个请求在第一个请求响应前发出了，为了测试准确性，通过将请求端换另一台机器，
// 在接收端抓包观察，接收端依然及时收到了，说明发送端没缓存处理。接收端还要再测试是在哪变更的顺序

//将代码运行在anyproxy后面，在copyBuffer函数增加日志
/*
请求端
$ telnet 127.0.0.1 4000
Trying 127.0.0.1...
Connected to 127.0.0.1.
Escape character is '^]'.
GET /sleep HTTP/1.1
HOST: 127.0.0.1:8880

GET / HTTP/1.1
HOST: www.aaa.com

HTTP/1.1 200 OK
Date: Sat, 22 Aug 2020 15:44:12 GMT
Content-Length: 28
Content-Type: text/plain; charset=utf-8

Sleep! 127.0.0.1:8880/sleep
Connection closed by foreign host.
*/

/*
接收端
以下日志有删减
$ go run anyproxy.go -l :4000 -d 2
grace/server.go:215: Listening for connections on [::]:4000, pid=1188
proto/client.go:22: ID #1, remoteAddr:127.0.0.1:6657
ID #1, GET /sleep HTTP/1.1
ID #1, Host = [127.0.0.1:8880]
ID #1,
proto/tunnel.go:62: ID #1, receive from client, n=1

1598111028138113800 GET / HTTP/1.1

proto/tunnel.go:83: ID #1, receive from server, n=1, data len: 145
ID #1, 1598111052420328000 HTTP/1.1 200 OK
Date: Sat, 22 Aug 2020 15:44:12 GMT
Content-Length: 28
Content-Type: text/plain; charset=utf-8

Sleep! 127.0.0.1:8880/sleep

*/

// 结论：TCP层面是没有处理顺序的。就是说第二个发送是有及时收到的。但是HTTP层面第二个发送是推迟到第一个请求返回后收到
// 所以是HTTP层面有做一些操作。那么在tcp的copyBuffer函数就不能根据第二个请求是否到达来判断第一个请求是否完成并关闭第一个请求的返回。
