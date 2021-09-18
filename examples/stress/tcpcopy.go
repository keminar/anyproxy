package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/keminar/anyproxy/proto/tcp"
)

/**
 * 用于对tcp服务器的压力测试, 外部请求到本服务的监听端口
 * 本服务把流量复制N份与目标服务器交互。同时只将一份的返回数据返回给客户端
 * 编译:CGO_ENABLED=0 go build -o /tmp/tcpcopy tcpcopy.go
 *
 * 用curl进行多级HTTP代理测试时为避免http_proxy会有Proxy-Connection: keep-alive
 * 干扰链接断开造成部分请求一直收不到结束标志直到Nginx超时退出，可使用socks5协议测试，示例如下
 * 运行：./tcpcopy -listen 0.0.0.0:10010 -server 127.0.0.1:58813 -num 5000 -debug 1 -ignoreDog
 *      其中58813为另一个程序的socks5代理入口，并且可以访问本地80端口
 * curl --socks5 '127.0.0.1:10010'  http://127.0.0.1/test.html
 */

// 定义命令行参数对应的变量
var listen = flag.String("listen", ":6000", "本地监听端口")
var server = flag.String("server", ":8000", "目标服务器")
var num = flag.Int("num", 1, "压力测试数")
var mustLen = flag.Int("mustLen", 0, "目标服务器返回长度，非此长度的在debug 1以上时输出最后一段内容")
var panicLen = flag.Int("panicLen", 0, "目标服务器返回长度，非此长度的在debug 1以上时显示异常并退出，优先级大于mustLen")
var ignore = flag.Bool("ignoreDog", false, "忽略127.0.0.1来的请求，防止看门狗的请求被复制")
var debug = flag.Int("debug", 0, "调试日志级别")

const (
	OUT_NONE = iota
	OUT_INFO
	OUT_DEBUG
)

// tcp 压力测试
func main() {
	// 把用户传递的命令行参数解析为对应变量的值
	flag.Parse()
	if *num <= 0 {
		*num = 1
	}

	fmt.Println("本地监听", *listen)
	fmt.Println("压测目标", *server)
	fmt.Println("压测连接数", *num)
	fmt.Println("防看门狗", *ignore)
	if *panicLen > 0 {
		fmt.Println("程序panic长度", *panicLen)
	}

	err := accept()
	fmt.Println(err)
}

func accept() (err error) {
	var lnaddr *net.TCPAddr
	lnaddr, err = net.ResolveTCPAddr("tcp", *listen)
	if err != nil {
		err = fmt.Errorf("net.Listen error: %v", err)
		return
	}

	ln, err := net.ListenTCP("tcp", lnaddr)
	if err != nil {
		err = fmt.Errorf("net.Listen error: %v", err)
		return
	}

	for {
		var rw *net.TCPConn
		rw, err = ln.AcceptTCP()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			if ne, ok := err.(net.Error); ok && ne.Temporary() {
				tempDelay := 5 * time.Millisecond
				log.Printf("Accept error: %v; retrying in %v\n", err, tempDelay)
				time.Sleep(tempDelay)
				continue
			}
			return
		}
		// 忽略看门狗程序搔扰
		if *ignore && strings.Contains(rw.RemoteAddr().String(), "127.0.0.1:") {
			rw.Close()
			continue
		}
		go conn(rw)
	}
}

func conn(rwc *net.TCPConn) {
	if *debug >= OUT_INFO {
		log.Println("accecpt connection")
	}

	defer func() {
		rwc.Close()
	}()
	connTimeout := time.Duration(5) * time.Second
	tunnel := newTunnel(rwc)
	for i := 0; i < *num; i++ {
		var conn net.Conn
		conn, err := net.DialTimeout("tcp", *server, connTimeout)
		if err != nil {
			log.Println("connect", i, err)
			return
		}
		tunnel.addTarget(conn.(*net.TCPConn))
	}
	tunnel.transfer()
}

const (
	stateNew int = iota
	stateActive
	stateClosed
	stateIdle
)

type target struct {
	conn   *net.TCPConn
	reader *tcp.Reader
}

// 转发实体
type tunnel struct {
	clientConn   *net.TCPConn
	clientReader *tcp.Reader
	targets      []target

	curState int

	readSize  int64
	writeSize int64

	buf []byte
}

// newTunnel 实例
func newTunnel(client *net.TCPConn) *tunnel {
	s := &tunnel{
		clientConn:   client,
		clientReader: tcp.NewReader(client),
	}
	return s
}

// 添加连接
func (s *tunnel) addTarget(conn *net.TCPConn) {
	s.targets = append(s.targets, target{conn, tcp.NewReader(conn)})
}

// transfer 交换数据
func (s *tunnel) transfer() {
	s.curState = stateActive
	done := make(chan struct{})

	//发送请求
	go func() {
		defer func() {
			close(done)
		}()
		//不能和外层共用err
		var err error
		var closeWrite int64
		s.readSize, closeWrite, err = s.copyBuffer(s.clientReader, "request")
		s.logCopyErr("read from request", err)
		if *debug >= OUT_INFO {
			// 用fmt方便tee到另一个文件日志查看
			fmt.Println("request body size", s.readSize, "send closeWrite", closeWrite)
		}
	}()

	// 加锁防止顺序错乱
	var wg sync.WaitGroup
	wg.Add(len(s.targets))
	go func() { // 丢弃其它服务器返回的内容
		size := 4 * 1024
		for i, t := range s.targets {
			if i > 0 {
				go func(i int, t target) {
					defer func() {
						wg.Done()
					}()
					buf := make([]byte, size)
					var c int64
					var last string
					c = 0
					for {
						var lastlast string
						lastlast = last
						nr, er := t.reader.Read(buf)
						if nr > 0 {
							if *mustLen > 0 || *panicLen > 0 {
								last = string(buf[0:nr])
							}
							c += int64(nr)
						}
						if er != nil {
							if *debug >= OUT_INFO {
								if *panicLen > 0 && c != int64(*panicLen) {
									panic(lastlast + string(buf[0:nr]))
								} else if *mustLen > 0 && c != int64(*mustLen) { //不为指定大小的结果，输出上一次的值
									fmt.Println("reader", i, "#lastlast#", lastlast, "#this#", string(buf[0:nr]))
								}
								s.logReaderClosed("reader closed", i, c, er)
							}
							return
						}
					}
				}(i, t)
			} else {
				wg.Done()
			}
		}
	}()

	var err error
	//取返回结果
	s.writeSize, _, err = s.copyBuffer(s.targets[0].reader, "server")

	wg.Wait()
	<-done
	// 不管是不是正常结束，只要server结束了，函数就会返回，然后底层会自动断开与client的连接
	s.logReaderClosed("reader closed", 0, s.writeSize, err)
}

// copyBuffer 传输数据
func (s *tunnel) copyBuffer(src *tcp.Reader, srcname string) (written int64, closeWrite int64, err error) {
	//如果设置过大会耗内存高，4k比较合理
	size := 4 * 1024
	buf := make([]byte, size)
	i := 0
	for {
		i++
		nr, er := src.Read(buf)
		if nr > 0 {
			var nw int
			var ew error
			if srcname == "request" {
				nw, ew = s.targets[0].conn.Write(buf[0:nr])
				if *debug >= OUT_DEBUG {
					s.logReaderClosed("real request", 0, int64(nw), ew)
				}
				// 加锁防止顺序错乱
				var wg sync.WaitGroup
				wg.Add(len(s.targets))
				go func() { //同步发到多个连接
					for tk, tv := range s.targets {
						if tk > 0 {
							nx, ex := tv.conn.Write(buf[0:nr])
							if *debug >= OUT_DEBUG {
								s.logReaderClosed("copy request", tk, int64(nx), ex)
							}
						}
						wg.Done()
					}
				}()
				wg.Wait()
			} else {
				nw, ew = s.clientConn.Write(buf[0:nr])
				//打印测试服务端返回值
				//fmt.Println(string(buf[0:nr]))
			}
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = fmt.Errorf("id#1 %s", ew.Error())
				break
			}
			if nr != nw {
				err = fmt.Errorf("id#2 %s", io.ErrShortWrite.Error())
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = fmt.Errorf("id#3 %s", er.Error())
			} else {
				s.logCopyErr(srcname+" read", er)
				if srcname == "server" {
					if s.curState != stateClosed {
						// 如果非客户端导致的服务端关闭，则关闭客户端读
						// Notice: 如果只是CloseRead(),当在windows上执行时，且是做为订阅端从服务器收到请求再转到charles
						//         等服务时,当请求的地址返回足够长的内容时会触发卡住问题。
						//         流程如 curl -> anyproxy(server) -> ws -> anyproxy(windows) -> charles
						//         用Close()可以解决卡住，不过客户端会收到use of closed network connection的错误提醒
						s.clientConn.Close()
					}
				}
			}

			if srcname == "request" {
				// 客户端已经主动发送了EOF断开, 读取不到内容也算正常
				if strings.Contains(er.Error(), "use of closed network connection") {
					err = nil
				}
				// 当客户端断开或出错了，服务端也不用再读了，可以关闭，解决读Server卡住不能到EOF的问题
				for tk, tv := range s.targets {
					cerr := tv.conn.CloseWrite()
					if cerr != nil { //调试时改为panic也行
						log.Println("closeWrite", cerr.Error())
					} else {
						closeWrite++
						if *debug >= OUT_DEBUG {
							log.Println("closeWrite", tk)
						}
					}
				}
				s.curState = stateClosed
			}
			break
		}
	}
	return written, closeWrite, err
}

// 错误日志
func (s *tunnel) logCopyErr(name string, err error) {
	if err == nil || err == io.EOF {
		return
	}
	log.Println(name, err.Error())
}

// 读取字节日志
func (s *tunnel) logReaderClosed(msg string, i int, c int64, err error) {
	if err != nil && err != io.EOF {
		log.Println(msg, i, "size", c, "error", err.Error())
	} else {
		log.Println(msg, i, "size", c)
	}
}
