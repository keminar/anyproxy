package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"github.com/keminar/anyproxy/proto/tcp"
)

/**
 * 用于对tcp服务器的压力测试
 * 外部请求到本服务的监听端口，本服务把流量复制N份与目标服务器交互。同时只将一份的返回数据返回给客户端
 */

// 定义命令行参数对应的变量
var listen = flag.String("listen", ":6000", "本地监听端口")
var server = flag.String("server", ":8000", "目标服务器")
var num = flag.Int("num", 1, "压力测试数")

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
			return
		}
		go conn(rw)
	}
}

func conn(rwc *net.TCPConn) {
	connTimeout := time.Duration(5) * time.Second
	tunnel := newTunnel(rwc)
	for i := 0; i < *num; i++ {
		var conn net.Conn
		conn, err := net.DialTimeout("tcp", *server, connTimeout)
		if err != nil {
			fmt.Println(err)
			rwc.Close()
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
		s.readSize, err = s.copyBuffer(s.clientReader, "request")
		s.logCopyErr("request->server", err)
		log.Println("request body size", s.readSize)
	}()

	go func() { // 丢弃其它服务器返回的内容
		size := 4 * 1024
		for i, t := range s.targets {
			if i > 0 {
				go func(i int) {
					buf := make([]byte, size)
					for {
						_, er := t.reader.Read(buf)
						if er != nil {
							log.Println("reader closed", i)
							return
						}
					}
				}(i)
			}
		}
	}()
	var err error
	//取返回结果
	s.writeSize, err = s.copyBuffer(s.targets[0].reader, "server")
	s.logCopyErr("server->request", err)

	<-done
	// 不管是不是正常结束，只要server结束了，函数就会返回，然后底层会自动断开与client的连接
	log.Println("transfer finished, response size", s.writeSize)
}

// copyBuffer 传输数据
func (s *tunnel) copyBuffer(src *tcp.Reader, srcname string) (written int64, err error) {
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
				go func() { //同步发到多个连接
					for tk, tv := range s.targets {
						if tk > 0 {
							tv.conn.Write(buf[0:nr])
						}
					}
				}()
			} else {
				nw, ew = s.clientConn.Write(buf[0:nr])
			}
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {
			if er != io.EOF {
				err = er
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
				// 当客户端断开或出错了，服务端也不用再读了，可以关闭，解决读Server卡住不能到EOF的问题
				for _, tv := range s.targets {
					tv.conn.CloseWrite()
				}
				s.curState = stateClosed
			}
			break
		}
	}
	return written, err
}

func (s *tunnel) logCopyErr(name string, err error) {
	if err == nil {
		return
	}
	log.Println(name, err.Error())
}
