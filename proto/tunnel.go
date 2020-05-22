package proto

import (
	"bufio"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/keminar/anyproxy/config"
	"github.com/keminar/anyproxy/crypto"
)

const (
	stateNew int = iota
	stateActive
	stateClosed
)

// 转发实体
type tunnel struct {
	req      *Request
	conn     *net.TCPConn
	curState int

	readSize  int64
	writeSize int64
}

// newTunnel 实例
func newTunnel(req *Request) *tunnel {
	s := &tunnel{
		req: req,
	}
	return s
}

// copyBuffer 传输数据
func (s *tunnel) copyBuffer(dst io.Writer, src io.Reader, dstname string, srcname string) (written int64, err error) {
	size := 32 * 1024
	if l, ok := src.(*io.LimitedReader); ok && int64(size) > l.N {
		if l.N < 1 {
			size = 1
		} else {
			size = int(l.N)
		}
	}
	buf := make([]byte, size)
	i := 0
	for {
		i++
		if config.DebugLevel == config.LevelDebug {
			log.Printf("%s receive from %s, n=%d\n", TraceID(s.req.ID), srcname, i)
		}
		nr, er := src.Read(buf)
		if nr > 0 {
			if config.DebugLevel == config.LevelDebug {
				log.Printf("%s receive from %s, n=%d, data len: %d\n", TraceID(s.req.ID), srcname, i, nr)
			}
			nw, ew := dst.Write(buf[0:nr])
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
				log.Println(TraceID(s.req.ID), srcname, "read", er.Error())
			}

			if srcname == "client" {
				// 当客户端断开或出错了，服务端也不用再读了，可以关闭，解决读Server卡住不能到EOF的问题
				s.conn.CloseWrite()
				s.curState = stateClosed
			} else {
				// 如果非客户端导致的服务端关闭，则关闭客户端读
				if s.curState != stateClosed {
					dst.(*net.TCPConn).CloseRead()
				}
			}
			break
		}
	}
	return written, err
}

// transfer 交换数据
// leftConn 不用req.conn 有一定原因是leftConn可能会是newTCPConn
func (s *tunnel) transfer(leftConn *net.TCPConn) {
	log.Println(TraceID(s.req.ID), "transfer start")
	var err error
	s.curState = stateActive
	done := make(chan int, 1)

	//发送请求
	go func() {
		defer func() {
			done <- 1
			close(done)
		}()
		s.readSize, err = s.copyBuffer(s.conn, leftConn, "server", "client")
		if err != nil {
			log.Println(TraceID(s.req.ID), "client->server", err.Error())
		}
		log.Println(TraceID(s.req.ID), "request body size", s.readSize)
	}()

	//取返回结果
	s.writeSize, err = s.copyBuffer(leftConn, s.conn, "client", "server")
	if err != nil {
		log.Println(TraceID(s.req.ID), "server->client", err.Error())
	}

	<-done
	// 不管是不是正常结束，只要server结束了，函数就会返回，然后底层会自动断开与client的连接
	log.Println(TraceID(s.req.ID), "transfer finished, response size", s.writeSize)
}

// dail tcp连接
func (s *tunnel) dail(dstIP string, dstPort uint16) (err error) {
	log.Printf("%s accept and create a new connection to server %s:%d\n", TraceID(s.req.ID), dstIP, dstPort)
	var addr *net.TCPAddr
	addr, err = net.ResolveTCPAddr("tcp4", fmt.Sprintf("%s:%d", dstIP, dstPort))
	if err != nil {
		return
	}
	s.conn, err = net.DialTCP("tcp4", nil, addr)
	return
}

// handshake 和server握手
func (s *tunnel) handshake(dstName, dstIP string, dstPort uint16) (err error) {
	if config.ProxyServer != "" && config.ProxyPort > 0 {
		err = s.dail(config.ProxyServer, config.ProxyPort)
		if err != nil {
			log.Println(TraceID(s.req.ID), "dail err", err.Error())
			return
		}
		if dstName == "" {
			dstName = dstIP
		}
		x := []byte(fmt.Sprintf("%s:%d", dstName, dstPort))
		log.Println(TraceID(s.req.ID), fmt.Sprintf("PROXY %s:%d for %s", config.ProxyServer, config.ProxyPort, string(x)))
		key := []byte(AesToken)
		var x1 []byte
		x1, err = crypto.EncryptAES(x, key)
		if err != nil {
			log.Println(TraceID(s.req.ID), "encrypt err", err.Error())
			return
		}

		// CONNECT实现的加密版
		connectString := fmt.Sprintf("CONNECT %s HTTP/1.1\r\n\r\n", base64.StdEncoding.EncodeToString(x1))
		fmt.Fprintf(s.conn, connectString)
		var status string
		status, err = bufio.NewReader(s.conn).ReadString('\n')
		if err != nil {
			log.Printf("%s PROXY ERR: Could not find response to CONNECT: err=%v", TraceID(s.req.ID), err)
			return
		}
		// 检查是不是200返回
		if strings.Contains(status, "200") == false {
			log.Printf("%s PROXY ERR: Proxy response to CONNECT was: %s.\n", TraceID(s.req.ID), strconv.Quote(status))
		}
	} else {
		err = s.dail(dstIP, dstPort)
		if err != nil {
			return
		}
	}
	s.curState = stateNew
	return
}
