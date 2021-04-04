package proto

import (
	"bytes"
	"fmt"
	"io"
	"log"

	"github.com/keminar/anyproxy/config"
	"github.com/keminar/anyproxy/nat"
	"github.com/keminar/anyproxy/utils/trace"
)

// 转发实体
type wsTunnel struct {
	req *Request

	readSize  int64
	writeSize int64

	buffer *bytes.Buffer
}

// newTunnel 实例
func newWsTunnel(req *Request) *wsTunnel {
	s := &wsTunnel{
		req:    req,
		buffer: new(bytes.Buffer),
	}
	return s
}

// copyBuffer 传输数据
func (s *wsTunnel) copyBuffer(dst io.Writer, src io.Reader, srcname string) (written int64, err error) {
	//如果设置过大会耗内存高，4k比较合理
	size := 4 * 1024
	buf := make([]byte, size)
	i := 0
	for {
		i++
		if config.DebugLevel >= config.LevelDebug {
			log.Printf("%s receive from %s, n=%d\n", trace.ID(s.req.ID), srcname, i)
		}
		nr, er := src.Read(buf)
		if nr > 0 {
			if config.DebugLevel >= config.LevelDebugBody {
				log.Printf("%s receive from %s, n=%d, data len: %d\n", trace.ID(s.req.ID), srcname, i, nr)
				fmt.Println(trace.ID(s.req.ID), string(buf[0:nr]))
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
			}
			break
		}

	}
	return written, err
}

// transfer 交换数据
func (s *wsTunnel) transfer() {
	if config.DebugLevel >= config.LevelLong {
		log.Println(trace.ID(s.req.ID), "transfer start")
	}

	b := nat.ServerBridge.Register(s.req.ID, s.req.conn)

	var err error
	done := make(chan int, 1)

	//发送请求
	go func() {
		defer func() {
			done <- 1
			close(done)
		}()
		b.Write([]byte(s.buffer.String()))
		s.readSize, err = s.copyBuffer(b, s.req.reader, "client")
		b.CloseWrite()
		s.logCopyErr("client->websocket", err)
		log.Println(trace.ID(s.req.ID), "request body size", s.readSize)
	}()
	//取返回结果
	b.ReadPump()

	<-done
	// 不管是不是正常结束，只要server结束了，函数就会返回，然后底层会自动断开与client的连接
	log.Println(trace.ID(s.req.ID), "websocket transfer finished, response size", s.writeSize)
}

func (s *wsTunnel) logCopyErr(name string, err error) {
	if err == nil {
		return
	}
	if config.DebugLevel >= config.LevelLong {
		log.Println(trace.ID(s.req.ID), name, err.Error())
	} else if err != io.EOF {
		log.Println(trace.ID(s.req.ID), name, err.Error())
	}
}
