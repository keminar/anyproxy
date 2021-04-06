package proto

import (
	"bytes"
	"io"
	"log"

	"github.com/keminar/anyproxy/config"
	"github.com/keminar/anyproxy/nat"
	"github.com/keminar/anyproxy/proto/http"
	"github.com/keminar/anyproxy/utils/trace"
)

// 转发实体
type wsTunnel struct {
	req    *Request
	header http.Header

	readSize  int64
	writeSize int64

	buffer *bytes.Buffer
}

// newTunnel 实例
func newWsTunnel(req *Request, header http.Header) *wsTunnel {
	s := &wsTunnel{
		req:    req,
		header: header,
		buffer: new(bytes.Buffer),
	}
	return s
}

// transfer 交换数据
func (s *wsTunnel) transfer() bool {
	if config.DebugLevel >= config.LevelLong {
		log.Println(trace.ID(s.req.ID), "websocket transfer start")
	}

	c := nat.ServerHub.GetClient(s.header)
	if c == nil {
		// 走旧转发
		return false
	}
	b := nat.ServerBridge.Register(c, s.req.ID, s.req.conn)
	defer func() {
		b.Unregister(b)
	}()

	// 发送创建连接请求
	b.Open()
	var err error
	done := make(chan int, 1)

	//发送请求给websocket
	go func() {
		defer func() {
			done <- 1
			close(done)
		}()
		b.Write([]byte(s.buffer.String()))
		s.readSize, err = b.CopyBuffer(b, s.req.reader, "request")
		s.logCopyErr("request->websocket", err)
		log.Println(trace.ID(s.req.ID), "request body size", s.readSize)
		b.CloseWrite()
	}()
	//取返回结果写入请求端
	s.writeSize, err = b.WritePump()
	s.logCopyErr("websocket->request", err)

	<-done
	// 不管是不是正常结束，只要server结束了，函数就会返回，然后底层会自动断开与client的连接
	log.Println(trace.ID(s.req.ID), "websocket transfer finished, response size", s.writeSize)
	return true
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
