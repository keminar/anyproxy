package proto

import (
	"bytes"
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

// transfer 交换数据
func (s *wsTunnel) transfer() {
	if config.DebugLevel >= config.LevelLong {
		log.Println(trace.ID(s.req.ID), "websocket transfer start")
	}

	b := nat.ServerBridge.Register(nat.ServerHub, s.req.ID, s.req.conn)
	defer func() {
		nat.ServerBridge.Unregister(b)
	}()

	// 发送创建连接请求
	b.Open()
	var err error
	done := make(chan int, 1)

	//发送请求
	go func() {
		defer func() {
			done <- 1
			close(done)
		}()
		b.Write([]byte(s.buffer.String()))
		s.readSize, err = b.CopyBuffer(b, s.req.reader, "client")
		s.logCopyErr("client->websocket", err)
		log.Println(trace.ID(s.req.ID), "request body size", s.readSize)
		b.CloseWrite()
	}()
	//取返回结果
	b.WritePump()

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
