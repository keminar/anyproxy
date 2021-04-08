package proto

import (
	"bytes"
	"io"
	"log"

	"github.com/keminar/anyproxy/config"
	"github.com/keminar/anyproxy/nat"
	"github.com/keminar/anyproxy/proto/http"
	"github.com/keminar/anyproxy/utils/conf"
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

// 检查ws转发是否允许
func (s *wsTunnel) getTarget(dstName string) (ok bool) {
	if dstName == "" {
		return false
	}
	host := findHost(dstName, dstName)
	var confTarget string
	confTarget = getString(host.Target, conf.RouterConfig.Target, "auto")

	if confTarget == "deny" {
		return false
	}
	return true
}

// transfer 交换数据
func (s *wsTunnel) transfer() bool {
	if config.DebugLevel >= config.LevelLong {
		log.Println(trace.ID(s.req.ID), "websocket transfer start")
	}

	c := nat.ServerHub.GetClient(s.header)
	if c == nil {
		// 走旧转发
		log.Println(trace.ID(s.req.ID), "websocket transfer fail")
		return false
	}
	b := nat.ServerBridge.Register(c, s.req.ID, s.req.conn)
	defer func() {
		b.Unregister()
	}()

	// 发送创建连接请求
	b.Open()
	var err error
	done := make(chan struct{})

	//发送请求给websocket
	go func() {
		defer close(done)
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
