package proto

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/keminar/anyproxy/utils/trace"
)

// KeepHandler HTTP/1.1复用处理
func KeepHandler(ctx context.Context, tcpConn *net.TCPConn, buf []byte) error {
	req := NewRequestWithBuf(ctx, tcpConn, buf)

	// test if the underlying fd is nil
	remoteAddr := tcpConn.RemoteAddr()
	if remoteAddr == nil {
		log.Println(trace.ID(req.ID), "ClientHandler(): oops, clientConn.fd is nil!")
		return errors.New("clientConn.fd is nil")
	}
	// 日志方便查询有走到keep.go的记录
	log.Println(trace.ID(req.ID), "remoteAddr:"+remoteAddr.String())

	// 和client.go统一代码好维护
	ok, err := req.ReadRequest("client")
	if err != nil && !ok {
		log.Println(trace.ID(req.ID), "req err", err.Error())
		return err
	}
	// 增加一个协议判断的日志
	if req.Proto != "http" {
		err = fmt.Errorf("is not http request %s: %s", req.Proto, string(buf))
		log.Println(trace.ID(req.ID), err.Error())
		return err
	}
	return req.Stream.response()
}

// 预判后面的包是不是http链接
func isKeepAliveHttp(ctx context.Context, tcpConn *net.TCPConn, buf []byte) bool {
	req := NewRequestWithBuf(ctx, tcpConn, buf)
	req.ReadRequest("client")
	return req.Proto == "http"
}
