package proto

import (
	"context"
	"errors"
	"log"
	"net"

	"github.com/keminar/anyproxy/utils/trace"
)

// ServerHandler 服务端处理
func ServerHandler(ctx context.Context, tcpConn *net.TCPConn) error {
	req := NewRequest(ctx, tcpConn)

	// test if the underlying fd is nil
	remoteAddr := tcpConn.RemoteAddr()
	if remoteAddr == nil {
		log.Println(trace.ID(req.ID), "ClientHandler(): oops, clientConn.fd is nil!")
		return errors.New("clientConn.fd is nil")
	}
	log.Println(trace.ID(req.ID), "remoteAddr:"+remoteAddr.String())

	ok, err := req.ReadRequest("server")
	if err != nil && ok == false {
		log.Println("req err", err.Error())
		return err
	}

	// server 只支持通过client/server和server连接，后续还要加安全密钥检查
	if req.Proto != "http" {
		return errors.New("Not http method")
	}
	stream, ok := req.Stream.(*httpStream)
	if !ok || stream.Method != "CONNECT" {
		return errors.New("Not CONNECT method")
	}
	return req.Stream.response()
}
