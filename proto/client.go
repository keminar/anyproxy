package proto

import (
	"context"
	"errors"
	"log"
	"net"
)

// ClientHandler 客户端处理
func ClientHandler(ctx context.Context, tcpConn *net.TCPConn) error {
	req := NewRequest(ctx, tcpConn)

	// test if the underlying fd is nil
	remoteAddr := tcpConn.RemoteAddr()
	if remoteAddr == nil {
		log.Println(TraceID(req.ID), "ClientHandler(): oops, clientConn.fd is nil!")
		return errors.New("clientConn.fd is nil")
	}

	ok, err := req.ReadRequest("client")
	if err != nil && ok == false {
		log.Println("req err", err.Error())
		return err
	}
	return req.Stream.response()
}
