package proto

import (
	"context"
	"errors"
	"log"
	"net"

	"github.com/keminar/anyproxy/utils/trace"
)

// ClientHandler 客户端处理
func ClientHandler(ctx context.Context, tcpConn *net.TCPConn) error {
	req := NewRequest(ctx, tcpConn)

	// test if the underlying fd is nil
	remoteAddr := tcpConn.RemoteAddr()
	if remoteAddr == nil {
		log.Println(trace.ID(req.ID), "ClientHandler(): oops, clientConn.fd is nil!")
		return errors.New("clientConn.fd is nil")
	}
	log.Println(trace.ID(req.ID), "remoteAddr:"+remoteAddr.String())

	ok, err := req.ReadRequest("client")
	if err != nil && ok == false {
		log.Println("req err", err.Error())
		return err
	}
	return req.Stream.response()
}
