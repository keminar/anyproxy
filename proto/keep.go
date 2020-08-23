package proto

import (
	"context"
	"log"
	"net"
)

// KeepHandler 处理
func KeepHandler(ctx context.Context, tcpConn *net.TCPConn, buf []byte) error {
	req := NewRequestWithBuf(ctx, tcpConn, buf)
	var s stream
	s = newHTTPStream(req)

	ok, err := s.readRequest("client")
	if err != nil && ok == false {
		log.Println("req err", err.Error())
		return err
	}
	return req.Stream.response()
}
