package proto

import (
	"context"
	"log"
	"net"
)

// KeepHandler HTTP/1.1复用处理
func KeepHandler(ctx context.Context, tcpConn *net.TCPConn, buf []byte) error {
	req := NewRequestWithBuf(ctx, tcpConn, buf)
	var s stream
	s = newHTTPStream(req)

	// 直接用http实例请求
	ok, err := s.readRequest("client")
	if err != nil && ok == false {
		log.Println("req err", err.Error())
		return err
	}
	// 直接用http实例返回
	return s.response()
}
