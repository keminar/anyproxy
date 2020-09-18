package proto

import (
	"context"
	"fmt"
	"log"
	"net"
)

// KeepHandler HTTP/1.1复用处理
func KeepHandler(ctx context.Context, tcpConn *net.TCPConn, buf []byte) error {
	req := NewRequestWithBuf(ctx, tcpConn, buf)
	var s *httpStream
	s = newHTTPStream(req)

	// 直接用http实例请求
	var err error
	ok := s.readFistLine()
	if !ok {
		err = fmt.Errorf("is not http request: %s", string(buf))
		log.Println(err.Error())
		return err
	}
	ok, err = s.readRequest("client")
	if err != nil && ok == false {
		log.Println("req err", err.Error())
		return err
	}
	// 直接用http实例返回
	return s.response()
}
