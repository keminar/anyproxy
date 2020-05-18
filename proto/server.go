package proto

import (
	"errors"
	"log"
	"net"
)

// Server 服务端
type Server struct {
	req *Request
}

// NewServer 服务端初始化
func NewServer() *Server {
	c := &Server{}
	return c
}

// Handler 服务端处理
func (that *Server) Handler(tcpConn *net.TCPConn) error {
	that.req = NewRequest(tcpConn)
	_, err := that.req.ReadRequest("server")
	if err != nil {
		return err
	}
	// server 只支持通过client或是server连接，后续还要加安全密钥检查
	if that.req.Method != "CONNECT" {
		return errors.New("Not CONNECT method")
	}
	log.Println(that.req.IsHTTP, that.req.Method, that.req.RequestURI)
	log.Println(that.req.URL.Scheme, that.req.URL.Host, that.req.URL.Port(), that.req.Header)

	//建立隧道
	_, err = tcpConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	if err != nil {
		log.Println("write err", err.Error())
		return err
	}

	log.Println("PROXY=>", that.req.DstIP, that.req.DstPort)
	rightConn, err := dail(that.req.DstIP, that.req.DstPort)
	if err != nil {
		log.Println("dail err", err.Error())
		return err
	}
	transfer(tcpConn, rightConn)
	return nil
}
