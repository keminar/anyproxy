package proto

import (
	"fmt"
	"log"
	"net"
)

// Client 客户端
type Client struct {
	req *Request
}

// NewClient 客户端初始化
func NewClient() *Client {
	c := &Client{}
	return c
}

// Handler 客户端处理
func (that *Client) Handler(tcpConn *net.TCPConn) error {
	that.req = NewRequest(tcpConn)
	ok, err := that.req.ReadRequest("client")
	if err != nil && ok == false {
		log.Println("req err", err.Error())
		return err
	}
	if that.req.Method == "CONNECT" {
		log.Println(that.req.IsHTTP, that.req.Method, that.req.RequestURI)
		log.Println(that.req.URL.Scheme, that.req.URL.Host, that.req.URL.Port(), that.req.Header)

		_, err := tcpConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		if err != nil {
			log.Println("write err", err.Error())
			return err
		}
		log.Println("CONNECT->", that.req.DstName, that.req.DstIP, that.req.DstPort)
		rightConn, err := handshake(that.req.DstName, that.req.DstIP, that.req.DstPort)
		if err != nil {
			log.Println("dail err", err.Error())
			return err
		}
		transfer(tcpConn, rightConn)
	} else if that.req.IsHTTP {
		log.Println(that.req.IsHTTP, that.req.Method, that.req.RequestURI)
		log.Println(that.req.URL.Scheme, that.req.URL.Host, that.req.URL.Port(), that.req.Header)

		log.Println("HTTP->", that.req.DstName, that.req.DstIP, that.req.DstPort)
		rightConn, err := handshake(that.req.DstName, that.req.DstIP, that.req.DstPort)
		if err != nil {
			log.Println("dail err", err.Error())
			return err
		}

		// 先将请求头部发出
		rightConn.Write([]byte(fmt.Sprintf("%s\r\n", that.req.FirstLine)))
		that.req.Header.Write(rightConn)
		rightConn.Write([]byte("\r\n"))

		transfer(tcpConn, rightConn)
	} else {
		// tcp请求
		dstIP, dstPort, tcpConn, err := GetOriginalDstAddr(tcpConn)
		if err != nil {
			log.Println("GetOriginalDstAddr err", err.Error())
			return err
		}

		log.Println("TCP->", dstIP, dstPort)
		rightConn, err := handshake("", dstIP, uint16(dstPort))
		if err != nil {
			log.Println("dail err", err.Error())
			return err
		}

		// 将前8个字节补上
		rightConn.Write(that.req.FirstBuf)
		transfer(tcpConn, rightConn)
	}
	return nil
}
