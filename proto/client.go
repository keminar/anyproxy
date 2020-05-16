package proto

import (
	"net"
	"log"
	"fmt"
)

type Client struct {
	content *Content
}

func NewClient() *Client {
	c := &Client{}
	return c
}

func (that *Client) Handler(tcpConn *net.TCPConn) error  {
	that.content =  NewContent(tcpConn)
	that.content.ReadLine()
	log.Println(that.content.ReadBuf.String())
	return nil
}

