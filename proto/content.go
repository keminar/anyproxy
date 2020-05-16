package proto

import (
	"net"
	"log"
	"io"
	"bytes"
	"regexp"
)

/*
GET
PUT
HEAD
POST
TRACE
DELETE
CONNECT
OPTIONS
*/

var HTTPReqExp = regexp.MustCompile("^[a-zA-Z]+\\s+([^\\s]+)\\s+HTTP/1.\\d")

type Content struct {
	ReadBuf bytes.Buffer
	tcpConn *net.TCPConn
	TcpType string
	HttpMethod string
}

func NewContent(tcpConn *net.TCPConn) *Content {
	c := &Content{
		tcpConn: tcpConn,
	}
	return c
}

func (that *Content) ReadLine() (err error) {
	b := make([]byte, 7)
	for {
		var nr int
		nr, err = that.tcpConn.Read(b[:])
		log.Println(nr, string(b[0:nr]))
		if err == io.EOF {		
			if len(that.ReadBuf.Bytes()) != 0 {
				err = nil
				return
			}
			log.Println("read EOF")
			return
		}
		if err != nil {
			log.Println("ReadLine error", err.Error())
			return
		}
		that.ReadBuf.Write(b[:nr])
		if that.TcpType == "" {
			if !that.isHttp() {
				return
			}
		}
		for i:=0 ; i<nr; i++ {
			if b[i] == '\n'  {
				// 不能用break 因为只能跳一层for
				return
			}
		}
		if that.ReadBuf.Len() > 10240 {
			return
		}
	}
	return
}

func (that *Content) isHttp() bool {
	if that.TcpType != "" {
		return that.TcpType == "http"
	}
	word := that.ReadBuf.Bytes()[0:7]
	if string(word[0:7]) == "CONNECT" ||  string(word[0:7]) == "OPTIONS" {
		that.TcpType = "http"
		that.HttpMethod = string(word[0:7])
	} else if string(word[0:6]) == "DELETE" {
		that.TcpType = "http"
		that.HttpMethod = string(word[0:6])
	} else if string(word[0:5]) == "TRACE" {
		that.TcpType = "http"
		that.HttpMethod = string(word[0:5])
	} else if string(word[0:4]) == "POST" ||  string(word[0:7]) == "HEAD" {
		that.TcpType = "http"
		that.HttpMethod = string(word[0:4])
	} else if string(word[0:3]) == "GET" ||  string(word[0:7]) == "PUT" {
		that.TcpType = "http"
		that.HttpMethod = string(word[0:3])
	} else {
		that.TcpType = "tcp"
	}
	return that.TcpType == "http"
}