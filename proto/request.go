package proto

import (
	"context"
	"net"

	"github.com/keminar/anyproxy/utils/conf"

	"github.com/keminar/anyproxy/grace"
	"github.com/keminar/anyproxy/proto/tcp"
)

// AesToken 加密密钥
var AesToken = "anyproxy"

// Request 请求类
type Request struct {
	ID     uint
	conn   *net.TCPConn
	reader *tcp.Reader
	Proto  string //http

	Stream  stream
	DstName string //目标域名
	DstIP   string //目标ip
	DstPort uint16 //目标端口
}

// NewRequest 请求类
func NewRequest(ctx context.Context, conn *net.TCPConn) *Request {
	// 取traceID
	traceID, _ := ctx.Value(grace.TraceIDContextKey).(uint)
	c := &Request{
		ID:     traceID,
		conn:   conn,
		reader: tcp.NewReader(conn),
	}
	return c
}

// ReadRequest 分析请求内容
func (that *Request) ReadRequest(from string) (canProxy bool, err error) {
	_, err = that.reader.Peek(1)
	if err != nil {
		return false, err
	}

	var s stream
	protos := []string{"http"}
	for _, v := range protos {
		switch v {
		case "http":
			s = newHTTPStream(that)
			if s.validHead() {
				that.Proto = v
				break
			}
		}
	}
	if that.Proto == "" {
		s = newTCPStream(that)
		that.Proto = "tcp"
	}
	that.Stream = s
	return s.readRequest(from)
}

// 加密Token
func getToken() string {
	if conf.RouterConfig.Token == "" {
		return AesToken
	}
	return conf.RouterConfig.Token
}
