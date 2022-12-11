package proto

import (
	"context"
	"net"

	"github.com/keminar/anyproxy/utils/conf"

	"github.com/keminar/anyproxy/grace"
	"github.com/keminar/anyproxy/proto/tcp"
)

// AesToken 加密密钥, 必须16位长度
var AesToken = "anyproxyproxyany"

// Request 请求类
type Request struct {
	ID     uint
	ctx    context.Context
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
		ctx:    ctx,
		ID:     traceID,
		conn:   conn,
		reader: tcp.NewReader(conn),
	}
	return c
}

// NewRequestWithBuf 请求类，前带buf内容
func NewRequestWithBuf(ctx context.Context, conn *net.TCPConn, buf []byte) *Request {
	// 取traceID
	traceID, _ := ctx.Value(grace.TraceIDContextKey).(uint)
	c := &Request{
		ctx:    ctx,
		ID:     traceID,
		conn:   conn,
		reader: tcp.NewReaderWithBuf(conn, buf),
	}
	return c
}

// ReadRequest 分析请求内容
func (that *Request) ReadRequest(from string) (canProxy bool, err error) {
	//如果启用了tcpcopy 且目标地址也有配置，则进行tcpcopy转发
	if conf.RouterConfig.TcpCopy.Enable {
		if conf.RouterConfig.TcpCopy.IP != "" && conf.RouterConfig.TcpCopy.Port > 0 {
			s := newTCPCopy(that)
			that.Proto = "tcp"
			that.Stream = s
			return s.readRequest(from)
		}
	}
	_, err = that.reader.Peek(1)
	if err != nil {
		return false, err
	}

	var s stream
	protos := []string{"http", "socks5"}
	for _, v := range protos {
		switch v {
		case "http":
			s = newHTTPStream(that)
			if s.validHead() {
				that.Proto = v
				break
			}
		case "socks5":
			s = newSocks5Stream(that)
			if s.validHead() {
				that.Proto = v
				break
			}
		}
		if that.Proto != "" {
			break
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
