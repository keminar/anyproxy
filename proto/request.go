package proto

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"

	"github.com/keminar/anyproxy/grace"
)

// AesToken 加密密钥
var AesToken = "hgfedcba87654321"

// Request 请求类
type Request struct {
	ID     uint
	conn   *net.TCPConn
	reader *bufio.Reader
	Proto  string //http

	Stream   stream
	FirstBuf []byte //前8个字节
	DstName  string //目标域名
	DstIP    string //目标ip
	DstPort  uint16 //目标端口
}

// NewRequest 请求类
func NewRequest(ctx context.Context, conn *net.TCPConn) *Request {
	// 取traceID
	traceID, _ := ctx.Value(grace.TraceIDContextKey).(uint)
	c := &Request{
		ID:     traceID,
		conn:   conn,
		reader: bufio.NewReader(conn),
	}
	return c
}

func (that *Request) readHead() error {
	// http.Method 不会超过7位,再多加一个空格
	num := 8
	tmp := make([]byte, num)
	for {
		// 这里一定要用*net.TCPConn来读
		// 如用*bufio.Reader会多读导致后面转发取不到内容
		nr, err := that.conn.Read(tmp[:])
		if err == io.EOF {
			return err
		}
		that.FirstBuf = append(that.FirstBuf, tmp[:nr]...)
		if len(that.FirstBuf) >= num {
			return nil
		}
	}
}

// ReadRequest 分析请求内容
func (that *Request) ReadRequest(from string) (canProxy bool, err error) {
	err = that.readHead()
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

// TraceID 日志ID
func TraceID(id uint) string {
	return fmt.Sprintf("ID #%d,", id)
}
