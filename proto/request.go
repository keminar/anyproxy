package proto

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"net"
	"time"

	"github.com/keminar/anyproxy/utils/conf"

	"github.com/keminar/anyproxy/grace"
	"github.com/keminar/anyproxy/proto/tcp"
)

// AesToken 加密密钥默认值, 不再要求配置的 token 必须凑够16位, 见 getAesKey
var AesToken = "anyproxyproxyany"

// readRequestTimeout 读完整个请求头(首行 + 头部)的上限。
//
// 没有这个上限时, 一个完成了 TCP 握手却一个字节都不发的客户端, 会让 ReadRequest 里
// 那句 Peek(1) 永远阻塞, 白占一个 goroutine 和一个 fd 直到 OS 的 TCP keepalive 生效
// (默认 2 小时) —— 即 slowloris。同理"一次发一个字节、永不结束请求头"也是这条路。
//
// 只盖请求头阶段: 读完就清掉(见 ReadRequest 的 defer), 之后的数据转发是长连接, 本来
// 就该允许长时间静默。
//
// 30s 取值: 比 sniffTimeoutHTTP(5s, 那是"等首包冒头"的探测)宽得多, 因为这里要等的是
// 整个请求头读完, 慢速移动网络上确实会慢; 但又远短于 keepalive 的 2 小时。代理端口上
// 的协议(HTTP/SOCKS5)一律是客户端先说话, 所以这个超时不会误伤"服务端先说话"的协议
// —— 那类流量走的是 TUN 的 ForwardTCP, 不经过这里。
const readRequestTimeout = 30 * time.Second

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
	TUN     bool   // 来自 TUN 设备，DstIP 已由内核路由确定，无需本地 DNS 重解析
	Raw     bool   // 原始字节流透传(socks5/tun): 不是 http.go 解析改写成绝对形式的请求，走 http 上级代理时须用 CONNECT 隧道而非直发
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
	if conf.RouterConfig().TcpCopy.Enable {
		if conf.RouterConfig().TcpCopy.IP != "" && conf.RouterConfig().TcpCopy.Port > 0 {
			s := newTCPCopy(that)
			that.Proto = "tcp"
			that.Stream = s
			return s.readRequest(from)
		}
	}
	// 读请求头期间加超时, 读完(无论成败)立刻清掉: 后面的转发是长连接, 静默是正常的。
	// 放在 tcpcopy 分支之后: 那条路直接返回、不读任何东西, 没有要保护的阻塞点。
	if that.conn != nil {
		_ = that.conn.SetReadDeadline(time.Now().Add(readRequestTimeout))
		defer func() {
			_ = that.conn.SetReadDeadline(time.Time{})
			if err != nil {
				// 超时会把错误挂在 reader 上, 不清掉会影响后续读取(同 socks5.go
				// sniffProto 的处理)。
				that.reader.ResetErr()
			}
		}()
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
	if conf.RouterConfig().Token == "" {
		return AesToken
	}
	return conf.RouterConfig().Token
}

// getAesKey 把配置的 token 归一化成 AES-128 要求的16字节key, 两端只要 token 配的
// 字符串相同, 不管长度多少都能派生出同一把key: 超过16位截取前16位, 不足16位则先
// md5(32位hex)再取前16位。这样配置 token 时不用再手数着凑够16个字符。
func getAesKey() []byte {
	token := getToken()
	if len(token) == 16 {
		return []byte(token)
	}
	if len(token) > 16 {
		return []byte(token[:16])
	}
	sum := md5.Sum([]byte(token))
	return []byte(hex.EncodeToString(sum[:])[:16])
}
