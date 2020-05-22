package proto

import (
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"

	"github.com/keminar/anyproxy/crypto"
)

// badRequestError is a literal string (used by in the server in HTML,
// unescaped) to tell the user why their request was bad. It should
// be plain text without user info or other embedded errors.
type badRequestError string

func (e badRequestError) Error() string { return "Bad Request: " + string(e) }

type httpStream struct {
	req        *Request
	Method     string      // http请求方法
	RequestURI string      //读求原值，非解密值
	URL        *url.URL    //http请求地址信息
	Proto      string      //形如 http/1.0 或 http/1.1
	Host       string      //域名含端口
	Header     http.Header //http请求头部
	FirstLine  string      //第一行字串
}

func newHTTPStream(req *Request) *httpStream {
	c := &httpStream{
		req: req,
	}
	return c
}

// 检查是不是HTTP请求
func (that *httpStream) validHead() bool {
	// 解析方法名
	tmpStr := string(that.req.FirstBuf)
	s1 := strings.Index(tmpStr, " ")
	if s1 < 0 {
		return false
	}
	that.Method = strings.ToUpper(tmpStr[:s1])

	allMethods := []string{"CONNECT", "OPTIONS", "DELETE", "TRACE", "POST", "HEAD", "GET", "PUT"}
	for _, one := range allMethods {
		if one == that.Method {
			return true
		}
	}
	return false
}

func (that *httpStream) readRequest(from string) (canProxy bool, err error) {
	// 下面是http的内容了，用*bufio.Reader比较好按行取内容
	tp := textproto.NewReader(that.req.reader)
	// First line: GET /index.html HTTP/1.0
	if that.FirstLine, err = tp.ReadLine(); err != nil {
		return false, err
	}
	that.FirstLine = string(that.req.FirstBuf) + that.FirstLine

	var ok bool
	that.RequestURI, that.Proto, ok = parseRequestLine(that.FirstLine)
	if !ok {
		// 格式非http请求, 报错
		return false, errors.New("not http request format")
	}

	rawurl := that.RequestURI
	if that.Method == "CONNECT" && from == "server" {
		key := []byte(AesToken)
		x1, err := base64.StdEncoding.DecodeString(that.RequestURI)
		if err != nil {
			return false, err
		}
		if len(x1) > 0 {
			x2, err := crypto.DecryptAES(x1, key)
			if err != nil {
				return false, err
			}
			rawurl = string(x2)
		}
	}
	justAuthority := that.Method == "CONNECT" && !strings.HasPrefix(rawurl, "/")
	if justAuthority {
		//CONNECT是http的,如果RequestURI不是/开头,则为域名且不带http://, 这里补上
		rawurl = "http://" + rawurl
	}

	if that.URL, err = url.ParseRequestURI(rawurl); err != nil {
		return false, err
	}

	// 读取http的头部信息
	// Subsequent lines: Key: value.
	mimeHeader, err := tp.ReadMIMEHeader()
	if err != nil {
		return false, err
	}
	that.Header = http.Header(mimeHeader)
	that.Host = that.URL.Host
	if that.Host == "" {
		that.Host = that.Header.Get("Host")
	}
	that.getNameIPPort()
	return true, nil
}

// getNameIPPort 分析请求目标
func (that *httpStream) getNameIPPort() {
	splitStr := strings.Split(that.Host, ":")
	that.req.DstName = splitStr[0]
	upIPs, _ := net.LookupIP(splitStr[0])
	if len(upIPs) > 0 {
		that.req.DstIP = upIPs[0].String()
		c, _ := strconv.ParseUint(that.URL.Port(), 0, 16)
		that.req.DstPort = uint16(c)
	}
	if that.req.DstPort == 0 {
		if that.URL.Scheme == "https" {
			that.req.DstPort = 443
		} else {
			that.req.DstPort = 80
		}
	}
}

// Request 请求地址
func (that *httpStream) Request() string {
	if that.RequestURI[0] == '/' {
		return that.Host + that.RequestURI
	}
	return that.RequestURI
}

// BadRequest 400响应
func (that *httpStream) BadRequest(err error) {

	const errorHeaders = "\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n"

	publicErr := "400 Bad Request"
	if err != nil {
		publicErr = "400 Bad Request" + ": " + err.Error()
	}

	fmt.Fprintf(that.req.conn, "HTTP/1.1 "+publicErr+errorHeaders+publicErr)
}

func (that *httpStream) response() error {
	tunnel := newTunnel(that.req)
	if that.Method == "CONNECT" {
		_, err := that.req.conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		if err != nil {
			log.Println(TraceID(that.req.ID), "write err", err.Error())
			return err
		}

		that.showIP("CONNECT")
		err = tunnel.handshake(that.req.DstName, that.req.DstIP, that.req.DstPort)
		if err != nil {
			log.Println(TraceID(that.req.ID), "dail err", err.Error())
			return err
		}
		tunnel.transfer(that.req.conn)
	} else {
		that.showIP("HTTP")
		err := tunnel.handshake(that.req.DstName, that.req.DstIP, that.req.DstPort)
		if err != nil {
			log.Println(TraceID(that.req.ID), "dail err", err.Error())
			return err
		}

		// 先将请求头部发出
		tunnel.conn.Write([]byte(fmt.Sprintf("%s\r\n", that.FirstLine)))
		that.Header.Write(tunnel.conn)
		tunnel.conn.Write([]byte("\r\n"))

		tunnel.transfer(that.req.conn)
	}
	return nil
}

func (that *httpStream) showIP(method string) {
	if method == "CONNECT" {
		log.Println(TraceID(that.req.ID), fmt.Sprintf("%s %s -> %s:%d", method, that.req.conn.RemoteAddr().String(), that.req.DstName, that.req.DstPort))
	} else {
		log.Println(TraceID(that.req.ID), fmt.Sprintf("%s %s -> %s", method, that.req.conn.RemoteAddr().String(), that.Request()))
	}
}

// parseRequestLine parses "GET /foo HTTP/1.1" into its three parts.
func parseRequestLine(line string) (requestURI, proto string, ok bool) {
	s1 := strings.Index(line, " ")
	s2 := strings.Index(line[s1+1:], " ")
	if s1 < 0 || s2 < 0 {
		return
	}
	s2 += s1 + 1
	return line[s1+1 : s2], line[s2+1:], true
}
