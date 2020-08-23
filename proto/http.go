package proto

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strconv"
	"strings"

	"github.com/keminar/anyproxy/config"
	"github.com/keminar/anyproxy/crypto"
	"github.com/keminar/anyproxy/proto/http"
	"github.com/keminar/anyproxy/proto/text"
	"github.com/keminar/anyproxy/utils/trace"
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
	BodyBuf    []byte
}

func newHTTPStream(req *Request) *httpStream {
	c := &httpStream{
		req: req,
	}
	return c
}

// 检查是不是HTTP请求
func (that *httpStream) validHead() bool {
	if that.req.reader.Buffered() < 8 {
		return false
	}
	tmpBuf, err := that.req.reader.Peek(8)
	if err != nil {
		return false
	}
	// 解析方法名
	s1 := bytes.IndexByte(tmpBuf, ' ')
	if s1 < 0 {
		return false
	}
	that.Method = strings.ToUpper(string(tmpBuf[:s1]))

	allMethods := []string{"CONNECT", "OPTIONS", "DELETE", "TRACE", "POST", "HEAD", "GET", "PUT"}
	for _, one := range allMethods {
		if one == that.Method {
			return true
		}
	}
	return false
}

func (that *httpStream) readRequest(from string) (canProxy bool, err error) {
	// 下面是http的内容了，用封装的reader比较好按行取内容
	tp := text.NewReader(that.req.reader)
	// First line: GET /index.html HTTP/1.0
	if that.FirstLine, err = tp.ReadLine(true); err != nil {
		return false, err
	}

	var ok bool
	that.RequestURI, that.Proto, ok = parseRequestLine(that.FirstLine)
	if !ok {
		// 格式非http请求, 报错
		return false, errors.New("not http request format")
	}

	rawurl := that.RequestURI
	if that.Method == "CONNECT" && from == "server" {
		key := []byte(getToken())
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
	that.Header, err = tp.ReadHeader()
	if err != nil {
		return false, err
	}
	that.Host = that.URL.Host
	if that.Host == "" {
		that.Host = that.Header.Get("Host")
	}
	//that.Header.Set("Connection", "Close")
	that.BodyBuf = that.req.reader.UnreadBuf()
	that.getNameIPPort()

	//debug
	if config.DebugLevel == config.LevelDebug {
		fmt.Println(trace.ID(that.req.ID), that.FirstLine)
		for k, v := range that.Header {
			fmt.Println(trace.ID(that.req.ID), k, "=", v)
		}
		fmt.Println(trace.ID(that.req.ID), string(that.BodyBuf))
	}
	return true, nil
}

// getNameIPPort 分析请求目标
func (that *httpStream) getNameIPPort() {
	splitStr := strings.Split(that.Host, ":")
	that.req.DstName = splitStr[0]
	if len(splitStr) == 2 {
		// 优先Host中的端口
		c, _ := strconv.ParseUint(splitStr[1], 0, 16)
		that.req.DstPort = uint16(c)
		if that.req.DstPort > 0 {
			return
		}
	}

	c, _ := strconv.ParseUint(that.URL.Port(), 0, 16)
	that.req.DstPort = uint16(c)
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

// badRequest 400响应
func (that *httpStream) badRequest(err error) {

	const errorHeaders = "\r\nContent-Type: text/plain; charset=utf-8\r\nConnection: close\r\n\r\n"

	publicErr := "400 Bad Request"
	if err != nil {
		publicErr = "400 Bad Request" + ": " + err.Error()
	}

	fmt.Fprintf(that.req.conn, "HTTP/1.1 "+publicErr+errorHeaders+publicErr)
}

func (that *httpStream) response() error {
	tunnel := newTunnel(that.req)
	if ip, ok := tunnel.isAllowed(); !ok {
		err := errors.New(ip + " is not allowed")
		that.badRequest(err)
		return err
	}
	if that.Method == "CONNECT" {
		_, err := that.req.conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		if err != nil {
			log.Println(trace.ID(that.req.ID), "write err", err.Error())
			return err
		}

		that.showIP("CONNECT")
		err = tunnel.handshake(protoHTTP, that.req.DstName, "", that.req.DstPort)
		if err != nil {
			log.Println(trace.ID(that.req.ID), "handshake err", err.Error())
			return err
		}
		tunnel.transfer(that.req.conn, -1)
	} else {
		that.showIP("HTTP")
		err := tunnel.handshake(protoHTTP, that.req.DstName, "", that.req.DstPort)
		if err != nil {
			log.Println(trace.ID(that.req.ID), "handshake err", err.Error())
			return err
		}

		// 先将请求头部发出
		tunnel.conn.Write([]byte(fmt.Sprintf("%s\r\n", that.FirstLine)))
		that.Header.Write(tunnel.conn)
		tunnel.conn.Write([]byte("\r\n"))
		// 多读取的body部分
		tunnel.conn.Write(that.BodyBuf)

		clientUnRead := -1
		if that.Proto == "HTTP/1.1" {
			clientUnRead = 0
			if contentLen, ok := that.Header["Content-Length"]; ok {
				if bodyLen, err := parseContentLength(contentLen[0]); err == nil {
					fmt.Println(bodyLen, len(that.BodyBuf))
					clientUnRead = int(bodyLen) - len(that.BodyBuf)
				}
			}
		}
		tunnel.transfer(that.req.conn, clientUnRead)
	}
	return nil
}

func (that *httpStream) showIP(method string) {
	if method == "CONNECT" {
		log.Println(trace.ID(that.req.ID), fmt.Sprintf("%s %s -> %s:%d", method, that.req.conn.RemoteAddr().String(), that.req.DstName, that.req.DstPort))
	} else {
		log.Println(trace.ID(that.req.ID), fmt.Sprintf("%s %s -> %s", method, that.req.conn.RemoteAddr().String(), that.Request()))
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

// parseContentLength trims whitespace from s and returns -1 if no value
// is set, or the value if it's >= 0.
func parseContentLength(cl string) (int64, error) {
	cl = strings.TrimSpace(cl)
	if cl == "" {
		return -1, nil
	}
	n, err := strconv.ParseInt(cl, 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("bad Content-Length %s", cl)
	}
	return n, nil
}
