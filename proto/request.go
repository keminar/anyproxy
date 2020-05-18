package proto

import (
	"bufio"
	"encoding/base64"
	"errors"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"

	"github.com/keminar/anyproxy/crypto"
)

// AesToken 加密密钥
var AesToken = "hgfedcba87654321"

// Request 请求类
type Request struct {
	conn       *net.TCPConn
	reader     *bufio.Reader
	IsHTTP     bool        //是否为http
	Method     string      // http请求方法
	RequestURI string      //读求原值，非解密值
	URL        *url.URL    //http请求地址信息
	Proto      string      //形如 http/1.0 或 http/1.1
	Host       string      //域名含端口
	Header     http.Header //http请求头部
	FirstBuf   []byte      //前8个字节
	FirstLine  string      //第一行字串
	DstName    string      //目标域名
	DstIP      string      //目标ip
	DstPort    uint16      //目标端口
}

// NewRequest 请求类
func NewRequest(conn *net.TCPConn) *Request {
	c := &Request{
		conn:   conn,
		reader: bufio.NewReader(conn),
	}
	return c
}

func (that *Request) readMethod() error {
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
			break
		}
	}

	// 解析方法名
	tmpStr := string(that.FirstBuf)
	s1 := strings.Index(tmpStr, " ")
	if s1 < 0 {
		return nil
	}
	that.Method = strings.ToUpper(tmpStr[:s1])
	return nil
}

// ReadRequest 分析请求内容
func (that *Request) ReadRequest(from string) (canProxy bool, err error) {
	err = that.readMethod()
	if err != nil {
		return false, err
	}

	if !that.validMethod() {
		// Method非http请求, 后面按tcp处理
		return true, errors.New("not http method")
	}

	// 下面是http的内容了，用*bufio.Reader比较好按行取内容
	tp := textproto.NewReader(that.reader)
	// First line: GET /index.html HTTP/1.0
	if that.FirstLine, err = tp.ReadLine(); err != nil {
		return false, err
	}
	that.FirstLine = string(that.FirstBuf) + that.FirstLine

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

// 检查是不是HTTP请求
func (that *Request) validMethod() bool {
	allMethods := []string{"CONNECT", "OPTIONS", "DELETE", "TRACE", "POST", "HEAD", "GET", "PUT"}
	for _, one := range allMethods {
		if one == that.Method {
			that.IsHTTP = true
		}
	}
	return that.IsHTTP
}

// getNameIPPort 分析请求目标
func (that *Request) getNameIPPort() {
	splitStr := strings.Split(that.Host, ":")
	that.DstName = splitStr[0]
	upIPs, _ := net.LookupIP(splitStr[0])
	if len(upIPs) > 0 {
		that.DstIP = upIPs[0].String()
		c, _ := strconv.ParseUint(that.URL.Port(), 0, 16)
		that.DstPort = uint16(c)
	}
	if that.DstPort == 0 {
		if that.URL.Scheme == "https" {
			that.DstPort = 443
		} else {
			that.DstPort = 80
		}
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
