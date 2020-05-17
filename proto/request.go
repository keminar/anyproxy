package proto

import (
	"bufio"
	"bytes"
	"io"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
	"sync"
)

type Request struct {
	ReadBuf    bytes.Buffer
	reader     *bufio.Reader
	IsHTTP     bool
	Method     string
	RequestURI string
	URL        *url.URL
	Proto      string
	Host       string
	Header     http.Header
}

func NewRequest(conn *net.TCPConn) *Request {
	c := &Request{
		reader: bufio.NewReader(conn),
	}
	return c
}

func (that *Request) ReadRequest() (err error) {
	tp := newTextprotoReader(that.reader)
	// First line: GET /index.html HTTP/1.0
	var s string
	if s, err = tp.ReadLine(); err != nil {
		return err
	}
	defer func() {
		putTextprotoReader(tp)
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
	}()

	var ok bool
	that.Method, that.RequestURI, that.Proto, ok = parseRequestLine(s)
	if !ok {
		// 非http请求, 后面按tcp处理
		return nil
	}

	if !that.validMethod() {
		// 非http请求, 后面按tcp处理
		return nil
	}
	rawurl := that.RequestURI
	justAuthority := that.Method == "CONNECT" && !strings.HasPrefix(rawurl, "/")
	if justAuthority {
		//CONNECT是http的,如果RequestURI不是/开头,则为域名且不带http://, 这里补上
		rawurl = "http://" + rawurl
	}

	if that.URL, err = url.ParseRequestURI(rawurl); err != nil {
		return err
	}

	if justAuthority {
		// Strip the bogus "http://" back off.
		// 还原Scheme值为空
		that.URL.Scheme = ""
	}

	// 读取http的头部信息
	// Subsequent lines: Key: value.
	mimeHeader, err := tp.ReadMIMEHeader()
	if err != nil {
		return err
	}
	that.Header = http.Header(mimeHeader)
	that.Host = that.URL.Host
	if that.Host == "" {
		that.Host = that.Header.Get("Host")
	}
	return
}

func (that *Request) validMethod() bool {
	allMethods := []string{"CONNECT", "OPTIONS", "DELETE", "TRACE", "POST", "HEAD", "GET", "PUT"}
	for _, one := range allMethods {
		if one == that.Method {
			that.IsHTTP = true
		}
	}
	return that.IsHTTP
}

var textprotoReaderPool sync.Pool

func newTextprotoReader(br *bufio.Reader) *textproto.Reader {
	if v := textprotoReaderPool.Get(); v != nil {
		tr := v.(*textproto.Reader)
		tr.R = br
		return tr
	}
	return textproto.NewReader(br)
}

func putTextprotoReader(r *textproto.Reader) {
	r.R = nil
	textprotoReaderPool.Put(r)
}

// parseRequestLine parses "GET /foo HTTP/1.1" into its three parts.
func parseRequestLine(line string) (method, requestURI, proto string, ok bool) {
	s1 := strings.Index(line, " ")
	s2 := strings.Index(line[s1+1:], " ")
	if s1 < 0 || s2 < 0 {
		return
	}
	s2 += s1 + 1
	return line[:s1], line[s1+1 : s2], line[s2+1:], true
}
