package proto

import (
	"bufio"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/keminar/anyproxy/config"
	"github.com/keminar/anyproxy/crypto"
	"github.com/keminar/anyproxy/utils/cache"
	"github.com/keminar/anyproxy/utils/conf"
	"github.com/keminar/anyproxy/utils/trace"
	"golang.org/x/net/proxy"
)

const (
	stateNew int = iota
	stateActive
	stateClosed
)

// 转发实体
type tunnel struct {
	req      *Request
	conn     *net.TCPConn
	curState int

	readSize  int64
	writeSize int64
}

// newTunnel 实例
func newTunnel(req *Request) *tunnel {
	s := &tunnel{
		req: req,
	}
	return s
}

// copyBuffer 传输数据
func (s *tunnel) copyBuffer(dst io.Writer, src io.Reader, dstname string, srcname string) (written int64, err error) {
	size := 32 * 1024
	if l, ok := src.(*io.LimitedReader); ok && int64(size) > l.N {
		if l.N < 1 {
			size = 1
		} else {
			size = int(l.N)
		}
	}
	buf := make([]byte, size)
	i := 0
	for {
		i++
		if config.DebugLevel == config.LevelDebug {
			log.Printf("%s receive from %s, n=%d\n", trace.ID(s.req.ID), srcname, i)
		}
		nr, er := src.Read(buf)
		if nr > 0 {
			if config.DebugLevel == config.LevelDebug {
				log.Printf("%s receive from %s, n=%d, data len: %d\n", trace.ID(s.req.ID), srcname, i, nr)
			}
			nw, ew := dst.Write(buf[0:nr])
			if nw > 0 {
				written += int64(nw)
			}
			if ew != nil {
				err = ew
				break
			}
			if nr != nw {
				err = io.ErrShortWrite
				break
			}
		}
		if er != nil {

			if er != io.EOF {
				err = er
			} else {
				log.Println(trace.ID(s.req.ID), srcname, "read", er.Error())
			}

			if srcname == "client" {
				// 当客户端断开或出错了，服务端也不用再读了，可以关闭，解决读Server卡住不能到EOF的问题
				s.conn.CloseWrite()
				s.curState = stateClosed
			} else {
				// 如果非客户端导致的服务端关闭，则关闭客户端读
				if s.curState != stateClosed {
					dst.(*net.TCPConn).CloseRead()
				}
			}
			break
		}
	}
	return written, err
}

// transfer 交换数据
// leftConn 不用req.conn 有一定原因是leftConn可能会是newTCPConn
func (s *tunnel) transfer(leftConn *net.TCPConn) {
	log.Println(trace.ID(s.req.ID), "transfer start")
	s.curState = stateActive
	done := make(chan int, 1)

	//发送请求
	go func() {
		defer func() {
			done <- 1
			close(done)
		}()
		//不能和外层共用err
		var err error
		s.readSize, err = s.copyBuffer(s.conn, leftConn, "server", "client")
		if err != nil {
			log.Println(trace.ID(s.req.ID), "client->server", err.Error())
		}
		log.Println(trace.ID(s.req.ID), "request body size", s.readSize)
	}()

	var err error
	//取返回结果
	s.writeSize, err = s.copyBuffer(leftConn, s.conn, "client", "server")
	if err != nil {
		log.Println(trace.ID(s.req.ID), "server->client", err.Error())
	}

	<-done
	// 不管是不是正常结束，只要server结束了，函数就会返回，然后底层会自动断开与client的连接
	log.Println(trace.ID(s.req.ID), "transfer finished, response size", s.writeSize)
}

// dail tcp连接
func (s *tunnel) dail(dstIP string, dstPort uint16) (err error) {
	log.Printf("%s accept and create a new connection to server %s:%d\n", trace.ID(s.req.ID), dstIP, dstPort)
	connTimeout := time.Duration(5) * time.Second
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", dstIP, dstPort), connTimeout) // 3s timeout
	if err != nil {
		return
	}
	s.conn = conn.(*net.TCPConn)
	return
}

// DNS解析
func (s *tunnel) lookup(dstName, dstIP string) (string, cache.DialState) {
	state := cache.StateNone
	if dstName != "" {
		dstIP, state = cache.ResolveLookup.Lookup(s.req.ID, dstName)
		if dstIP == "" {
			upIPs, _ := net.LookupIP(dstName)
			if len(upIPs) > 0 {
				dstIP = upIPs[0].String()
				cache.ResolveLookup.Store(dstName, dstIP, cache.StateNew, time.Duration(10)*time.Minute)
				return dstIP, cache.StateNew
			}
		}
	}
	return dstIP, state
}

// 查询配置
func (s *tunnel) findHost(dstName, dstIP string) conf.Host {
	for _, h := range conf.RouterConfig.Hosts {
		confMatch := getString(h.Match, conf.RouterConfig.Match, "equal")
		switch confMatch {
		case "equal":
			if h.Name == dstName || h.Name == dstIP {
				return h
			}
		case "contain":
			if strings.Contains(dstName, h.Name) || strings.Contains(dstIP, h.Name) {
				return h
			}
		default:
			//todo
		}
	}
	return conf.Host{}
}

// 取值，如为空取默认
func getString(val string, def string, def2 string) string {
	if val == "" {
		if def == "" {
			return def2
		}
		return def
	}
	return val
}

// handshake 和server握手
func (s *tunnel) handshake(dstName, dstIP string, dstPort uint16) (err error) {
	var state cache.DialState
	if dstName != "" {
		// http请求,dns解析
		dstIP, state = s.lookup(dstName, dstIP)
	}
	host := s.findHost(dstName, dstIP)
	confTarget := getString(host.Target, conf.RouterConfig.Target, "auto")
	confDNS := getString(host.DNS, conf.RouterConfig.DNS, "local")

	// tcp 请求，如果是解析的IP被禁（代理端也无法telnet），不知道域名又无法使用远程dns解析，只能手动换ip
	// 如golang.org 解析为180.97.235.30 不通，配置改为 216.239.37.1就行
	if host.IP != "" {
		dstIP = host.IP
	}

	if confTarget == "deny" {
		err = fmt.Errorf("deny visit %s (%s)", dstName, dstIP)
		return
	}

	if config.ProxyServer != "" && config.ProxyPort > 0 && confTarget != "local" {
		if confTarget == "auto" && state != cache.StateFail {
			//local dial成功则返回
			err = s.dail(dstIP, dstPort)
			if err == nil {
				s.curState = stateNew
				return
			}
			cache.ResolveLookup.Store(dstName, dstIP, cache.StateFail, time.Duration(1)*time.Hour)
		}
		// remote 请求
		var target string
		if confDNS == "remote" {
			if dstName == "" {
				dstName = dstIP
			}
			target = fmt.Sprintf("%s:%d", dstName, dstPort)
		} else {
			target = fmt.Sprintf("%s:%d", dstIP, dstPort)
		}
		if target[0] == ':' {
			err = errors.New("target host is empty")
			return
		}
		log.Println(trace.ID(s.req.ID), fmt.Sprintf("PROXY %s:%d for %s", config.ProxyServer, config.ProxyPort, target))

		switch config.ProxyScheme {
		case "socks5":
			err = s.socks5(target)
		case "http":
			err = s.httpConnect(target)
		default:
			log.Println(trace.ID(s.req.ID), "proxy scheme", config.ProxyScheme, "is error")
			err = fmt.Errorf("%s is error", config.ProxyScheme)
			return
		}
	} else {
		if dstIP == "" {
			err = errors.New("dstIP is empty")
		} else {
			err = s.dail(dstIP, dstPort)
		}
	}
	if err != nil {
		return
	}
	s.curState = stateNew
	return
}

// socket5代理
func (s *tunnel) socks5(target string) (err error) {
	address := fmt.Sprintf("%s:%d", config.ProxyServer, config.ProxyPort)
	var dialProxy proxy.Dialer
	dialProxy, err = proxy.SOCKS5("tcp", address, nil, proxy.Direct)
	if err != nil {
		log.Println(trace.ID(s.req.ID), "socket5 err", err.Error())
		return
	}

	var conn net.Conn
	conn, err = dialProxy.Dial("tcp", target)
	if err != nil {
		log.Println(trace.ID(s.req.ID), "dail err", err.Error())
		return
	}
	s.conn = conn.(*net.TCPConn)
	return
}

// http代理
func (s *tunnel) httpConnect(target string) (err error) {
	err = s.dail(config.ProxyServer, config.ProxyPort)
	if err != nil {
		log.Println(trace.ID(s.req.ID), "dail err", err.Error())
		return
	}
	key := []byte(getToken())
	var x1 []byte
	x1, err = crypto.EncryptAES([]byte(target), key)
	if err != nil {
		log.Println(trace.ID(s.req.ID), "encrypt err", err.Error())
		return
	}

	// CONNECT实现的加密
	connectString := fmt.Sprintf("CONNECT %s HTTP/1.1\r\n\r\n", base64.StdEncoding.EncodeToString(x1))
	fmt.Fprintf(s.conn, connectString)
	var status string
	status, err = bufio.NewReader(s.conn).ReadString('\n')
	if err != nil {
		log.Printf("%s PROXY ERR: Could not find response to CONNECT: err=%v", trace.ID(s.req.ID), err)
		return
	}
	// 检查是不是200返回
	if strings.Contains(status, "200") == false {
		log.Printf("%s PROXY ERR: Proxy response to CONNECT was: %s.\n", trace.ID(s.req.ID), strconv.Quote(status))
		err = fmt.Errorf("Proxy response was: %s", strconv.Quote(status))
	}
	return
}

// IP限制
func (s *tunnel) isAllowed() (string, bool) {
	if len(conf.RouterConfig.AllowIP) == 0 {
		return "", true
	}
	ip := s.req.conn.RemoteAddr().String()
	ipSplit := strings.Split(ip, ":")
	for _, p := range conf.RouterConfig.AllowIP {
		if ipSplit[0] == p {
			return "", true
		}
	}
	return ipSplit[0], false
}
