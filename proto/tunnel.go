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
	"github.com/keminar/anyproxy/proto/tcp"
	"github.com/keminar/anyproxy/utils/cache"
	"github.com/keminar/anyproxy/utils/conf"
	"github.com/keminar/anyproxy/utils/trace"
	"golang.org/x/net/proxy"
)

const (
	stateNew int = iota
	stateActive
	stateClosed
	stateIdle
)

const protoTCP = "tcp"
const protoHTTP = "http"
const protoHTTPS = "https"

// 转发实体
type tunnel struct {
	req      *Request
	conn     *net.TCPConn //后端服务
	curState int

	readSize  int64
	writeSize int64

	clientUnRead int

	buf []byte
}

// newTunnel 实例
func newTunnel(req *Request) *tunnel {
	s := &tunnel{
		req: req,
	}
	return s
}

// copyBuffer 传输数据
func (s *tunnel) copyBuffer(dst io.Writer, src *tcp.Reader, srcname string) (written int64, err error) {
	//如果设置过大会耗内存高，4k比较合理
	size := 4 * 1024
	buf := make([]byte, size)
	i := 0
	for {
		i++
		if config.DebugLevel >= config.LevelDebug {
			log.Printf("%s receive from %s, n=%d\n", trace.ID(s.req.ID), srcname, i)
		}
		nr, er := src.Read(buf)
		if nr > 0 {
			// 如果为HTTP/1.1的Keep-alive情况下
			if srcname == "request" && s.clientUnRead >= 0 {
				// 之前已读完，说明要建新链接
				if s.clientUnRead == 0 {
					// 关闭与旧的服务器的连接的写
					s.conn.CloseWrite()
					// 状态变成已空闲，不能为关闭，会导致下面逻辑的Client也被关闭
					s.curState = stateIdle

					//todo 如果域名不同跳出交换数据, 因为这个逻辑会出现N次，应该在http.go实现
					//fmt.Println(string(buf[0:nr]))
					s.buf = make([]byte, nr)
					copy(s.buf, buf[0:nr])
					break
				}
				// 未读完
				s.clientUnRead -= nr
			}
			if config.DebugLevel >= config.LevelDebugBody {
				log.Printf("%s receive from %s, n=%d, data len: %d\n", trace.ID(s.req.ID), srcname, i, nr)
				fmt.Println(trace.ID(s.req.ID), string(buf[0:nr]))
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
				s.logCopyErr(srcname+" read", er)
				if srcname == "server" {
					// 技巧：keep-alive 复用连接时写，后端收到CloseWrite后响应EOF，当收到EOF时说明body都收完了。
					if s.curState == stateIdle {
						//可以开始复用了, 带上之前读过的缓存
						KeepHandler(s.req.ctx, s.req.conn, s.buf)
						break
					} else if s.curState != stateClosed {
						// 如果非客户端导致的服务端关闭，则关闭客户端读
						// Notice: 如果只是CloseRead(),当在windows上执行时，且是做为订阅端从服务器收到请求再转到charles
						//         等服务时,当请求的地址返回足够长的内容时会触发卡住问题。
						//         流程如 curl -> anyproxy(server) -> ws -> anyproxy(windows) -> charles
						//         用Close()可以解决卡住，不过客户端会收到use of closed network connection的错误提醒
						dst.(*net.TCPConn).Close()
					}
				}
			}

			if srcname == "request" {
				// 当客户端断开或出错了，服务端也不用再读了，可以关闭，解决读Server卡住不能到EOF的问题
				s.conn.CloseWrite()
				s.curState = stateClosed
			}
			break
		}
	}
	return written, err
}

// transfer 交换数据
func (s *tunnel) transfer(clientUnRead int) {
	if config.DebugLevel >= config.LevelLong {
		log.Println(trace.ID(s.req.ID), "transfer start")
	}
	s.curState = stateActive
	s.clientUnRead = clientUnRead
	done := make(chan struct{})

	//发送请求
	go func() {
		defer func() {
			close(done)
		}()
		//不能和外层共用err
		var err error
		s.readSize, err = s.copyBuffer(s.conn, s.req.reader, "request")
		s.logCopyErr("request->server", err)
		if config.DebugLevel >= config.LevelLong {
			log.Println(trace.ID(s.req.ID), "request body size", s.readSize)
		}
	}()

	var err error
	//取返回结果
	s.writeSize, err = s.copyBuffer(s.req.conn, tcp.NewReader(s.conn), "server")
	s.logCopyErr("server->request", err)

	<-done
	// 不管是不是正常结束，只要server结束了，函数就会返回，然后底层会自动断开与client的连接
	if config.DebugLevel >= config.LevelLong {
		log.Println(trace.ID(s.req.ID), "transfer finished, response size", s.writeSize)
	}
}

func (s *tunnel) logCopyErr(name string, err error) {
	if err == nil {
		return
	}
	if config.DebugLevel >= config.LevelLong {
		log.Println(trace.ID(s.req.ID), name, err.Error())
	} else if err != io.EOF {
		log.Println(trace.ID(s.req.ID), name, err.Error())
	}
}

// dail tcp连接
func (s *tunnel) dail(dstIP string, dstPort uint16) (err error) {
	if config.DebugLevel >= config.LevelLong {
		log.Printf("%s create a new connection to server %s:%d\n", trace.ID(s.req.ID), dstIP, dstPort)
	}
	connTimeout := time.Duration(5) * time.Second
	var conn net.Conn
	if strings.Contains(dstIP, ":") {
		// tcp6 支持
		conn, err = net.DialTimeout("tcp6", fmt.Sprintf("[%s]:%d", dstIP, dstPort), connTimeout)
	} else {
		conn, err = net.DialTimeout("tcp", fmt.Sprintf("%s:%d", dstIP, dstPort), connTimeout)
	}
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
			s1 := time.Now()
			upIPs, _ := net.LookupIP(dstName)
			if time.Since(s1).Seconds() > 1 && config.DebugLevel >= config.LevelLong {
				log.Println(trace.ID(s.req.ID), "dns look up costtime", time.Since(s1).Seconds())
			}
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
func findHost(dstName, dstIP string) conf.Host {
	for _, h := range conf.RouterConfig.Hosts {
		confMatch := getString(h.Match, conf.RouterConfig.Default.Match, "equal")
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
func (s *tunnel) handshake(proto string, dstName, dstIP string, dstPort uint16) (err error) {
	var state cache.DialState
	// 先取下配置，再决定要不要走本地dns解析，否则未解析域名DNS解析再超时卡半天，又不会被缓存
	host := findHost(dstName, dstIP)

	var confTarget string
	if proto == protoTCP {
		confTarget = getString(host.Target, conf.RouterConfig.Default.TCPTarget, "auto")
	} else {
		confTarget = getString(host.Target, conf.RouterConfig.Default.Target, "auto")
	}
	confDNS := getString(host.DNS, conf.RouterConfig.Default.DNS, "local")

	// tcp 请求，如果是解析的IP被禁（代理端也无法telnet），不知道域名又无法使用远程dns解析，只能手动换ip
	// 如golang.org 解析为180.97.235.30 不通，配置改为 216.239.37.1就行
	if host.IP != "" {
		dstIP = host.IP
	} else if dstName != "" && confDNS != "remote" {
		// http请求的dns解析
		dstIP, state = s.lookup(dstName, dstIP)
	}

	// 检查是否要换端口
	for _, p := range host.Port {
		if p.From == dstPort {
			dstPort = p.To
			break
		}
	}

	if confTarget == "deny" {
		err = fmt.Errorf("deny visit %s (%s)", dstName, dstIP)
		return
	}
	proxyScheme := config.ProxyScheme
	proxyServer := config.ProxyServer
	proxyPort := config.ProxyPort
	if host.Proxy != "" { //如果有自定义代理，则走自定义
		proxyScheme2, proxyServer2, proxyPort2, err := getProxyServer(host.Proxy)
		if err != nil {
			// 如果自定义代理不可用，confTarget走原来逻辑
			log.Println(trace.ID(s.req.ID), "host.proxy err", err)
		} else {
			proxyScheme = proxyScheme2
			proxyServer = proxyServer2
			proxyPort = proxyPort2
			if confTarget != "remote" { //如果有定制代理，就不能用local 和 auto
				confTarget = "remote"
			}
		}
	}
	if proxyServer != "" && proxyPort > 0 && confTarget != "local" {
		if confTarget == "auto" {
			if state != cache.StateFail {
				//local dial成功则返回，走本地网络
				//auto 只能优化ip ping 不通的情况，能dail通访问不了的需要手动remote
				if dstIP != "" {
					err = s.dail(dstIP, dstPort)
				} else if dstName != "" {
					err = s.dail(dstName, dstPort)
				}
				if err == nil {
					s.curState = stateNew
					return
				}
				if dstName != "" && dstIP != "" {
					cache.ResolveLookup.Store(dstName, dstIP, cache.StateFail, time.Duration(1)*time.Hour)
				}
			}
			//fail的auto 等于用remote访问，但ip在remote访问可能也是不通的，强制用远程dns
			//如果又想远程，又想用本地dns请配置中单独指定
			//有一种情况是ip能dail通，auto模式就是会用local，但是transfer时接不到数据包，这种也要配置中单独指定remote
			confDNS = "remote"
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

		switch proxyScheme {
		case "socks5":
			log.Println(trace.ID(s.req.ID), fmt.Sprintf("PROXY %s:%d for %s", proxyServer, proxyPort, target))
			err = s.socks5(target, proxyServer, proxyPort)
		case "tunnel":
			log.Println(trace.ID(s.req.ID), fmt.Sprintf("PROXY %s:%d for %s", proxyServer, proxyPort, target))
			err = s.httpConnect(target, proxyServer, proxyPort, true)
		case "http":
			if proto == protoHTTP { //可避免转发到charles显示2次域名，且部分电脑请求出错
				log.Println(trace.ID(s.req.ID), fmt.Sprintf("PROXY %s:%d", proxyServer, proxyPort))
				err = s.dail(proxyServer, proxyPort)
			} else {
				log.Println(trace.ID(s.req.ID), fmt.Sprintf("PROXY %s:%d for %s", proxyServer, proxyPort, target))
				err = s.httpConnect(target, proxyServer, proxyPort, false)
			}
		default:
			log.Println(trace.ID(s.req.ID), "proxy scheme", proxyScheme, "is error")
			err = fmt.Errorf("%s is error", proxyScheme)
			return
		}
	} else {
		if dstIP != "" {
			log.Println(trace.ID(s.req.ID), fmt.Sprintf("direct to %s:%d for %s", dstIP, dstPort, dstName))
			err = s.dail(dstIP, dstPort)
		} else if dstName != "" {
			log.Println(trace.ID(s.req.ID), fmt.Sprintf("direct to %s:%d", dstName, dstPort))
			err = s.dail(dstName, dstPort)
		} else {
			err = errors.New("dstName && dstIP is empty")
		}
	}
	if err != nil {
		return
	}
	s.curState = stateNew
	return
}

//  getProxyServer 解析代理服务器
func getProxyServer(proxySpec string) (string, string, uint16, error) {
	if proxySpec == "" {
		return "", "", 0, errors.New("proxy 长度为空")
	}
	proxyScheme := "tunnel"
	var proxyServer string
	var proxyPort uint16
	// 先检查协议
	tmp := strings.Split(proxySpec, "://")
	if len(tmp) == 2 {
		proxyScheme = tmp[0]
		proxySpec = tmp[1]
	}
	// 检查端口，和上面的顺序不能反
	tmp = strings.Split(proxySpec, ":")
	if len(tmp) == 2 {
		portInt, err := strconv.Atoi(tmp[1])
		if err == nil {
			proxyServer = tmp[0]
			proxyPort = uint16(portInt)
			// 检查是否可连通
			connTimeout := time.Duration(100) * time.Millisecond
			conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", proxyServer, proxyPort), connTimeout)
			if err != nil {
				return "", "", 0, err
			}
			conn.Close()
			return proxyScheme, proxyServer, proxyPort, nil
		}
		return "", "", 0, err
	}
	return "", "", 0, errors.New("proxy 格式不对")
}

// socket5代理
func (s *tunnel) socks5(target string, proxyServer string, proxyPort uint16) (err error) {
	address := fmt.Sprintf("%s:%d", proxyServer, proxyPort)
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
func (s *tunnel) httpConnect(target string, proxyServer string, proxyPort uint16, encrypt bool) (err error) {
	err = s.dail(proxyServer, proxyPort)
	if err != nil {
		log.Println(trace.ID(s.req.ID), "dail err", err.Error())
		return
	}
	var connectString string
	if encrypt {
		key := []byte(getToken())
		var x1 []byte
		x1, err = crypto.EncryptAES([]byte(target), key)
		if err != nil {
			log.Println(trace.ID(s.req.ID), "encrypt err", err.Error())
			return
		}
		// CONNECT实现的加密
		connectString = fmt.Sprintf("CONNECT %s HTTP/1.1\r\n\r\n", base64.StdEncoding.EncodeToString(x1))
	} else {
		connectString = fmt.Sprintf("CONNECT %s HTTP/1.1\r\n\r\n", target)
	}
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
