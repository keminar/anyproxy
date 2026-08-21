package nat

import (
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/keminar/anyproxy/config"
	"github.com/keminar/anyproxy/grace/autoinc"
	"github.com/keminar/anyproxy/utils/conf"
	"github.com/keminar/anyproxy/utils/trace"
)

// forwardInc 裸TCP路径的连接采番器。与 HTTP 路径(req.ID)各自从 1 起,
// 靠 Message.Type(ConnTCP/ConnHTTP) 区分, 复合键不会撞号。
var forwardInc = autoinc.New(1, 1)

// buildForward 订阅方按自己这条连接的配置构建 端口->target 映射(见 conf.ClientForward)。
// 每条 server 连接各自持有一份(见 nat/handler.go 的 wsClientConn.forward), 互不干扰。
func buildForward(rules []conf.ClientForward) map[uint16]string {
	m := map[uint16]string{}
	for _, r := range rules {
		if r.Port != 0 && r.Target != "" {
			m[r.Port] = r.Target
		}
	}
	if len(m) > 0 {
		log.Printf("nat local forward map: %v", m)
	}
	return m
}

// isForwardEmail 该email是否为某条服务端forward规则的目标。命中则允许其空订阅
// 接入(仅用于裸TCP转发, 不参与http头订阅匹配)。
func isForwardEmail(email string) bool {
	if email == "" {
		return false
	}
	for _, r := range conf.RouterConfig.Websocket.Server.Forward {
		if r.Listen != "" && r.Email == email {
			return true
		}
	}
	return false
}

// dialForCreate 订阅方收到 CREATE 时按类型决定 dial 目标:
//
//	ConnHTTP: 本地代理端口(原逻辑)
//	ConnTCP : 按入口端口查写死的 target, 查不到即报错(由调用方回 CLOSE)
func dialForCreate(c *Client, msg *Message) (*net.TCPConn, error) {
	var conn net.Conn
	var err error
	if msg.Type == ConnTCP {
		target, ok := c.forward[msg.Port]
		if !ok {
			return nil, fmt.Errorf("no forward target for entry port %d", msg.Port)
		}
		conn, err = bypassDial("tcp", target, 5*time.Second)
		if err == nil {
			log.Println(c.tag, trace.ID(msg.ID), fmt.Sprintf("local tcp forward connecting to %s (entry port %d)", target, msg.Port))
		}
	} else {
		conn = dialProxy() //创建本地与本地代理端口之间的连接
		if conn == nil {
			err = errors.New("dial local proxy failed")
		}
	}
	if err != nil {
		return nil, err
	}
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		conn.Close()
		return nil, errors.New("dial result is not *net.TCPConn")
	}
	return tcpConn, nil
}

// StartForward 服务端(tunnel侧)启动裸TCP端口转发监听。每条 forward 规则一个
// 监听 goroutine; 只对配了 Listen 的规则生效。需在 NewServer 之后调用(依赖
// ServerHub/ServerBridge 已初始化)。
func StartForward(rules []conf.ServerForward) {
	for _, r := range rules {
		if r.Listen == "" {
			continue
		}
		go listenForward(r)
	}
}

func listenForward(r conf.ServerForward) {
	ln, err := net.Listen("tcp", r.Listen)
	if err != nil {
		log.Printf("nat forward listen %s err: %v", r.Listen, err)
		return
	}
	log.Printf("nat forward listening on %s -> email %s", r.Listen, r.Email)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("nat forward accept %s err: %v", r.Listen, err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go handleForward(conn.(*net.TCPConn), r)
	}
}

// handleForward 处理一条进来的裸TCP连接: 选订阅方 -> 建 bridge -> 双向转发。
func handleForward(conn *net.TCPConn, r conf.ServerForward) {
	if r.Email == "" {
		log.Printf("nat forward %s email empty, close", r.Listen)
		conn.Close()
		return
	}
	if !serverStart || ServerHub == nil {
		conn.Close()
		return
	}
	c := ServerHub.GetClientByEmail(r.Email)
	if c == nil {
		log.Printf("nat forward %s no subscriber for email %s, close", r.Listen, r.Email)
		conn.Close()
		return
	}

	id := forwardInc.ID()
	// 服务端入口端口: 从监听地址解析, 供订阅方查固定 target
	port := listenPort(r.Listen)
	log.Println(trace.ID(id), fmt.Sprintf("nat forward accept %s -> email %s (entry port %d)", conn.RemoteAddr(), r.Email, port))
	defer log.Println(trace.ID(id), "nat forward closed")

	b := ServerBridge.Register(c, id, ConnTCP, conn)
	defer b.Unregister()

	// 通知订阅方创建到内网目标的连接
	b.Open(port)

	done := make(chan struct{})
	// 请求端 -> websocket
	go func() {
		defer close(done)
		readSize, err := b.CopyBuffer(b, conn, "forward")
		logCopyErr(trace.ID(id), "nat forward request->websocket", err)
		if config.DebugLevel >= config.LevelDebug {
			log.Println(trace.ID(id), "nat forward request size", readSize)
		}
		b.CloseWrite()
	}()
	// websocket -> 请求端
	written, err := b.WritePump()
	logCopyErr(trace.ID(id), "nat forward websocket->request", err)
	if config.DebugLevel >= config.LevelDebug {
		log.Println(trace.ID(id), "nat forward response size", written)
	}
	<-done
}

// listenPort 从监听地址(如 ":2222" / "0.0.0.0:2222")解析端口号。
func listenPort(addr string) uint16 {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return 0
	}
	p, err := net.LookupPort("tcp", portStr)
	if err != nil {
		return 0
	}
	return uint16(p)
}
