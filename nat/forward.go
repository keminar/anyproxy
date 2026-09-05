package nat

import (
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/keminar/anyproxy/grace/autoinc"
	"github.com/keminar/anyproxy/utils/conf"
	"github.com/keminar/anyproxy/utils/trace"
)

// forwardInc 裸TCP路径的连接采番器。与 HTTP 路径(req.ID)各自从 1 起,
// 靠 Message.Type(ConnTCP/ConnHTTP) 区分, 复合键不会撞号。
var forwardInc = autoinc.New(1, 1)

// forwardAliveInterval 裸TCP转发长连接的存活心跳间隔: 未关闭的连接每隔该时长打一行
// 累计流量+时长, 便于发现长期挂着的会话(如RDP)。可按需调整。
const forwardAliveInterval = 60 * time.Second

// forwardIdleTimeout 裸TCP转发连接的空闲超时: 双向都超过该时长无真实收发数据(仅靠
// TCP不主动断开、也不发RST/FIN的僵尸连接, 常见于对端网络中断但连接未被系统层探测到),
// 判定为僵尸连接并主动关闭入口连接触发正常关闭流程。可按需调整。
const forwardIdleTimeout = 30 * time.Minute

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
			log.Println(trace.ID(msg.ID), c.tag, fmt.Sprintf("local tcp forward connecting to %s (entry port %d)", target, msg.Port))
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
		if !r.ValidProtocol() {
			log.Printf("nat forward %s has unknown protocol %q, skipped", r.Listen, r.Protocol)
			continue
		}
		if !r.WantTCP() {
			continue // protocol: udp, 只起 UDP 中继(见 nat/relay_udp_server.go)
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
	// server.allowIP 白名单同样约束裸TCP入口(:listen)的来源: 按真实TCP来源判定,
	// 为空不限制, loopback 始终放行(见 serverIPAllowed)。否则入口端口对公网全开,
	// 会被扫描器不断连入并触发到内网目标的无谓转发。
	peerIP, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
	if !serverIPAllowed(peerIP) {
		log.Printf("nat forward deny ip %s on %s, not in websocket.server.allowIP", peerIP, r.Listen)
		conn.Close()
		return
	}
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
	src := conn.RemoteAddr()
	start := time.Now()
	log.Println(trace.ID(id), fmt.Sprintf("nat forward accept %s -> email %s (entry port %d)", src, r.Email, port))

	b := ServerBridge.Register(c, id, ConnTCP, conn)
	defer b.Unregister()

	// 存活心跳: 未关闭的连接每隔 forwardAliveInterval 打一行累计流量+时长, 便于发现长期
	// 挂着的会话(如RDP), 也能和"秒级RST"的扫描噪声区分开。连接结束时 close(alive) 停掉。
	alive := make(chan struct{})
	defer close(alive)
	go func() {
		t := time.NewTicker(forwardAliveInterval)
		defer t.Stop()
		// prevUp/prevDown/prevAt 只在这个 goroutine 里用, 不需要放进 Bridge: 算的是
		// "这一轮心跳区间"的瞬时速率, 不是从连接建立到现在的累计平均——长连接(RDP
		// 一开就是几小时)的累计平均没法告诉你"现在是不是被限速了", 只有瞬时值能看
		// 出变化, 跟 -send 进度条改瞬时速率是同一个理由。
		prevUp, prevDown := int64(0), int64(0)
		prevAt := start
		for {
			select {
			case <-alive:
				return
			case <-t.C:
				up, down := b.Stats()
				idle := b.IdleFor()
				now := time.Now()
				upRate, downRate := rate(up-prevUp, now.Sub(prevAt)), rate(down-prevDown, now.Sub(prevAt))
				prevUp, prevDown, prevAt = up, down, now
				log.Println(trace.ID(id), fmt.Sprintf("nat forward alive %s up=%d(%s) down=%d(%s) dur=%s idle=%s",
					src, up, upRate, down, downRate, time.Since(start).Round(time.Second), idle.Round(time.Second)))
				if idle >= forwardIdleTimeout {
					log.Println(trace.ID(id), fmt.Sprintf("nat forward zombie %s up=%d down=%d dur=%s idle=%s, closing", src, up, down, time.Since(start).Round(time.Second), idle.Round(time.Second)))
					conn.Close()
					return
				}
			}
		}
	}()

	// 通知订阅方创建到内网目标的连接
	b.Open(port)

	done := make(chan struct{})
	var upErr error
	// 请求端 -> websocket
	go func() {
		defer close(done)
		_, upErr = b.CopyBuffer(b, conn, "forward")
		logCopyErr(trace.ID(id), "nat forward request->websocket", upErr)
		b.CloseWrite()
	}()
	// websocket -> 请求端
	_, downErr := b.WritePump()
	logCopyErr(trace.ID(id), "nat forward websocket->request", downErr)
	<-done

	// 关闭汇总: 无条件打一行, 含累计上/下行字节、连接时长、关闭原因, 用来判断这条连接
	// 到底传没传数据、活了多久、怎么断的(TCP连通≠真登录, 登录审计仍以内网机器为准)。
	//
	// 订阅方主动拒绝时带的原因优先: 那才是根因(比如查不到 forward 映射), 而 upErr/
	// downErr 只是它的下游症状 —— 订阅方一发 CLOSE、这边的 WritePump 就半关(FIN)
	// 给外部客户端, 客户端收到没数据的 FIN 常会自己 RST, 那个 RST 才是 upErr 里
	// 抓到的东西, 单看它只会让人怀疑网络, 找不到真正原因。
	up, down := b.Stats()
	reason := forwardCloseReason(upErr, downErr)
	if peer := b.CloseReason(); peer != "" {
		reason = "peer close: " + peer
	}
	dur := time.Since(start)
	// 这里的速率是整条连接从建到断的**平均值**, 跟存活心跳里的瞬时速率是两回事:
	// 一次性汇总只有这一个值可算, 想看变化过程要看上面那几行 alive 心跳。
	log.Println(trace.ID(id), fmt.Sprintf("nat forward closed %s up=%d(%s) down=%d(%s) dur=%s reason=%s",
		src, up, rate(up, dur), down, rate(down, dur), dur.Round(time.Second), reason))
}

// forwardCloseReason 归纳裸TCP转发连接的关闭原因: CopyBuffer/WritePump 正常结束(含对端EOF)
// 返回 nil, 此时记 normal; 任一方向有真错误则标出方向与错误。
func forwardCloseReason(up, down error) string {
	if up != nil {
		return "up:" + up.Error()
	}
	if down != nil {
		return "down:" + down.Error()
	}
	return "normal"
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
