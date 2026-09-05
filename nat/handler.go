package nat

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strings"
	"time"

	"github.com/keminar/anyproxy/utils/conf"
	"github.com/keminar/anyproxy/utils/tools"

	"github.com/gorilla/websocket"
	"github.com/keminar/anyproxy/config"
)

// wsClientConn 订阅方单条 server 连接的私有状态。一个进程可同时订阅多台 server,
// 每台各自一份, 替代原来假设"只连一台"的包级全局单例(ClientHub/LocalBridge/tempDelay)。
type wsClientConn struct {
	cfg       conf.WsClient
	liveIndex int // 在 conf.RouterConfig.Websocket.ClientList() 里的下标, 用于热加载重新取值, 见 liveAuthCfg
	hub       *Hub
	bridge    *BridgeHub
	forward   map[uint16]string
	tempDelay time.Duration
	tag       string      // 日志前缀, 用 cfg.Connect 区分是哪条连接
	direct    *directPeer // IPv6 QUIC 直连运行时, 未启用时为 nil
}

// liveAuthCfg 每次重连前重新取一遍 user/pass/host/email/subscribe, 保留热加载语义
// (这几项在 docs/hot-reload.md 里承诺"下次重连时生效"); connect/forward 是启动时定的,
// 不随热加载变, 取自 w.cfg。用 liveIndex 定位到配置热加载后的同一条目, 而不是重新用地址
// 字符串匹配(地址会被 FillPort/去掉 ws:// 前缀改写, 直接比较不可靠)。
func (w *wsClientConn) liveAuthCfg() conf.WsClient {
	cfg := w.cfg
	list := conf.RouterConfig.Websocket.ClientList()
	if w.liveIndex < 0 || w.liveIndex >= len(list) {
		return cfg // 条目在热加载后消失(如数组变短), 用启动时的快照兜底
	}
	live := list[w.liveIndex]
	cfg.User, cfg.Pass, cfg.Host, cfg.Email, cfg.Subscribe = live.User, live.Pass, live.Host, live.Email, live.Subscribe
	return cfg
}

// logf 带 [tag] 前缀打日志, 多条 server 连接并发时便于按前缀区分。
func (w *wsClientConn) logf(format string, args ...interface{}) {
	log.Printf("[%s] %s", w.tag, fmt.Sprintf(format, args...))
}

// ConnectServer 连接到websocket服务。cfg 为这一台 server 的独立配置(见
// conf.Websocket.ClientList), 可对多台 server 并发调用本函数。liveIndex 是 cfg 在
// ClientList() 里的下标, 热加载时用于重新取 user/pass/host/email/subscribe(见 liveAuthCfg)。
func ConnectServer(cfg conf.WsClient, liveIndex int) {
	if cfg.User == "" || cfg.Email == "" {
		log.Println("ws user or email empty, donot connect", cfg.Connect)
		return
	}
	addrs := strings.Split(cfg.Connect, "://")
	if addrs[0] == "ws" && len(addrs) == 2 {
		cfg.Connect = addrs[1]
	}

	w := &wsClientConn{
		cfg:       cfg,
		liveIndex: liveIndex,
		hub:       newHub(),
		bridge:    newBridgeHub(),
		forward:   buildForward(cfg.Forward),
		tag:       cfg.Connect,
	}
	go w.hub.run()
	go w.bridge.run()

	// IPv6 QUIC 直连。
	//
	// 入口 TCP/UDP 监听在这里起一次: 下面的 for 循环每次重连都会新建 Client, 放进
	// connect() 里会重复绑定同一端口。
	//
	// 但 C 侧的 QUIC 监听**不在这里起** —— 它是请求驱动的: 收到服务端转来的 punch 才
	// 起监听并当场探测端点, 没有活跃连接且空闲一段后自动释放。这样 C 平时不占端口、
	// 空闲时零后台流量, 也不存在"开机时 IPv6 还没就绪导致永久禁用"的问题。
	if cfg.DirectAccept || len(cfg.Direct) > 0 {
		w.direct = newDirectPeer(w.tag, cfg, w.forward)
		w.direct.startEntries(cfg.Direct)
		go w.direct.reapSessions()
		if cfg.DirectAccept {
			go w.direct.reapAccept()
		}
	}

	interruptClose = false
	interrupt := make(chan os.Signal, 1)
	signal.Notify(interrupt, os.Interrupt)

	for {
		w.connect(interrupt)
		if interruptClose {
			break
		}
	}
}

// 连接本地Proxy服务
func dialProxy() net.Conn {
	connTimeout := time.Duration(5) * time.Second
	var err error
	localProxy := fmt.Sprintf("%s:%d", "127.0.0.1", config.ListenPort)
	proxyConn, err := bypassDial("tcp", localProxy, connTimeout)
	if err != nil {
		log.Println("dial local proxy", err)
	}
	log.Printf("local websocket connecting to %s", localProxy)
	return proxyConn
}

// connect 认证连接并交换数据。方法接收者 w 持有这条 server 连接的私有状态
// (hub/bridge/forward/tempDelay), 与其它并发的 wsClientConn 互不干扰。
func (w *wsClientConn) connect(interrupt chan os.Signal) {
	live := w.liveAuthCfg()

	u := url.URL{Scheme: "ws", Host: w.cfg.Connect, Path: "/ws"}
	w.logf("connecting to %s", u.String())

	h := http.Header{}
	if live.Host != "" {
		h.Add("Host", live.Host)
	}
	wsDialer := &websocket.Dialer{
		NetDial:          func(network, addr string) (net.Conn, error) { return bypassDial(network, addr, 30*time.Second) },
		HandshakeTimeout: 45 * time.Second,
	}
	c, resp, err := wsDialer.Dial(u.String(), h)
	if err != nil {
		// 必须把 HTTP 响应也读出来: 服务端在 upgrade 之前拒绝时(如 allowIP 命中回
		// 403)只会返回普通 HTTP 响应, 而 gorilla 一律报 "websocket: bad handshake",
		// 把状态码和原因全丢掉 —— 现象是本端只看到"连不上"并无限重连, 完全不知道是
		// 被白名单挡了。
		w.logf("ws connect err: %v%s", err, httpRejectReason(resp))
		time.Sleep(time.Duration(3) * time.Second)
		return
	}
	defer c.Close()

	ch := newClientHandler(c)
	err = ch.auth(live.User, live.Pass, live.Key, live.Email, w.direct != nil)
	if err != nil {
		w.logf("auth: %v", err)

		if w.tempDelay == 0 {
			w.tempDelay = 3 * time.Second
		} else {
			w.tempDelay *= 2
		}
		if max := 1 * time.Minute; w.tempDelay > max {
			w.tempDelay = max
		}
		time.Sleep(w.tempDelay)
		return
	}
	w.tempDelay = 0
	err = ch.subscribe(live.Subscribe)
	if err != nil {
		w.logf("subscribe: %v", err)
		time.Sleep(time.Duration(3) * time.Second)
		return
	}
	w.logf("websocket auth and subscribe ok")

	client := &Client{hub: w.hub, conn: c, send: make(chan *Message, SEND_CHAN_LEN), bridge: w.bridge, forward: w.forward, tag: w.tag}
	if w.direct != nil {
		// 直连信令要经这条新连接收发, 每次重连都要重新挂上。
		// 不需要在这里通告端点: 端点是收到请求时当场探测的, 不预先上报。
		client.setDirectPeer(w.direct)
		w.direct.setClient(client)
	}
	client.hub.register <- client
	defer func() {
		client.hub.unregister <- client
	}()

	go client.writePump()
	done := make(chan struct{})
	go func() { //客户端的client.readRump
		defer close(done)
		client.localReadPump()
	}()
	for {
		select {
		case <-done:
			return
		case <-interrupt:
			w.logf("interrupt")
			interruptClose = true

			// Cleanly close the connection by sending a close message and then
			// waiting (with timeout) for the server to close the connection.
			err := c.WriteMessage(websocket.CloseMessage, websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""))
			if err != nil {
				w.logf("write close: %v", err)
				return
			}
			select {
			case <-done:
			case <-time.After(time.Second):
			}
			return
		}
	}
}

// httpRejectReason 从被拒的 HTTP 响应里提取状态码与响应体, 拼成可读的原因。
// 无响应(纯网络错误)时返回空串。
func httpRejectReason(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	reason := strings.TrimSpace(string(body))
	if reason == "" {
		return fmt.Sprintf(" (server replied %s)", resp.Status)
	}
	hint := ""
	if resp.StatusCode == http.StatusForbidden {
		hint = "; 本端地址不在服务端 websocket.server.allowIP 里(注意 IPv6 地址会轮换, 建议白名单写前缀网段)"
	}
	return fmt.Sprintf(" (server replied %s: %s%s)", resp.Status, reason, hint)
}

// ClientHandler 认证助手
type ClientHandler struct {
	c *websocket.Conn
}

func newClientHandler(c *websocket.Conn) *ClientHandler {
	return &ClientHandler{c: c}
}

// auth 认证。密码与密钥二选一: 配了 key 走挑战-应答(不依赖两端时钟), 否则走原来的
// md5(user|pass|xtime)。direct 表示本端参与 IPv6 QUIC 直连, 供服务端放行空订阅
// (见 AuthMessage.Direct)。
func (h *ClientHandler) auth(user, pass, key, email string, direct bool) error {
	if key != "" {
		return h.authKey(user, key, email, direct)
	}
	xtime := time.Now().Unix()
	token, err := tools.Md5Str(fmt.Sprintf("%s|%s|%d", user, pass, xtime))
	if err != nil {
		return err
	}
	msg := AuthMessage{User: user, Token: token, Xtime: xtime, Email: email, Direct: direct}
	return h.ask(&msg)
}

// authKey 密钥鉴权: 先声明要走密钥, 服务端回一个一次性随机数, 本端用私钥签名再发回去。
// 服务端那边回的可能是挑战, 也可能是一句拒绝的说明(比如该账号其实配的是密码), 两者
// 都得能识别, 否则本端只会看到"连不上"。
func (h *ClientHandler) authKey(user, key, email string, direct bool) error {
	// 先自检私钥: 配错了要在本端就说清楚, 不然错误要等服务端验签失败才回来, 看着像
	// 是对端的问题。
	if _, err := signChallenge(key, base64.StdEncoding.EncodeToString(make([]byte, authChallengeSize))); err != nil {
		return fmt.Errorf("websocket.client.key is invalid: %w", err)
	}
	if err := h.c.WriteJSON(&AuthMessage{User: user, Email: email, KeyAuth: true, Direct: direct}); err != nil {
		return err
	}
	message, err := h.readReply()
	if err != nil {
		return err
	}
	var ch AuthChallenge
	if json.Unmarshal(message, &ch) != nil || ch.Challenge == "" {
		return errors.New("fail, " + string(message))
	}
	sig, err := signChallenge(key, ch.Challenge)
	if err != nil {
		return err
	}
	return h.ask(&AuthSignature{Signature: sig})
}

// subscribe 订阅
func (h *ClientHandler) subscribe(sub []conf.Subscribe) error {
	msg := []SubscribeMessage{}
	for _, s := range sub {
		msg = append(msg, SubscribeMessage{Key: s.Key, Val: s.Val})
	}
	return h.ask(&msg)
}

func (h *ClientHandler) ask(v interface{}) error {
	err := h.c.WriteJSON(v)
	if err != nil {
		return err
	}
	message, err := h.readReply()
	if err != nil {
		return err
	}
	if string(message) != "ok" {
		return errors.New("fail, " + string(message))
	}
	return nil
}

// readReply 读服务端的一条回包, 超时返回 error。
func (h *ClientHandler) readReply() ([]byte, error) {
	ticker := time.NewTicker(3 * time.Second)
	defer func() {
		ticker.Stop()
	}()

	// 带缓冲: 超时走掉后读到的包没人接, 无缓冲的话这个 goroutine 会永远卡在发送上。
	send := make(chan []byte, 1)
	go func() {
		defer close(send)
		_, message, _ := h.c.ReadMessage()
		send <- message
	}()
	select {
	case message, ok := <-send: //ok为判断channel是否关闭
		if !ok {
			return nil, errors.New("fail")
		}
		return message, nil
	case <-ticker.C:
		return nil, errors.New("timeout")
	}
}

// md5
func md5Byte(data []byte) (string, error) {
	h := md5.New()
	h.Write(data)
	cipherStr := h.Sum(nil)
	return hex.EncodeToString(cipherStr), nil
}
