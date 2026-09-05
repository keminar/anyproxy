package nat

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/keminar/anyproxy/utils/conf"
)

// A 侧的一次性发送: 建 websocket -> 鉴权 -> 打洞直连 -> 传文件 -> 退出。
//
// 为什么是独立进程而不是让常驻的 anyproxy 去传: 传文件是个有明确开始和结束的动作,
// 独立进程的退出码就能直接表达成败(脚本里 `anyproxy -send ... && echo ok` 就能用),
// 而且不要求本机已经跑着 anyproxy —— 想传一次文件不必先把守护进程配起来。
//
// 与服务端多一条 websocket 连接不冲突: 直连信令是按"发起请求的那条连接"回的
// (见 directBroker.track), 不是按 email 查的, 所以同一个 email 上多一条连接不会
// 把常驻那条的 offer 认错人。

// sendDialTimeout 建 websocket 的超时。
const sendDialTimeout = 30 * time.Second

// SendFiles 把 paths 指定的文件/目录发给 toEmail 对应的订阅方。
//
// 打洞失败就直接返回错误、一个字节都不传 —— 这条路径没有经服务端中继的回落, 与
// 直连入口的约定一致(见 directPeer.handleEntry)。
func SendFiles(cfg conf.WsClient, toEmail string, paths []string) error {
	if cfg.Connect == "" {
		return fmt.Errorf("websocket.client.connect is empty, cannot reach the server")
	}
	if toEmail == "" {
		return fmt.Errorf("-to is required: which subscriber should receive the files")
	}
	if toEmail == cfg.Email {
		return fmt.Errorf("-to %s is this machine's own email", toEmail)
	}
	items, err := collectFiles(paths)
	if err != nil {
		return err
	}
	var total int64
	for _, it := range items {
		total += it.size
	}
	fmt.Fprintf(os.Stderr, "sending %d file(s), %s to %s via %s\n",
		len(items), humanBytes(total), toEmail, cfg.Connect)

	sender, err := dialSender(cfg)
	if err != nil {
		return err
	}
	defer sender.close()

	// 一次直连, 所有文件共用 —— 每个文件占一条 stream, 不必反复打洞。
	rule := conf.ClientDirect{Email: toEmail, Port: directFilePort}
	sess, err := sender.peer.ensureSession(rule)
	if err != nil {
		return fmt.Errorf("direct connect to %s failed, nothing was sent: %w", toEmail, err)
	}

	var sentBytes int64
	for i, it := range items {
		start := time.Now()
		prefix := fmt.Sprintf("[%d/%d] %s", i+1, len(items), it.name)
		p := newProgress(prefix, it.size)
		saved, err := sender.peer.sendFile(sess, it, p.update)
		p.done()
		if err != nil {
			return fmt.Errorf("%s: %w", it.name, err)
		}
		sentBytes += it.size
		fmt.Fprintf(os.Stderr, "%s -> %s  (%s in %s, %s)\n", prefix, saved,
			humanBytes(it.size), time.Since(start).Round(time.Millisecond), rate(it.size, time.Since(start)))
	}
	fmt.Fprintf(os.Stderr, "done: %d file(s), %s\n", len(items), humanBytes(sentBytes))
	return nil
}

// oneShotSender 一次发送用到的连接与运行时。
type oneShotSender struct {
	peer   *directPeer
	ws     *websocket.Conn
	client *Client
}

func (s *oneShotSender) close() {
	if s.client != nil {
		s.client.hub.unregister <- s.client
	}
	if s.ws != nil {
		s.ws.Close()
	}
	if s.peer != nil {
		s.peer.closeTransport()
	}
}

// dialSender 建 websocket、完成鉴权与(空)订阅, 并挂好直连运行时。
//
// 这段是 wsClientConn.connect 的精简版: 不要重连循环(一次性动作, 失败就该报错退出,
// 悄悄重试只会让人以为在传), 也不要入口监听和转发表(这个进程不接受任何入站)。
func dialSender(cfg conf.WsClient) (*oneShotSender, error) {
	connect := cfg.Connect
	if parts := strings.Split(connect, "://"); len(parts) == 2 && parts[0] == "ws" {
		connect = parts[1]
	}

	hub := newHub()
	go hub.run()
	bridge := newBridgeHub()
	go bridge.run()

	s := &oneShotSender{}
	u := url.URL{Scheme: "ws", Host: connect, Path: "/ws"}
	h := map[string][]string{}
	if cfg.Host != "" {
		h["Host"] = []string{cfg.Host}
	}
	dialer := &websocket.Dialer{
		NetDial:          func(network, addr string) (net.Conn, error) { return bypassDial(network, addr, sendDialTimeout) },
		HandshakeTimeout: sendDialTimeout,
	}
	ws, resp, err := dialer.Dial(u.String(), h)
	if err != nil {
		return nil, fmt.Errorf("connect %s: %w%s", connect, err, httpRejectReason(resp))
	}
	s.ws = ws

	ch := newClientHandler(ws)
	// direct=true: 这个进程没有头部订阅规则, 服务端要靠这个标志放行空订阅。
	if err := ch.auth(cfg.User, cfg.Pass, cfg.Key, cfg.Email, true); err != nil {
		ws.Close()
		return nil, fmt.Errorf("auth: %w", err)
	}
	if err := ch.subscribe(nil); err != nil {
		ws.Close()
		return nil, fmt.Errorf("subscribe: %w", err)
	}

	cfg.Connect = connect
	s.peer = newDirectPeer("send", cfg, nil)
	s.client = &Client{hub: hub, conn: ws, send: make(chan *Message, SEND_CHAN_LEN), bridge: bridge, tag: "send"}
	s.client.setDirectPeer(s.peer)
	s.peer.setClient(s.client)
	hub.register <- s.client
	go s.client.writePump()
	go s.client.localReadPump()
	return s, nil
}

// ---------- 进度输出 ----------

// progress 单个文件的进度条, 输出到 stderr。
//
// 限流刷新: 千兆下一次 io.Copy 循环就是 256KB, 不限流的话每秒要打几千行, 光是写
// 终端就能拖慢传输本身。
type progress struct {
	prefix   string
	total    int64
	start    time.Time
	last     time.Time
	lastSent int64
	shown    bool
}

func newProgress(prefix string, total int64) *progress {
	now := time.Now()
	return &progress{prefix: prefix, total: total, start: now, last: now}
}

func (p *progress) update(sent int64) {
	now := time.Now()
	if now.Sub(p.last) < 200*time.Millisecond {
		return
	}
	// 显示的是**这一小段区间**的速率, 不是从头到现在的累计平均: 排查限速/拥塞退避
	// 时要看的是"现在多快、有没有往下掉", 累计平均会把开头的高速和后面的骤降拉平抹
	// 掉, 看着一直是个温吞的数字, 分不清是从来没快过还是快过又掉了下去。
	instRate := rate(sent-p.lastSent, now.Sub(p.last))
	p.lastSent = sent
	p.last = now
	p.shown = true
	pct := 0.0
	if p.total > 0 {
		pct = float64(sent) * 100 / float64(p.total)
	}
	fmt.Fprintf(os.Stderr, "\r%s  %s/%s  %.1f%%  %s   ",
		p.prefix, humanBytes(sent), humanBytes(p.total), pct, instRate)
}

// done 收尾: 把进度那一行擦掉, 让后面的结果行从行首开始打。
func (p *progress) done() {
	if p.shown {
		fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", 100))
	}
}

func rate(n int64, d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	return humanBytes(int64(float64(n)/d.Seconds())) + "/s"
}
