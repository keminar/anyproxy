package nat

import (
	"fmt"
	"net"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
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

// ViaDirect/ViaRelay -send 的两种路径, 必须显式声明(见 SendFiles 的 via 参数)。
const (
	ViaDirect = "direct" // 打洞直连(A<->C, 不经服务端转发数据), 默认
	ViaRelay  = "relay"  // 经服务端 B 中继转发(不打洞, 不需要对端开 directAccept)
)

// splitSendTo 把 "-to" 参数拆成邮箱和目标子目录, 类似 scp 的 user@host:path ——
// user@a.com:/aaa/ 表示存到对端 receive.dir/aaa/ 下, 不带冒号则跟以前一样存到根目录。
func splitSendTo(to string) (email, subdir string, err error) {
	idx := strings.IndexByte(to, ':')
	if idx < 0 {
		return to, "", nil
	}
	email = to[:idx]
	raw := strings.Trim(to[idx+1:], "/")
	if raw == "" {
		return email, "", nil
	}
	if strings.ContainsAny(raw, `\:`) {
		return "", "", fmt.Errorf("-to subdir %q must not contain backslash or colon", raw)
	}
	clean := path.Clean(raw)
	for _, seg := range strings.Split(clean, "/") {
		if seg == ".." {
			return "", "", fmt.Errorf("-to subdir %q escapes the receive directory", raw)
		}
	}
	if clean == "." {
		return email, "", nil
	}
	return email, clean, nil
}

// SendFiles 把 paths 指定的文件/目录发给 to 对应的订阅方(邮箱, 可选 :子目录后缀)。
//
// via 二选一, 不接受默认之外的静默兜底(传别的值直接报错), 呼应两条路径完全不同的
// 失败语义:
//
//   - ViaDirect: 打洞失败就直接返回错误、一个字节都不传——没有经服务端中继的回落,
//     与直连入口的约定一致(见 directPeer.handleEntry)。要传输保密(QUIC 全程加密)、
//     或双方都不方便让 B 看到明文时用这条。
//   - ViaRelay: 不打洞, 只要 A、C 都连着同一个 B 就能传, 不需要对端开
//     directAccept。代价是数据经过 B(信令与直连一样鉴权发起方身份, 但字节本身
//     B 是能看到的, 不像直连那样端到端加密), 且吞吐受 B 的带宽限制。
//
// parallel 大于 1 且单个文件够大(见 chunkMinSize)时, 把这一个文件切成最多 parallel
// 块、各开一条独立连接并行传——只切单个大文件, 不会让多个文件同时传输(那样反而可能
// 拖长每一个文件的耗时, 见 planChunks 的阈值判断)。parallel<=1 或文件不够大时走原来
// 的单连接路径, 行为与之前完全一样。
func SendFiles(cfg conf.WsClient, to string, paths []string, via string, parallel int) error {
	if cfg.Connect == "" {
		return fmt.Errorf("websocket.client.connect is empty, cannot reach the server")
	}
	toEmail, subdir, err := splitSendTo(to)
	if err != nil {
		return err
	}
	if toEmail == "" {
		return fmt.Errorf("-to is required: which subscriber should receive the files")
	}
	if toEmail == cfg.Email {
		return fmt.Errorf("-to %s is this machine's own email", toEmail)
	}
	if via != ViaDirect && via != ViaRelay {
		return fmt.Errorf("-via must be %q or %q, got %q", ViaDirect, ViaRelay, via)
	}
	items, err := collectFiles(paths)
	if err != nil {
		return err
	}
	if subdir != "" {
		for i := range items {
			items[i].name = path.Join(subdir, items[i].name)
		}
	}
	var total int64
	for _, it := range items {
		total += it.size
	}
	fmt.Fprintf(os.Stderr, "sending %d file(s), %s to %s via %s (%s)\n",
		len(items), humanBytes(total), toEmail, cfg.Connect, via)

	sender, err := dialSender(cfg, "send")
	if err != nil {
		return err
	}
	defer sender.close()

	// send 按 via 分派到两种取得"可写文件通道"的方式, 拿到之后发送循环是共用的——
	// sendFile(直连)/sendFileViaRelay(中继)内部都调用同一个 sendFileOver, 首部/
	// 校验/落盘协议完全一样, 两条路径只是"字节怎么送到对面"不同。sendChunk 是它们
	// 的分块版, 同样两条路径共用一份编排(sendFileParallel)。
	var send func(it fileItem, onProgress func(int64)) (string, error)
	var sendChunk func(it fileItem, offset, length int64, tid string, chunkIdx, chunkCount int, onProgress func(int64)) (string, error)
	// quicStats 直连路径才有: 传完打一行 QUIC 收发统计, 用来判断"传得慢"是链路丢包
	// 还是本端的问题(见 nat/direct_stats.go 的判读说明)。
	var quicStats *directStats
	switch via {
	case ViaDirect:
		// 一次直连, 所有文件共用 —— 每个文件(或每一块)占一条 stream, 不必反复打洞。
		//
		// ensureSession 内部打洞/握手的过程日志全部挂在 directPeer.quiet 后面(见
		// nat/direct.go 的 logf), 一次性命令默认不显示——不加这两行的话, 用户在打洞
		// 期间会看着终端空等好几秒, 不知道卡在哪一步、打了多久、连的是哪个地址。这两行
		// 独立于那套调试日志之外, 一次性命令默认就该看到。
		fmt.Fprintf(os.Stderr, "connecting to %s via direct (NAT punch)...\n", toEmail)
		punchStart := time.Now()
		rule := conf.ClientDirect{Email: toEmail, ForwardPort: directFilePort}
		sess, err := sender.peer.ensureSession(rule)
		if err != nil {
			return fmt.Errorf("direct connect to %s failed, nothing was sent: %w", toEmail, err)
		}
		fmt.Fprintf(os.Stderr, "connected to %s at %s (punch %s)\n",
			toEmail, sess.addr, time.Since(punchStart).Round(time.Millisecond))
		quicStats = sess.stats
		send = func(it fileItem, onProgress func(int64)) (string, error) {
			return sender.peer.sendFile(sess, it, onProgress)
		}
		sendChunk = func(it fileItem, offset, length int64, tid string, chunkIdx, chunkCount int, onProgress func(int64)) (string, error) {
			return sender.peer.sendFileChunk(sess, it, offset, length, tid, chunkIdx, chunkCount, onProgress)
		}
	case ViaRelay:
		send = func(it fileItem, onProgress func(int64)) (string, error) {
			return sendFileViaRelay(sender.client, toEmail, it, onProgress)
		}
		sendChunk = func(it fileItem, offset, length int64, tid string, chunkIdx, chunkCount int, onProgress func(int64)) (string, error) {
			return sendFileChunkViaRelay(sender.client, toEmail, it, offset, length, tid, chunkIdx, chunkCount, onProgress)
		}
	}

	var sentBytes int64
	for i, it := range items {
		start := time.Now()
		prefix := fmt.Sprintf("[%d/%d] %s", i+1, len(items), it.name)
		p := newProgress(prefix, it.size)
		var saved string
		var err error
		if chunks := planChunks(it.size, parallel); chunks != nil {
			saved, err = sendParallel(it, chunks, sendChunk, p)
		} else {
			saved, err = send(it, p.update)
		}
		p.done()
		if err != nil {
			return fmt.Errorf("%s: %w", it.name, err)
		}
		sentBytes += it.size
		fmt.Fprintf(os.Stderr, "%s -> %s  (%s in %s, %s)\n", prefix, saved,
			humanBytes(it.size), time.Since(start).Round(time.Millisecond), rate(it.size, time.Since(start)))
	}
	fmt.Fprintf(os.Stderr, "done: %d file(s), %s\n", len(items), humanBytes(sentBytes))
	if quicStats != nil {
		if s := quicStats.summary(); s != "" {
			fmt.Fprintf(os.Stderr, "quic: %s\n", s)
		}
	}
	return nil
}

// oneShotSender 一次发送用到的连接与运行时。
type oneShotSender struct {
	peer   *directPeer
	ws     *websocket.Conn
	client *Client
	// writeDone 在 writePump 退出后关闭。close() 靠它等 writePump 把 send channel
	// 里排着的消息(比如 -recv 刚写出去的 fileReply)真正写到 socket 上, 再去强制
	// 断连——不然对面(尤其中继路径的对端)可能只收到"peer disconnected", 明明文件
	// 已经收完整了。
	writeDone chan struct{}
}

// closeGrace close() 等 writePump 自然收尾的上限, 兜底 writePump 卡住时不至于
// 一次性收文件(-recv)进程也跟着挂死退不出。
const closeGrace = 3 * time.Second

func (s *oneShotSender) close() {
	if s.client != nil {
		s.client.hub.unregister <- s.client
	}
	if s.writeDone != nil {
		select {
		case <-s.writeDone:
		case <-time.After(closeGrace):
		}
	}
	if s.ws != nil {
		s.ws.Close()
	}
	if s.peer != nil {
		s.peer.closeTransport()
	}
}

// dialSender 建 websocket、完成鉴权与(空)订阅, 并挂好直连运行时。-send 与 -recv
// 共用: 两者都是"临时连上去做一件事就退"的一次性进程。tag 只用于日志前缀, 区分这
// 两者(-debug 下的打洞日志会带上它)。
//
// 这段是 wsClientConn.connect 的精简版: 不要重连循环(一次性动作, 失败就该报错退出,
// 悄悄重试只会让人以为在传), 也不要入口监听和转发表(这个进程不接受任何入站)。
func dialSender(cfg conf.WsClient, tag string) (*oneShotSender, error) {
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
	if err := ch.auth(cfg.User, cfg.Pass, cfg.Key, cfg.Email, true, false); err != nil {
		ws.Close()
		return nil, fmt.Errorf("auth: %w", err)
	}
	if err := ch.subscribe(nil); err != nil {
		ws.Close()
		return nil, fmt.Errorf("subscribe: %w", err)
	}

	cfg.Connect = connect
	s.peer = newDirectPeer(tag, cfg, nil)
	// 前台命令: 屏幕上只留进度和结果, 打洞细节退到 -debug 后面(见 directPeer.quiet)。
	s.peer.quiet = true
	s.client = &Client{hub: hub, conn: ws, send: make(chan *Message, SEND_CHAN_LEN), bridge: bridge,
		tag: tag, receive: cfg.Receive, uuid: cfg.UUID, quiet: true}
	s.client.setDirectPeer(s.peer)
	s.peer.setClient(s.client)
	hub.register <- s.client
	s.writeDone = make(chan struct{})
	go func() {
		s.client.writePump()
		close(s.writeDone)
	}()
	go s.client.localReadPump()
	return s, nil
}

// ---------- 单文件分块并行发送 ----------

// sendParallel 把一个文件按 chunks 描述的区间拆成多条独立连接并行发, 是 send 闭包
// 的分块版编排, direct/relay 两条路径共用(区别只在传进来的 sendChunk 怎么开连接)。
// 与非分块路径同一个失败语义: 任意一块出错就让整份文件报错, 不重试、不跳过。
func sendParallel(it fileItem, chunks []chunkRange,
	sendChunk func(it fileItem, offset, length int64, tid string, chunkIdx, chunkCount int, onProgress func(int64)) (string, error),
	p *progress) (string, error) {
	tid, err := newTransferID()
	if err != nil {
		return "", fmt.Errorf("generate transfer id: %w", err)
	}
	cp := newChunkProgress(len(chunks), p)

	var wg sync.WaitGroup
	var mu sync.Mutex
	var firstErr error
	var saved string
	for i, c := range chunks {
		wg.Add(1)
		go func(i int, c chunkRange) {
			defer wg.Done()
			s, err := sendChunk(it, c.offset, c.length, tid, i, len(chunks), func(sent int64) { cp.update(i, sent) })
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				if firstErr == nil {
					firstErr = err
				}
				return
			}
			if s != "" {
				saved = s
			}
		}(i, c)
	}
	wg.Wait()
	if firstErr != nil {
		return "", firstErr
	}
	return saved, nil
}

// chunkProgress 把多个并行分块各自的进度回调聚合成一份整份文件的进度, 复用
// progress 已有的节流展示逻辑(见 progress.update), 不重复实现一遍。取件方向
// (file_recv.go)的分块编排也用它, 两边不必各写一份聚合代码。
type chunkProgress struct {
	mu   sync.Mutex
	each []int64
	p    *progress
}

func newChunkProgress(n int, p *progress) *chunkProgress {
	return &chunkProgress{each: make([]int64, n), p: p}
}

func (c *chunkProgress) update(i int, sent int64) {
	// progress.update 自己虽然是并发安全的(只是记一个值, 见其定义), 但这里的
	// each[i] 是所有分块共用同一个 slice——一个块写自己的 each[i] 的同时, 另一个块
	// 可能正在为了算 total 读整个 slice, 不加锁就是数据竞争, 所以要靠这把锁串行化。
	c.mu.Lock()
	defer c.mu.Unlock()
	c.each[i] = sent
	var total int64
	for _, n := range c.each {
		total += n
	}
	c.p.update(total)
}

// ---------- 进度输出 ----------

// progressTick 进度行的渲染间隔。定时渲染而不是"有新字节才画"——否则网络卡住后
// update() 不会再被调用, 界面就会停在卡住前算出的最后一个速率上, 看着像"卡在高速"
// 而不是真实地掉到 0(见 newProgress/render 的说明)。
const progressTick = 200 * time.Millisecond

// progress 单个文件的进度条, 输出到 stderr。
//
// update() 只负责记一个最新的 sent 值, 真正渲染在 newProgress 起的后台 goroutine
// 里按 progressTick 定时进行, 二者用 mu 解耦——中继路径下 update 现在是从
// localReadPump 那个后台 goroutine 回调进来的(见 nat/file_relay.go 的 onAcked),
// 不能假设只有一个 goroutine 会碰 sent。
type progress struct {
	prefix string
	total  int64

	mu       sync.Mutex
	sent     int64
	lastSent int64
	last     time.Time
	shown    bool

	stop     chan struct{}
	loopDone chan struct{}
}

func newProgress(prefix string, total int64) *progress {
	p := &progress{
		prefix: prefix, total: total, last: time.Now(),
		stop: make(chan struct{}), loopDone: make(chan struct{}),
	}
	go p.loop()
	return p
}

func (p *progress) update(sent int64) {
	p.mu.Lock()
	p.sent = sent
	p.mu.Unlock()
}

// loop 按 progressTick 定时渲染, 直到 done() 发出停止信号。
func (p *progress) loop() {
	defer close(p.loopDone)
	ticker := time.NewTicker(progressTick)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			p.render()
		case <-p.stop:
			return
		}
	}
}

func (p *progress) render() {
	p.mu.Lock()
	sent := p.sent
	now := time.Now()
	// 显示的是**这一小段区间**的速率, 不是从头到现在的累计平均: 排查限速/拥塞退避
	// 时要看的是"现在多快、有没有往下掉", 累计平均会把开头的高速和后面的骤降拉平抹
	// 掉, 看着一直是个温吞的数字, 分不清是从来没快过还是快过又掉了下去。定时渲染下,
	// 这一小段区间没有新字节时, sent-lastSent 就是 0, 速率如实显示成 0, 不会停留在
	// 卡住前的旧值上。
	instRate := rate(sent-p.lastSent, now.Sub(p.last))
	p.lastSent = sent
	p.last = now
	p.shown = true
	p.mu.Unlock()
	pct := 0.0
	if p.total > 0 {
		pct = float64(sent) * 100 / float64(p.total)
	}
	fmt.Fprintf(os.Stderr, "\r%s  %s/%s  %.1f%%  %s   ",
		p.prefix, humanBytes(sent), humanBytes(p.total), pct, instRate)
}

// done 收尾: 先停掉渲染 goroutine 并等它退出(避免和下面的擦行打印互相踩踏), 再把
// 进度那一行擦掉, 让后面的结果行从行首开始打。
func (p *progress) done() {
	close(p.stop)
	<-p.loopDone
	p.mu.Lock()
	shown := p.shown
	p.mu.Unlock()
	if shown {
		fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", 100))
	}
}

func rate(n int64, d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	return humanBytes(int64(float64(n)/d.Seconds())) + "/s"
}
