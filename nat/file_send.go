package nat

import (
	"errors"
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

// ViaDirect/ViaRelay -send 的两种路径关键字, 必须显式声明(见 SendFiles 的 via 参数)。
// via 除了这两个关键字外还可以填一个 email——见 resolveVia。
const (
	ViaDirect = "direct" // 打洞直连(A<->C, 不经服务端转发数据), 默认
	ViaRelay  = "relay"  // 经服务端 B 中继转发(不打洞, 不需要对端开 directAccept)
)

// resolveVia 解出 -via 参数的真实含义。三种取值:
//
//   - "direct": 打洞直连, 不经任何中继。
//   - "relay": 经服务端 B 中继转发(不打洞)。
//   - 其它任意值: 当作一台公网 VPS 的 email——打洞直连, 但打洞对象换成这台 VPS 的
//     盲转发中继端点(需 VPS 开 directRelay), 而非直连对端。QUIC/TLS 仍端到端在两个
//     订阅方之间, VPS 只盲转发不透明包。等价于配置里 direct[].via, 只是这里是命令行、
//     一次性生效。详见 docs/direct-relay-design.md。
//
// 不与前两个关键字冲突: 正常 email 都带 "@", 不会字面等于 "direct"/"relay" 这两个
// 保留词; 真撞上了(极端情况下有人把订阅方 email 就配成这两个词)按关键字处理, 不支持
// 经一个恰好叫 direct/relay 的 VPS 中继——这本身也是一种应该改名的配置。
func resolveVia(via string) (actualVia, relayVia string) {
	switch via {
	case ViaDirect, ViaRelay, "":
		if via == "" {
			via = ViaDirect
		}
		return via, ""
	default:
		return ViaDirect, via
	}
}

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
// via 三选一(见 resolveVia), 不接受识别不出的值之外的静默兜底, 呼应几条路径完全不同的
// 失败语义:
//
//   - ViaDirect("direct"): 打洞失败就直接返回错误、一个字节都不传——没有经服务端中继的
//     回落, 与直连入口的约定一致(见 directPeer.handleEntry)。要传输保密(QUIC 全程加密)、
//     或双方都不方便让 B 看到明文时用这条。
//   - ViaRelay("relay"): 不打洞, 只要 A、C 都连着同一个 B 就能传, 不需要对端开
//     directAccept。代价是数据经过 B(信令与直连一样鉴权发起方身份, 但字节本身
//     B 是能看到的, 不像直连那样端到端加密), 且吞吐受 B 的带宽限制。
//   - 一台公网 VPS 的 email: 仍是打洞直连, 但打洞对象换成这台 VPS(需开 directRelay)的
//     盲转发中继端点——两个居民各自朝 VPS 打洞, QUIC/TLS 仍端到端在 A<->C, VPS 只盲
//     转发不透明包、看不到明文。用于双方都在受限 CGNAT 后彼此直连打不通、但各自能连通
//     该 VPS 的场景。等价于配置里 direct[].via, 只是这里是一次性命令行、不需要写进配置
//     文件。详见 docs/direct-relay-design.md。
//
// parallel 大于 1 且单个文件够大(见 chunkMinSize)时, 把这一个文件切成最多 parallel
// 块、各开一条独立连接并行传——只切单个大文件, 不会让多个文件同时传输(那样反而可能
// 拖长每一个文件的耗时, 见 planChunks 的阈值判断)。parallel<=1 或文件不够大时走原来
// 的单连接路径, 行为与之前完全一样。
//
// conflict 是收方已有同名文件时的处理方式(见 ParseConflict 与 file_conflict.go): 空串表示
// 终端里逐个询问、否则让收方自动改名。
func SendFiles(cfg conf.WsClient, to string, paths []string, via string, parallel int, conflict string) error {
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
	res, err := newConflictResolver(conflict, conflictIn, os.Stderr)
	if err != nil {
		return err
	}
	parallel = clampParallel(parallel)
	actualVia, relayVia := resolveVia(via)
	if relayVia != "" {
		if relayVia == cfg.Email {
			return fmt.Errorf("-via %s is this machine's own email", relayVia)
		}
		if relayVia == toEmail {
			return fmt.Errorf("-via %s must be a different subscriber from -to %s", relayVia, toEmail)
		}
		// 中继连接要在 e2e QUIC 流里对 C 应答 uuid 挑战(见 direct_relay_auth.go), 提前
		// 校验免得先打完一趟洞、连上了才在鉴权这步报错。
		if !conf.IsValidUUID(cfg.UUID) {
			return errors.New("websocket.client.uuid is empty or not a valid uuid, required to authenticate a relayed (-via VPS) connection")
		}
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
	// quicStats 直连路径才有: 传完每条连接各打一行 QUIC 收发统计, 用来判断"传得慢"
	// 是链路丢包还是本端的问题(见 nat/direct_stats.go 的判读说明)。parallel>1 时
	// 这里会有不止一条, 方便挨个对比是不是某一条连接明显比别的差。
	var quicStats []*directSession
	// probe 在一条新通道上探测收方有没有同名文件(同名协商用)。
	var probe func(it fileItem, noHash bool) (*probeResult, error)
	notify := func(msg string) { fmt.Fprintln(os.Stderr, msg) }
	switch actualVia {
	case ViaDirect:
		// 一次直连, 所有文件共用 —— 每个文件(或每一块)占一条 stream, 不必反复打洞。
		//
		// ensureSession 内部打洞/握手的过程日志全部挂在 directPeer.quiet 后面(见
		// nat/direct.go 的 logf), 一次性命令默认不显示——不加这两行的话, 用户在打洞
		// 期间会看着终端空等好几秒, 不知道卡在哪一步、打了多久、连的是哪个地址。这两行
		// 独立于那套调试日志之外, 一次性命令默认就该看到。
		if relayVia != "" {
			fmt.Fprintf(os.Stderr, "connecting to %s via direct (NAT punch, blind-relayed through %s)...\n", toEmail, relayVia)
		} else {
			fmt.Fprintf(os.Stderr, "connecting to %s via direct (NAT punch)...\n", toEmail)
		}
		punchStart := time.Now()
		rule := conf.ClientDirect{Forward: conf.DirectForwardTarget{Email: toEmail, Tag: directFileTag}, Via: relayVia}
		// parallel>1 时这里可能打出最多 parallel 条相互独立的连接(见 ensureParallelSessions),
		// 不是像以前那样只打一条再靠 QUIC stream 复用——目的就是让每条连接各自维护自己的
		// 拥塞窗口, 链路有丢包时聚合吞吐能接近线性提升。parallel<=1 时行为跟以前完全一样,
		// 只会拿到一条连接。
		sessions, err := sender.peer.ensureParallelSessions(rule, parallel)
		if err != nil {
			return fmt.Errorf("direct connect to %s failed, nothing was sent: %w", toEmail, err)
		}
		if len(sessions) > 1 {
			fmt.Fprintf(os.Stderr, "connected to %s at %s (punch %s, %d independent connections)\n",
				toEmail, sessions[0].addr, time.Since(punchStart).Round(time.Millisecond), len(sessions))
		} else {
			fmt.Fprintf(os.Stderr, "connected to %s at %s (punch %s)\n",
				toEmail, sessions[0].addr, time.Since(punchStart).Round(time.Millisecond))
		}
		quicStats = sessions
		send = func(it fileItem, onProgress func(int64)) (string, error) {
			return sender.peer.sendFile(sessions[0], it, onProgress)
		}
		probe = func(it fileItem, noHash bool) (*probeResult, error) {
			return sender.peer.probeFile(sessions[0], it, noHash, notify)
		}
		sendChunk = func(it fileItem, offset, length int64, tid string, chunkIdx, chunkCount int, onProgress func(int64)) (string, error) {
			// 分块轮着用打开的这几条连接: chunkCount 可能比 len(sessions) 多(小文件
			// 阈值与连接数上限是分开算的), 取模让多出来的块回退到"共享一条连接的多个
			// stream"这个本来就安全的老路径, 不会因为连接数不够就出错。
			sess := sessions[chunkIdx%len(sessions)]
			return sender.peer.sendFileChunk(sess, it, offset, length, tid, chunkIdx, chunkCount, onProgress)
		}
	case ViaRelay:
		send = func(it fileItem, onProgress func(int64)) (string, error) {
			return sendFileViaRelay(sender.client, toEmail, it, onProgress)
		}
		probe = func(it fileItem, noHash bool) (*probeResult, error) {
			return probeFileViaRelay(sender.client, toEmail, it, noHash, notify)
		}
		sendChunk = func(it fileItem, offset, length int64, tid string, chunkIdx, chunkCount int, onProgress func(int64)) (string, error) {
			return sendFileChunkViaRelay(sender.client, toEmail, it, offset, length, tid, chunkIdx, chunkCount, onProgress)
		}
	}

	var sentBytes int64
	skipped := 0
	for i, it := range items {
		start := time.Now()
		prefix := fmt.Sprintf("[%d/%d] %s", i+1, len(items), it.name)

		// 同名协商放在进度条之前: 它要向用户提问, 进度条的定时重绘会把提示冲掉。
		skip, err := res.prepareSend(&it, probe)
		if err != nil {
			return fmt.Errorf("%s: %w", it.name, err)
		}
		if skip {
			fmt.Fprintf(os.Stderr, "%s -> skipped (already exists)\n", prefix)
			skipped++
			continue
		}
		p := newProgress(prefix, it.size)
		var saved string
		if it.conflict == ConflictResume {
			// 续传只发一段尾巴, 不做分块并行; 进度从收方已有的字节数起算。
			at := it.resumeAt
			saved, err = send(it, func(n int64) { p.update(at + n) })
		} else if chunks := planChunks(it.size, parallel); chunks != nil {
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
	fmt.Fprintf(os.Stderr, "done: %d file(s), %s%s\n", len(items)-skipped, humanBytes(sentBytes), skippedNote(skipped))
	for i, sess := range quicStats {
		if s := sess.stats.summary(); s != "" {
			if len(quicStats) > 1 {
				fmt.Fprintf(os.Stderr, "quic conn%d: %s\n", i+1, s)
			} else {
				fmt.Fprintf(os.Stderr, "quic: %s\n", s)
			}
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
//
// 除了聚合总量, 它还给 progress 挂一份"每条连接自己多快"的摘要(见 summary)——
// 分块并行传输本来就是想看"是不是每条连接都在出力、有没有哪一条明显拖后腿",
// 只看总速率看不出这个。
type chunkProgress struct {
	mu       sync.Mutex
	each     []int64 // 每块已发送/已取到的累计字节数
	lastEach []int64 // 上一次 summary() 时的快照, 用来算这一小段区间的瞬时速率
	lastAt   time.Time
	p        *progress
}

func newChunkProgress(n int, p *progress) *chunkProgress {
	cp := &chunkProgress{
		each: make([]int64, n), lastEach: make([]int64, n), lastAt: time.Now(), p: p,
	}
	p.setConnLine(cp.summary)
	return cp
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

// summary 渲染"connN: 已传 瞬时速率"这一串, 按 progress.render() 的节奏(progressTick)
// 调用一次——窗口跟总速率的计算对齐, 不是从头到现在的累计平均, 理由与 progress.render()
// 一致: 排查"是不是某条连接被限速/拥塞退避"要看的是"现在多快", 不是平均值。
func (c *chunkProgress) summary() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(c.lastAt)
	var b strings.Builder
	for i, sent := range c.each {
		if i > 0 {
			b.WriteString("  ")
		}
		fmt.Fprintf(&b, "conn%d: %s %s", i+1, humanBytes(sent), rate(sent-c.lastEach[i], elapsed))
	}
	copy(c.lastEach, c.each)
	c.lastAt = now
	return b.String()
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

	// connLine 非空时(分块并行传输, 见 newChunkProgress), render() 在主进度后面
	// 追加它返回的这一段"每条连接各自的进度/速率"摘要。单连接传输不设, 输出跟
	// 改动前完全一样。
	connLine func() string

	stopOnce sync.Once
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

// setConnLine 挂上 connLine 回调。要过锁: render() 的渲染 goroutine 从 newProgress
// 返回那一刻就已经在跑, newChunkProgress 是在那之后才调这个方法的, 不加锁就是对
// 同一个字段的数据竞争。
func (p *progress) setConnLine(f func() string) {
	p.mu.Lock()
	p.connLine = f
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
	connLine := p.connLine
	p.mu.Unlock()
	pct := 0.0
	if p.total > 0 {
		pct = float64(sent) * 100 / float64(p.total)
	}
	extra := ""
	if connLine != nil {
		extra = "  " + connLine()
	}
	fmt.Fprintf(os.Stderr, "\r%s  %s/%s  %.1f%%  %s%s   ",
		p.prefix, humanBytes(sent), humanBytes(p.total), pct, instRate, extra)
}

// done 收尾: 先停掉渲染 goroutine 并等它退出(避免和下面的擦行打印互相踩踏), 再把
// 进度那一行擦掉, 让后面的结果行从行首开始打。
//
// 幂等。传进来的都是"收尾"语义的调用点(正常路径 + 出错路径), 重复调用不该炸: 直接
// close(p.stop) 第二次就是 close of closed channel 的 panic, 所以整段用 once 包住。
//
// 漏调 done 的代价很大, 这一点必须说清楚: 渲染 goroutine 是按 ticker 无限循环的,
// 没人关 p.stop 它就永远不会退出, 会以 200ms 一次的频率往 stderr 一直打 "\r... ",
// 直到整个进程结束。在 go test 里就是**当前这个用例早就跑完了、后面的用例还在跑**,
// 它却一直在刷屏, 把真正的失败信息(--- FAIL / panic 栈)冲得七零八落——CI 上排查问题
// 时最要命的就是这个。所以新增调用点时必须配一个 done(通常 defer)。
func (p *progress) done() {
	p.stopOnce.Do(func() {
		close(p.stop)
		<-p.loopDone
		p.mu.Lock()
		shown := p.shown
		p.mu.Unlock()
		if shown {
			// 200: 单连接那行不到 100 就够了, 但分块并行时 connLine 会在后面加上
			// "connN: 已传 速率" 这样的片段, 4 条连接能把整行拉到一百七八十字符,
			// 擦得不够宽会在终端上留下没盖住的尾巴。
			fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", 200))
		}
	})
}

func rate(n int64, d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	return humanBytes(int64(float64(n)/d.Seconds())) + "/s"
}
