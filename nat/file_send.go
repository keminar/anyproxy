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
// parallel 大于 1 且单个文件够大(见 wantParallel)时, 把这一个文件按各连接实测速度
// 动态切块、各开一条独立连接并行传(见 chunkSizeForRate)——只切单个大文件, 不会让
// 多个文件同时传输(那样反而可能拖长每一个文件的耗时)。parallel<=1 或文件不够大时
// 走原来的单连接路径, 行为与之前完全一样。
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
	// 的分块版, 同样两条路径共用一份编排(sendParallel/runChunkWorkers)。
	var send func(it fileItem, onProgress func(int64)) (string, error)
	// sendChunk 的 worker 是 runChunkWorkers 里发起这次调用的那个 worker 编号
	// (0 开始, 一个 worker 绑一条连接), 不是分片的序号——一个 worker 会陆续认领
	// 好几片(每片大小按这条连接自己的实测速度动态决定, 见 file.go 的
	// chunkSizeForRate), 每次调 sendChunk 的 worker 编号不变。
	var sendChunk func(worker int, it fileItem, offset, length int64, tid string, chunkIdx int, onProgress func(int64)) (string, error)
	// abort 在一次分块并行传输失败后通知对端放弃 tid(见 sendParallel 的注释), 尽力
	// 而为、不返回错误。
	var abort func(tid string)
	// workers 是 sendParallel 该开几个抢活的 worker——direct 下是实际打通的独立连接数
	// (可能因为个别候选没打通而少于 parallel), relay 下没有"独立连接"这回事, 就是
	// parallel 本身当并发上限。
	var workers int
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
		workers = len(sessions)
		send = func(it fileItem, onProgress func(int64)) (string, error) {
			return sender.peer.sendFile(sessions[0], it, onProgress)
		}
		probe = func(it fileItem, noHash bool) (*probeResult, error) {
			return sender.peer.probeFile(sessions[0], it, noHash, notify)
		}
		sendChunk = func(worker int, it fileItem, offset, length int64, tid string, chunkIdx int, onProgress func(int64)) (string, error) {
			return sender.peer.sendFileChunk(sessions[worker], it, offset, length, tid, chunkIdx, onProgress)
		}
		abort = func(tid string) {
			// 随便挑一条打通的连接告诉对端就行, 不需要凑齐所有 worker——这条通知与
			// "哪个分片失败"无关, 只是"这个 tid 不用再等了"。
			sender.peer.abortTransfer(sessions[0], tid)
		}
	case ViaRelay:
		workers = parallel
		send = func(it fileItem, onProgress func(int64)) (string, error) {
			return sendFileViaRelay(sender.client, toEmail, it, onProgress)
		}
		probe = func(it fileItem, noHash bool) (*probeResult, error) {
			return probeFileViaRelay(sender.client, toEmail, it, noHash, notify)
		}
		sendChunk = func(worker int, it fileItem, offset, length int64, tid string, chunkIdx int, onProgress func(int64)) (string, error) {
			// relay 没有"独立连接"这回事(都复用同一条 websocket, 见 file_relay.go 的
			// sendFileChunkViaRelay), worker 编号在这条路径上只是并发上限, 不用来挑连接。
			return sendFileChunkViaRelay(sender.client, toEmail, it, offset, length, tid, chunkIdx, onProgress)
		}
		abort = func(tid string) {
			abortTransferViaRelay(sender.client, toEmail, tid)
		}
	}

	var sentBytes int64
	skipped := 0
	// warnedParallelNoResume 只提示一次: 一次 -send 可能发好几个文件, 每个都走
	// -parallel 的话没必要每个文件都重复这句话。
	warnedParallelNoResume := false
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
		if it.resumePart != "" {
			// 续传(覆盖或重命名都会续)只发一段尾巴, 不做分块并行; 进度从收方已有的字节数起算。
			at := it.resumeAt
			saved, err = send(it, func(n int64) { p.update(at + n) })
		} else if wantParallel(it.size, workers) {
			if !warnedParallelNoResume {
				warnedParallelNoResume = true
				fmt.Fprintln(os.Stderr, "note: -parallel transfers write several independent .chunks temp files and cannot be resumed if interrupted; an interrupted file restarts from scratch")
			}
			saved, err = sendParallel(it, workers, sendChunk, abort, p)
		} else {
			saved, err = send(it, p.update)
		}
		p.done()
		shown := p.wasShown()
		if err != nil {
			return fmt.Errorf("%s: %w", it.name, err)
		}
		sentBytes += it.size
		// 文件名已经在进度行上头单独打印过一遍的话(shown), 这里不再重复念它, 只续
		// 接一句结果——不然"[1/1] x.zip"和"[1/1] x.zip -> x.zip (...)"连着出现,
		// 看着像打印了两遍同一个文件名。没渲染过进度(文件小, 走得比第一个
		// progressTick 还快)的话, 文件名唯一露面的机会就是这一行, 照旧带上。
		if shown {
			fmt.Fprintf(os.Stderr, "  -> %s  (%s in %s, %s)\n", saved,
				humanBytes(it.size), time.Since(start).Round(time.Millisecond), rate(it.size, time.Since(start)))
		} else {
			fmt.Fprintf(os.Stderr, "%s -> %s  (%s in %s, %s)\n", prefix, saved,
				humanBytes(it.size), time.Since(start).Round(time.Millisecond), rate(it.size, time.Since(start)))
		}
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

// sendParallel 派 workers 个 worker(每个绑定一条独立连接)从共享的字节游标里抢着
// 认领活, 是 send 闭包的分块版编排, direct/relay 两条路径共用(区别只在传进来的
// sendChunk 怎么开连接)。认领/测速/按各自速度选分片大小这套编排全在 runChunkWorkers
// (nat/file.go)里, 这里只负责生成 transfer id 和把 sendChunk 接进去。
//
// 与非分块路径同一个失败语义: 任意一块出错就让整份文件报错, 不重试、不跳过——但不必
// 等其它 worker 也各自出错或认领完手头的活: 一旦有 worker 报错, 其它 worker 认领下
// 一片之前会先看到这个错误就地退出, 不会再白白多传几片注定要被扔掉的数据。
//
// 失败时用 abort 通知对端放弃 tid(见 fileHead.Abort 的注释): 接收端的 chunkAssembly
// 跑在对端(daemon 场景是远端长驻进程), 光是这边报错退出并不会让它知道要收拾, 不发
// 这条通知的话它只能靠 5 分钟的空闲回收器兜底——多个 worker 里只要有已经真正传出去
// 的分片报了错, 光凭字节计数就能立刻收尾(见 recvFileChunk), 但还没轮到认领、这里
// 就直接放弃的那些分片, 接收端根本不知道"还有一块永远不会来", 必须显式告诉它。
func sendParallel(it fileItem, workers int,
	sendChunk func(worker int, it fileItem, offset, length int64, tid string, chunkIdx int, onProgress func(int64)) (string, error),
	abort func(tid string),
	p *progress) (string, error) {
	tid, err := newTransferID()
	if err != nil {
		return "", fmt.Errorf("generate transfer id: %w", err)
	}
	// 进度按 worker(也就是按连接)算, 不是按 chunk 算——一个 worker 干完一片接着领
	// 下一片, c1/c2/... 这几栏该是"这条连接迄今为止总共传了多少", 不是"当前这一片
	// 传了多少"(片与片之间切换不该让进度条看着往回跳)。
	cp := newChunkProgress(workers, p)
	saved, err := runChunkWorkers(it.size, workers, cp, func(w int, offset, length int64, idx int, onProgress func(int64)) (string, error) {
		return sendChunk(w, it, offset, length, tid, idx, onProgress)
	})
	if err != nil && abort != nil {
		abort(tid)
	}
	return saved, err
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
	piece    []int64 // 每个 worker 当前正在传的这一片有多大(见 setPieceSize)
	lastAt   time.Time
	p        *progress
}

func newChunkProgress(n int, p *progress) *chunkProgress {
	cp := &chunkProgress{
		each: make([]int64, n), lastEach: make([]int64, n), piece: make([]int64, n), lastAt: time.Now(), p: p,
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

// setPieceSize 记下 worker i 刚认领到的这一片有多大, 供 summary() 展示。分片大小是
// 各连接按自己实测速度动态决定的(见 chunkSizeForRate), 不是配置项, 第一片固定是
// probeChunkSize(探测片), 之后每个 worker 各走各的——展示出来才看得出是不是某条
// 连接因为测速偏低被分到了明显更小的分片、一直追不上其它连接。
func (c *chunkProgress) setPieceSize(i int, length int64) {
	c.mu.Lock()
	c.piece[i] = length
	c.mu.Unlock()
}

// summary 渲染"cN: 已传 瞬时速率"这一串, 并把总速率也一并算出来返回, 按
// progress.render() 的节奏(progressTick)调用一次——窗口跟总速率的计算对齐, 不是
// 从头到现在的累计平均, 理由与 progress.render() 一致: 排查"是不是某条连接被
// 限速/拥塞退避"要看的是"现在多快", 不是平均值。
//
// 总速率**由这几条连接各自的字节增量直接加总算出**, 不是另外单独采样一次——如果
// 各算各的(这里一份时间窗口, progress.render() 自己再采一份), 两边取的时间点会
// 有微小的先后差, 遇到某条连接恰好在采样边界前后进出一大段数据时, "加起来对不上
// 总数"就会看得很明显。数字对得上账才好用来判断"是不是有条连接在拖后腿"。
func (c *chunkProgress) summary() (line string, totalRate string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	elapsed := now.Sub(c.lastAt)
	var b strings.Builder
	var totalDelta int64
	for i, sent := range c.each {
		if i > 0 {
			b.WriteString("  ")
		}
		delta := sent - c.lastEach[i]
		totalDelta += delta
		// "c%d:" 而不是 "conn%d:"——每条连接都要占一遍这个标签, 4 条连接下来省的
		// 宽度很可观, 标签本身没什么信息量, 认得出是第几条连接就够了。
		//
		// 两个 %-8s: 固定最小宽度, 数值变短时用空格补齐——不然"0B/s"跟"23.7MB/s"长度
		// 差一大截, 每次刷新后面的文字都要跟着左右挪, 看着比较闹心。8 是常见速率
		// (KB/s~几百MB/s)的字面宽度, 只比它们略宽一点点, 不像更早给到 10 那样在
		// "0B/s"这类短值后面拖出一大截空白——GB/s 这种更长的值本来就不常见, 且
		// %-8s 只规定最小宽度, 真出现了也不会被截断, 只是不再帮着对齐。当前这一片
		// 的大小放最后, 用括号而不是 "piece=" 这样的文字标签, 理由同上; 不参与宽度
		// 对齐, 是因为它比字节数/速率稳定得多(同一个 worker 好几次渲染之间通常还在
		// 传同一片)。
		fmt.Fprintf(&b, "c%d: %-8s %-8s (%s)", i+1, humanBytes(sent), rate(delta, elapsed), humanBytes(c.piece[i]))
	}
	copy(c.lastEach, c.each)
	c.lastAt = now
	return b.String(), rate(totalDelta, elapsed)
}

// ---------- 进度输出 ----------

// progressTick 进度行的渲染间隔。定时渲染而不是"有新字节才画"——否则网络卡住后
// update() 不会再被调用, 界面就会停在卡住前算出的最后一个速率上, 看着像"卡在高速"
// 而不是真实地掉到 0(见 newProgress/render 的说明)。
const progressTick = 1 * time.Second

// progress 单个文件的进度条, 输出到 stderr。
//
// 两行: 文件名(prefix)单独占一行, 只在第一次真正渲染时打印一次, 之后不再刷新——
// 名字本来就不会变, 没必要跟着进度行一起被 \r 反复重画; 总进度/速率(以及分块并行
// 时每条连接的明细)在它下面那一行, 用 \r 原地刷新, 不牵动上面那行, 不需要 ANSI
// 的"光标上移"这类要求终端支持 VT 的转义序列。
//
// update() 只负责记一个最新的 sent 值, 真正渲染在 newProgress 起的后台 goroutine
// 里按 progressTick 定时进行, 二者用 mu 解耦——中继路径下 update 现在是从
// localReadPump 那个后台 goroutine 回调进来的(见 nat/file_relay.go 的 onAcked),
// 不能假设只有一个 goroutine 会碰 sent。
type progress struct {
	prefix   string
	total    int64
	totalStr string // humanBytes(total), 算一次存下来, render() 里既当分子的对齐宽度、又省得每次重算
	sentW    int    // len(totalStr): sent 不会比 total 长多少, 按这个宽度右对齐, 不会比这个数固定得更松垮

	mu       sync.Mutex
	sent     int64
	lastSent int64
	last     time.Time
	shown    bool

	// lastLineLen 上一次实际输出的进度行(第二行, 不含开头的 \r)有多少字节, 供
	// render()/done() 决定要补多少空格才能盖住上一次的残留——不能靠一个固定的大
	// 常量硬凑, 见 render() 里的说明。
	lastLineLen int

	// connLine 非空时(分块并行传输, 见 newChunkProgress), render() 用它返回的总
	// 速率替换自己独立采样的那一份(见 render() 里的说明), 并把它返回的"每条连接
	// 各自的进度/速率"摘要追加到主进度后面。单连接传输不设, 输出跟改动前完全一样。
	connLine func() (line string, totalRate string)

	stopOnce sync.Once
	stop     chan struct{}
	loopDone chan struct{}
}

func newProgress(prefix string, total int64) *progress {
	totalStr := humanBytes(total)
	p := &progress{
		prefix: prefix, total: total, totalStr: totalStr, sentW: len(totalStr), last: time.Now(),
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
func (p *progress) setConnLine(f func() (string, string)) {
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
	firstRender := !p.shown // 文件名那一行只在第一次真正渲染时打印, 见 progress 的说明。
	p.shown = true
	connLine := p.connLine
	p.mu.Unlock()
	if firstRender {
		fmt.Fprintln(os.Stderr, p.prefix)
	}
	pct := 0.0
	if p.total > 0 {
		pct = float64(sent) * 100 / float64(p.total)
	}
	extra := ""
	if connLine != nil {
		// 分块并行时, 总速率改用 connLine 里"各连接增量直接加总"算出来的那一份,
		// 不用上面 instRate 这个独立采样的——两份各自的取样时刻有微小先后差, 用
		// 独立采样的总速率会出现"几条连接的速率加起来对不上总速率"这种看着违和
		// 的情况(参见 chunkProgress.summary 的说明), 改用同一份数据源就不会。
		var line string
		line, instRate = connLine()
		extra = "  " + line
	}
	// sent 右对齐到 sentW(即 total 那串的宽度): total 从头到尾不变, 这个宽度是
	// 提前量好的, 不用像固定给个 8 那样留一截用不上的空白——sent 从不会比 total
	// 长多少, 贴着"/"对齐比左对齐留一堆尾随空格好看。总速率长度还是会变(0B/s ~
	// 23.7MB/s 这种), 固定给 %-8s 兜住(理由与宽度取值同 chunkProgress.summary)。
	body := fmt.Sprintf("  %*s/%s  %6.1f%%  %-8s%s",
		p.sentW, humanBytes(sent), p.totalStr, pct, instRate, extra)
	// 新一行比上一行短时(比如分块并行的某条连接的速率数字变短了、或者一次刷新
	// 恰好没有 extra), 要补足空格盖住上一行的残留——不能像改动前那样靠一个固定的
	// 大常量(200)硬凑: 内容本身没那么长的时候, 打印出这么多空格会在终端实际宽度
	// 处触发自动换行, 而结尾的 \r 只能回到"换行后的那一行"行首, 于是上面多出几行
	// 洗不掉的空白——复制粘贴出来就是"进度行前面一大截空格"这种花样(实测 -parallel
	// 4 就能踩上)。这里只补到"迄今为止这个文件真正输出过的最大长度", 内容不会主动
	// 撑出终端宽度都用不完的空白, done() 收尾擦行时也是按这同一个长度擦, 道理一样。
	p.mu.Lock()
	if len(body) < p.lastLineLen {
		body += strings.Repeat(" ", p.lastLineLen-len(body))
	} else {
		p.lastLineLen = len(body)
	}
	p.mu.Unlock()
	fmt.Fprint(os.Stderr, "\r"+body)
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
		lineLen := p.lastLineLen
		p.mu.Unlock()
		if shown {
			// 按 lastLineLen(这个文件的进度行迄今真正输出过的最大长度)擦, 不再用
			// 固定常量——理由见 render() 里的说明, 擦得比实际输出过的还宽只会白白
			// 触发终端换行。
			fmt.Fprintf(os.Stderr, "\r%s\r", strings.Repeat(" ", lineLen))
		}
	})
}

// wasShown 报告这次传输过程中有没有实际渲染过至少一次进度行(见 render 里
// firstRender 的说明)。调用方(SendFiles/RecvFiles)拿它决定收尾那行要不要再重复一遍
// 文件名: 渲染过, 文件名已经单独占一行打印过, 收尾不用再念一遍, 看着重复; 没渲染过
// (文件小/传得比第一个 progressTick 还快), 文件名唯一露面的机会就是收尾这一行, 不能
// 省。放在 done() 之后调用能确保渲染 goroutine 已经彻底停了、读到的是最终值, 但
// shown 本身只会 false->true 单向翻转, 提前调用最多是那种"传输和下一个 tick 前后脚
// 完成"的边界上偶尔多打印一遍文件名, 不会读到错误的历史值。
func (p *progress) wasShown() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.shown
}

func rate(n int64, d time.Duration) string {
	if d <= 0 {
		return "-"
	}
	return humanBytes(int64(float64(n)/d.Seconds())) + "/s"
}
