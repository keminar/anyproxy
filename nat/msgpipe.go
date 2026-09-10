package nat

import (
	"errors"
	"io"
	"log"
	"sync"
	"time"

	"github.com/keminar/anyproxy/config"
)

// msgPipe 把"经 websocket 转发的一串 Message"包装成一个 fileConn(见 file.go)。
//
// 存在的理由: 中继路径下文件传输不走真实 socket、也不走 QUIC stream —— 字节是
// 一条条 Message 经 B 转发过来的。sendFileOver/recvFileOver 那套核心逻辑不该关心
// 这个区别, 所以在这里垫一层, 把"收消息"翻译成 Read()、把"发消息"翻译成 Write()。
//
// 流控(窗口 + 累计确认)是这一层的核心职责, 有两个非它不可的理由:
//
//  1. 收方那侧 push() 是被 localReadPump 调用的, 而 localReadPump 是订阅方处理
//     **所有**入站消息的唯一 goroutine —— 它一旦卡在这儿, 这条 websocket 上的
//     RDP 转发、心跳、其它一切全部停摆(现象: 一传文件, 同一台机器的 mstsc 就断)。
//     所以 pushCh 要有缓冲, 而且窗口必须保证在途字节量填不满这个缓冲。
//  2. 发方那侧, hub 的发送队列满了会直接丢消息并断开连接(见 Hub.run), 而字节流
//     少一段 = 对端帧边界错位, 表现为莫名其妙的解密失败或离谱的帧长度。窗口把
//     在途数据压在队列容量之内, 再加上 CMessage.done 的投递回执, 这条路径才是
//     "要么送到、要么当场报错", 不会静默丢数据。
type msgPipe struct {
	send    func([]byte) error // 把一段业务字节封成 Message 发出去
	sendAck func(int64) error  // 回一个累计确认(收方已消费到第几个字节), 可为 nil
	pushCh  chan []byte        // 待消费的数据段, 由 push() 塞入、Read() 取出
	done    chan struct{}      // 关闭信号, close 一次即可, 配合 select 让阻塞中的 Read/push 及时退出

	// tag 诊断日志前缀, 对应这条中继 session 所在的那条 websocket 连接(见
	// nat/file_relay.go 的 newFileRelaySession), 只在 -debug 2 打印的日志里用到,
	// 不参与业务逻辑, 所以不用加锁保护——创建时赋一次值, 之后只读。
	tag string

	mu       sync.Mutex
	rest     []byte // Read() 内部保存的、上一条消息里还没读完的尾巴
	closed   bool
	closeErr error // 对端带原因关闭时记的原因; Read 在 EOF 之外可以返回它

	deadlineMu   sync.Mutex // 单独保护 readDeadline, 不与 mu 共用——Read 阻塞等待时不该卡住关闭
	readDeadline time.Time

	// 发送侧窗口: sent/acked 只由 Write 那一个 goroutine 读写(sendFileOver 是单线程),
	// acked 的更新来自 onAck(另一个 goroutine), 所以用 ackMu 保护。
	ackMu    sync.Mutex
	ackedVal int64
	ackWake  chan struct{} // 收到确认时的唤醒信号(容量1, 满了就丢——值本身在 ackedVal 里)
	onAcked  func(int64)   // 可选: 每次确认值推进时回调, 供发送方把进度条挂在真实送达而不是本地读盘上(见 setOnAcked)
	sent     int64

	// 接收侧: 已交给上层的累计字节数与上次确认点, 只由 Read 那一个 goroutine 读写。
	consumed  int64
	lastAck   int64
	lastAckAt time.Time // 上一次回确认的时间, 仅用于 -debug 2 诊断日志算间隔/速率
}

const (
	// msgPipeBuffer 收方缓冲多少条消息。必须大于"窗口能容纳的消息条数", 这样正常
	// 流控下 push() 永远不会阻塞, localReadPump 也就不会被文件传输拖住。
	msgPipeBuffer = 32

	// relayWindow 在途(已发出、对端还没确认)字节数上限。
	// 4MB 对 2MB/s 量级的中继足够跑满, 又远小于 hub 发送队列(200 条)的容量。
	relayWindow = 4 << 20

	// relayAckEvery 收方每消费这么多字节回一次确认。必须明显小于 relayWindow,
	// 否则发方会等一个永远攒不够的确认。
	relayAckEvery = relayWindow / 4

	// relayAckTimeout 等确认的上限。对端要是根本不发确认(比如版本太老), 不能让
	// 发送方无限期挂着, 要给一个说得清楚的错误。
	relayAckTimeout = 60 * time.Second
)

func newMsgPipe(send func([]byte) error, sendAck func(int64) error) *msgPipe {
	return &msgPipe{
		send:    send,
		sendAck: sendAck,
		pushCh:  make(chan []byte, msgPipeBuffer),
		done:    make(chan struct{}),
		ackWake: make(chan struct{}, 1),
	}
}

// push 由消息分发那侧(localReadPump)调用, 把收到的一段数据交给读者。
//
// pushCh 有缓冲, 正常流控下不会阻塞——这一点很要紧: 调用方是订阅方处理所有入站
// 消息的唯一 goroutine, 在这里卡住等于整条 websocket 停摆。缓冲满了仍然阻塞(而不是
// 丢数据), 那是最后一道背压, 正常情况下够不着。
func (p *msgPipe) push(b []byte) {
	select {
	case p.pushCh <- b:
	case <-p.done:
	}
}

// onAck 收到对端的累计确认。只记下更大的值并唤醒可能在等窗口的 Write。
func (p *msgPipe) onAck(n int64) {
	p.ackMu.Lock()
	if n > p.ackedVal {
		p.ackedVal = n
	}
	acked := p.ackedVal
	onAcked := p.onAcked
	p.ackMu.Unlock()
	select {
	case p.ackWake <- struct{}{}:
	default: // 已经有一个待处理的唤醒了, 确认值是累计的, 不会因此丢
	}
	// 用 p.ackedVal(取过锁的最新值)而不是入参 n 回调: 重复/过期的确认不该让进度倒退。
	if onAcked != nil {
		onAcked(acked)
	}
}

// setOnAcked 挂一个进度回调: 每次确认值推进时收到新的累计已确认字节数。发送方
// (sendFileViaRelay/sendFileChunkViaRelay)用它替代"按本地读盘触发"的进度条——
// 中继路径下读盘只代表塞进了本地发送队列, 不代表对端真收到了(见 waitWindow 的
// 4MB 窗口), 按读盘触发会出现"冲一下就卡住"的假象。加锁是为了和 onAck 里的读
// 避免数据竞争, 不是因为真的会撞上(调用方总在还没开始写数据前设好这个回调)。
func (p *msgPipe) setOnAcked(f func(int64)) {
	p.ackMu.Lock()
	p.onAcked = f
	p.ackMu.Unlock()
}

func (p *msgPipe) acked() int64 {
	p.ackMu.Lock()
	defer p.ackMu.Unlock()
	return p.ackedVal
}

// Read 实现 io.Reader。顺带记账并按需回确认——确认要在数据**真正被上层取走**之后
// 才发, 不能一收到就发, 否则窗口保护的就不是接收方的处理能力了。
func (p *msgPipe) Read(buf []byte) (int, error) {
	n, err := p.read(buf)
	if n > 0 {
		p.consumed += int64(n)
		if p.consumed-p.lastAck >= relayAckEvery && p.sendAck != nil {
			if config.DebugLevel >= config.LevelDebug {
				now := time.Now()
				if !p.lastAckAt.IsZero() {
					d := now.Sub(p.lastAckAt)
					log.Printf("[%s] nat relay ack: consumed %d bytes in %s (%s)\n",
						p.tag, p.consumed-p.lastAck, d.Round(time.Millisecond), rate(p.consumed-p.lastAck, d))
				}
				p.lastAckAt = now
			}
			p.lastAck = p.consumed
			_ = p.sendAck(p.consumed)
		}
	}
	return n, err
}

func (p *msgPipe) read(buf []byte) (int, error) {
	p.mu.Lock()
	if len(p.rest) > 0 {
		n := copy(buf, p.rest)
		p.rest = p.rest[n:]
		p.mu.Unlock()
		return n, nil
	}
	p.mu.Unlock()

	var timer *time.Timer
	var timeoutCh <-chan time.Time
	p.deadlineMu.Lock()
	dl := p.readDeadline
	p.deadlineMu.Unlock()
	if !dl.IsZero() {
		d := time.Until(dl)
		if d <= 0 {
			return 0, errMsgPipeTimeout
		}
		timer = time.NewTimer(d)
		defer timer.Stop()
		timeoutCh = timer.C
	}

	select {
	case b, ok := <-p.pushCh:
		if !ok {
			return 0, p.closedErr()
		}
		n := copy(buf, b)
		if n < len(b) {
			p.mu.Lock()
			p.rest = b[n:]
			p.mu.Unlock()
		}
		return n, nil
	case <-p.done:
		// 关闭之前可能还有已经推进来、没读完的数据, 先把它们读干净再报结束——
		// 否则最后一小段(常常正是对端的结果回执)会被丢掉。
		select {
		case b := <-p.pushCh:
			n := copy(buf, b)
			if n < len(b) {
				p.mu.Lock()
				p.rest = b[n:]
				p.mu.Unlock()
			}
			return n, nil
		default:
		}
		return 0, p.closedErr()
	case <-timeoutCh:
		return 0, errMsgPipeTimeout
	}
}

func (p *msgPipe) closedErr() error {
	p.mu.Lock()
	err := p.closeErr
	p.mu.Unlock()
	if err == nil {
		err = io.EOF
	}
	return err
}

// Write 实现 io.Writer: 先等窗口有位置, 再经 send 发出去, 不做任何分片(调用方——
// writeFrame/io.CopyBuffer——本来就按合理的块大小在写)。
//
// 等窗口这一步是必须的: 没有它, 发送方会以本地磁盘的速度往一条网络通道里灌, hub
// 的发送队列一满就开始丢消息(还不告诉发送方), 对端收到的字节流就断层了。
func (p *msgPipe) Write(b []byte) (int, error) {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		return 0, errors.New("msgPipe: write on closed pipe")
	}
	if err := p.waitWindow(int64(len(b))); err != nil {
		return 0, err
	}
	if err := p.send(b); err != nil {
		return 0, err
	}
	p.sent += int64(len(b))
	return len(b), nil
}

// waitWindow 等到在途字节数落回窗口以内。第一块永远放行(sent==acked 时不等), 免得
// 单块大于窗口时死等。
func (p *msgPipe) waitWindow(n int64) error {
	var waitStart time.Time
	for {
		acked := p.acked()
		inflight := p.sent - acked
		if inflight == 0 || inflight+n <= relayWindow {
			return nil
		}
		debug := config.DebugLevel >= config.LevelDebug
		if debug && waitStart.IsZero() {
			waitStart = time.Now()
		}
		select {
		case <-p.ackWake:
			if debug {
				log.Printf("[%s] nat relay window: waited %s for ack, inflight=%d acked=%d\n",
					p.tag, time.Since(waitStart).Round(time.Millisecond), inflight, p.acked())
			}
		case <-p.done:
			return p.closedErr()
		case <-time.After(relayAckTimeout):
			return errors.New("msgPipe: peer stopped acknowledging relayed data")
		}
	}
}

// SetReadDeadline 实现 fileConn。
func (p *msgPipe) SetReadDeadline(t time.Time) error {
	p.deadlineMu.Lock()
	p.readDeadline = t
	p.deadlineMu.Unlock()
	return nil
}

// Close 实现 io.Closer: 本地主动关闭, 之后的 Read 立即返回 EOF、Write 立即报错。
// 不负责通知对端——那是调用方的事(直连路径靠 QUIC stream 自己的半关语义, 中继
// 路径由上层在关闭前/后发一条 METHOD_CLOSE, 见 file_relay.go)。
func (p *msgPipe) Close() error {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return nil
	}
	p.closed = true
	p.mu.Unlock()
	close(p.done)
	return nil
}

// closeWithError 由收到对端 METHOD_CLOSE(带错误原因)时调用: 之后的 Read 会返回
// 这个原因而不是普通 EOF, 好让调用方(比如 sendFileOver 等回复時)看到真正发生了
// 什么, 而不是一个语焉不详的 "EOF"。
func (p *msgPipe) closeWithError(err error) {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	p.closeErr = err
	p.mu.Unlock()
	close(p.done)
}

var errMsgPipeTimeout = errors.New("msgPipe: read timeout")
