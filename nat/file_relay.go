package nat

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/keminar/anyproxy/utils/conf"
)

// 文件传输的中继路径(经服务端 B 转发, 而不是 A<->C 打洞直连)。
//
// 现有的两条中继(裸TCP转发、UDP转发)都是给"外部客户端连 B 的公网端口"这种场景设计
// 的——B 认的是端口, 不认发起方是谁。文件传输如果照搬这个模型, 发起方身份就没法
// 验证, client.receive.allow 会形同虚设。
//
// 所以这里换一种接法: 复用 A、C 两边已经用密钥/密码鉴权过的 websocket 连接本身来转发
// 文件字节, 不需要新开端口、不需要动 server.forward/client.forward。B 只做一件事:
// 按 email 把 A 的一条"文件传输"关联到 C, 之后原样转发两边的消息。B 能看到 A 是用
// 哪个已认证账号连上来的(c.Email), 这个身份靠谱、不是 A 自己在协议里能伪造的东西,
// 所以把它转告给 C 之后, client.receive.allow 依然生效——这是选这条设计而不是"新开
// 一个公网转发端口"的全部理由。
//
// 时序:
//
//	A --d_file_open{email}-->     B    我要给这个 email 发文件
//	B --d_file_open{fromEmail}--> C    有人(这个身份)要发文件给你
//	C --d_file_ready{err}-->      B    C 按 client.receive 检查完的结果
//	B --d_file_ready{err}-->      A    转告结果
//	A <--文件数据(Message.Body)--> B <--> C   之后跟直连一样是 fileHead/数据/fileTrailer/fileReply,
//	                                          只是载体从 QUIC stream 换成一条条 Message
//
// 这条路径上的所有消息(信令与数据)都走自己的 Type=ConnFileRelay。
//
// 早先复用了 ConnTCP, 那是个真会出事的错: 中继的 ID 来自 fileRelay.nextID, 裸TCP
// 转发的 ID 来自 forwardInc, 两个计数器各自从 1 起步、互不知情, 共用一个 Type 就
// 必然撞号; 而订阅方那侧是文件中继先做分发判断的, 撞上之后转发的数据(实测是 RDP
// over TLS 的记录)会被中继抢走推进加密字节流 —— 文件这头帧边界错位(报出 0x17030300
// 这种"帧长度", 其实是 TLS 记录头), RDP 那头数据被偷走当场断线。(ID,Type) 本来就是
// 复合键, 各走各的 Type 就天然不相交。

const (
	METHOD_FILE_RELAY_OPEN  = "d_file_open"  // A -> B, B -> C
	METHOD_FILE_RELAY_READY = "d_file_ready" // C -> B, B -> A

	// METHOD_FILE_RELAY_ACK 收方回给发方的累计确认(见 msgPipe 的流控)。
	//
	// 故意不放进 isFileRelayMethod: 那样 B 会走 forwardIfRouted 这条通用转发,
	// 按路由原样转给另一端就行, B 不需要认识这个方法, 老版本的 B 也能正常中转。
	METHOD_FILE_RELAY_ACK = "d_file_ack" // 收方 -> B -> 发方
)

// fileRelayPendingTTL A 等 C 回 d_file_ready 的上限, 超时即报错给 A, 不让它干等。
const fileRelayPendingTTL = 15 * time.Second

// FileRelayOpen 请求中继一次文件传输。
//
// FromEmail 只在 B 转给 C 的那一份里有意义, 由 B 自己填(取自那条 websocket 的鉴权
// 账号)——它只是给 C 用来查 receive.allow 里对应哪一条(email 只是备注/查找用,
// 见 conf.ClientReceive), 不再是安全判断本身: 真正的凭证是 Salt 派生出的会话密钥
// 能不能解开 A 加密的数据, 那个 B 从头到尾都摸不到(见 nat/relay_crypto.go)。
type FileRelayOpen struct {
	Email     string `json:"email"`     // A -> B: 目标订阅方
	FromEmail string `json:"fromEmail"` // B -> C: 发起方身份(查找用), 由 B 填
	Salt      string `json:"salt"`      // A -> B -> C: 本次会话的随机盐(不是秘密), 由 A 生成, B 原样转发

	// Op 这条中继是哪个方向的: 空(或 "send")表示 A 要发文件给 C, "pull" 表示 A 要从
	// C 取文件(见 nat/file_pull.go)。B 只负责原样转发, 不理解它的含义。
	//
	// 老版本的 B 会把这个字段丢掉(它转发时是重新拼一个新结构体), C 于是当成发送处理,
	// 把 A 的取件请求帧当 fileHead 解, 最后回一个"名字不合法"的错误 —— 丑, 但是明确
	// 失败, 不会静默地传错东西。所以中继取件要求 B 与两端一起升级。
	Op string `json:"op"`
}

// fileRelayOpPull Op 的取值, 空值即默认的"发文件"。
const fileRelayOpPull = "pull"

// FileRelayReady C 侧检查结果(receive.dir 是否配置、email 是否在 allow 里)。
type FileRelayReady struct {
	Err string `json:"err"` // 非空表示 C 拒绝, 原因会一路带回 A
}

// isFileRelayMethod 信令方法是否属于文件中继。
func isFileRelayMethod(method string) bool {
	return method == METHOD_FILE_RELAY_OPEN || method == METHOD_FILE_RELAY_READY
}

// fileRelaySide 一条路由的一端: 哪个 Client、用它自己的哪个 ID。
type fileRelaySide struct {
	client *Client
	id     uint
}

// fileRelayRoute A<->C 之间的一条文件传输通道, B 只做原样转发。
type fileRelayRoute struct {
	a, c     fileRelaySide
	deadline time.Time // 还没等到 c 回 ready 之前的超时点; ready 之后不再使用
	ready    bool
}

// fileRelayKey 路由表的键: 消息是从哪个 Client、带着它自己的哪个 ID 发过来的。
// a 发消息用 (a.client, a.id) 查, c 发消息用 (c.client, c.id) 查, 两个键指向同一个
// *fileRelayRoute, 从中找到"另一端"转发过去。
type fileRelayKey struct {
	client *Client
	id     uint
}

// fileRelayBroker 服务端(B)侧的文件中继路由表。
type fileRelayBroker struct {
	mu     sync.Mutex
	routes map[fileRelayKey]*fileRelayRoute
	nextID uint
}

var fileRelay = &fileRelayBroker{routes: make(map[fileRelayKey]*fileRelayRoute)}

// handleFileRelayServer 服务端(B)侧处理文件中继消息。返回 true 表示消息已消费,
// 调用方不应再送进 ServerBridge——包括信令方法, 也包括属于某条已建路由的普通数据
// 消息(Method 为空)。
//
// 先看 Type: 只认 ConnFileRelay。不看 Type 只按 ID 查路由的话, 会把同号的裸TCP
// 转发消息一并吞掉(见文件头部的说明)。
func handleFileRelayServer(c *Client, msg *Message) bool {
	if msg.Type != ConnFileRelay {
		return false
	}
	if isFileRelayMethod(msg.Method) {
		switch msg.Method {
		case METHOD_FILE_RELAY_OPEN:
			fileRelay.onRequest(c, msg)
		case METHOD_FILE_RELAY_READY:
			fileRelay.forward(c, msg)
		}
		return true
	}
	// 不是信令: 只有落在某条已建路由里的消息才认, 否则不是这条路径的消息(交回给
	// 调用方按原来的逻辑处理), 避免这个检查把无关消息也吞掉。
	return fileRelay.forwardIfRouted(c, msg)
}

// onRequest A 请求给 email 中继发文件: 找到 C, 分配路由, 把请求转过去(带上 A 的
// 真实身份)。找不到人或对方是自己就直接回错误, 不建路由。
func (b *fileRelayBroker) onRequest(c *Client, msg *Message) {
	var req FileRelayOpen
	if err := json.Unmarshal(msg.Body, &req); err != nil {
		log.Printf("[%s] nat file relay: bad open from email %s: %v", c.tag, c.Email, err)
		return
	}
	reply := func(err string) {
		body, _ := json.Marshal(FileRelayReady{Err: err})
		c.hub.broadcast <- &CMessage{client: c, message: &Message{ID: msg.ID, Type: ConnFileRelay, Method: METHOD_FILE_RELAY_READY, Body: body}}
	}
	if req.Email == c.Email {
		reply("cannot relay a file to yourself")
		return
	}
	peer := c.hub.GetClientByEmail(req.Email)
	if peer == nil {
		reply(fmt.Sprintf("no subscriber online for email %s", req.Email))
		return
	}

	b.mu.Lock()
	b.sweepLocked(time.Now())
	b.nextID++
	id := b.nextID
	route := &fileRelayRoute{
		a:        fileRelaySide{client: c, id: msg.ID},
		c:        fileRelaySide{client: peer, id: id},
		deadline: time.Now().Add(fileRelayPendingTTL),
	}
	b.routes[fileRelayKey{c, msg.ID}] = route
	b.routes[fileRelayKey{peer, id}] = route
	b.mu.Unlock()

	// Salt 与 Op 都原样转发: 它们不是秘密, B 不需要也不应该生成、校验或理解, 只负责
	// 搬运。Op 漏转的话 C 会把取件当成发送来处理, 所以新增字段时这里必须跟着加。
	body, err := json.Marshal(FileRelayOpen{FromEmail: c.Email, Salt: req.Salt, Op: req.Op})
	if err != nil {
		reply("server encode failed")
		b.drop(route)
		return
	}
	peer.hub.broadcast <- &CMessage{client: peer, message: &Message{ID: id, Type: ConnFileRelay, Method: METHOD_FILE_RELAY_OPEN, Body: body}}
	log.Printf("[%s->%s] nat file relay: email %s -> %s, relaying a file transfer request", c.tag, peer.tag, c.Email, req.Email)
}

// forward 把消息原样转给路由的另一端, 替换成对端自己认得的 ID。用于信令回执
// (d_file_ready)与普通数据消息, 两者处理方式相同——B 不关心内容, 只做转发。
func (b *fileRelayBroker) forward(from *Client, msg *Message) {
	b.mu.Lock()
	route, ok := b.routes[fileRelayKey{from, msg.ID}]
	if !ok {
		b.mu.Unlock()
		return // 路由已经不在了(超时清理/已关闭), 静默丢弃即可
	}
	// ready 是 C 回的(它是收到请求的那一端), 也就是说 from 这时候是 route.c.client,
	// 不是下面判断方向用的 route.a.client——之前误把这行放在方向判断的分支里, 导致
	// ready 永远不会被置真, sweepLocked 会把任何一条存活超过 15s 的路由都当"没
	// 响应"清掉, 不管它是不是正常在传一个大文件。
	route.ready = route.ready || msg.Method == METHOD_FILE_RELAY_READY
	other := route.a
	if from == route.a.client {
		other = route.c
	}
	closing := msg.Method == METHOD_CLOSE
	b.mu.Unlock()

	other.client.hub.broadcast <- &CMessage{client: other.client, message: &Message{ID: other.id, Type: ConnFileRelay, Method: msg.Method, Body: msg.Body}}
	if closing {
		b.drop(route)
	}
}

// forwardIfRouted 只有这条消息确实属于某条已建路由(数据消息, Method 为空)时才转发
// 并消费掉; 不属于就原样交还, 不影响调用方接下来对它的处理。
func (b *fileRelayBroker) forwardIfRouted(from *Client, msg *Message) bool {
	b.mu.Lock()
	_, ok := b.routes[fileRelayKey{from, msg.ID}]
	b.mu.Unlock()
	if !ok {
		return false
	}
	b.forward(from, msg)
	return true
}

// drop 拆掉一条路由的两个方向索引。
func (b *fileRelayBroker) drop(route *fileRelayRoute) {
	b.mu.Lock()
	delete(b.routes, fileRelayKey{route.a.client, route.a.id})
	delete(b.routes, fileRelayKey{route.c.client, route.c.id})
	b.mu.Unlock()
}

// sweepLocked 清掉等 ready 等到超时的路由, 并告诉 A 超时了——调用方必须已持锁。
// 只在还没等到 ready 时才清: ready 之后这条路由要活到文件传完、由 METHOD_CLOSE
// 自然收尾, 没有固定的"这次传输最多传多久"上限(大文件在慢链路上传很久是正常的)。
func (b *fileRelayBroker) sweepLocked(now time.Time) {
	var expired []fileRelaySide
	for key, route := range b.routes {
		if route.ready || now.Before(route.deadline) {
			continue
		}
		if key.client != route.a.client || key.id != route.a.id {
			continue // 两个键指向同一条路由, 只处理一次
		}
		delete(b.routes, fileRelayKey{route.a.client, route.a.id})
		delete(b.routes, fileRelayKey{route.c.client, route.c.id})
		expired = append(expired, route.a)
	}
	if len(expired) == 0 {
		return
	}
	// 同 clientGone: 通知不能在持锁期间发。这里是持着 b.mu 被调用的, 而 hub 那侧
	// (Hub.run 的 unregister 分支)会调 clientGone 来抢同一把锁 —— 在这里阻塞在
	// hub.broadcast 上, 就会跟它互相等成死锁。
	go func() {
		for _, side := range expired {
			body, _ := json.Marshal(FileRelayReady{Err: "peer did not respond in time"})
			side.client.hub.broadcast <- &CMessage{client: side.client,
				message: &Message{ID: side.id, Type: ConnFileRelay, Method: METHOD_FILE_RELAY_READY, Body: body}}
		}
	}()
}

// clientGone 某个 Client 断线时, 把它牵涉到的路由全部拆掉, 并让另一端的 msgPipe
// 收到一个说得清楚的错误——不拆的话另一端会在 Read() 上无限期挂着, 既不是 EOF
// 也不是超时, 表现就是"传输卡住不动了"。
func (b *fileRelayBroker) clientGone(c *Client) {
	var affected []*fileRelayRoute
	b.mu.Lock()
	for key, route := range b.routes {
		if key.client != c {
			continue
		}
		affected = append(affected, route)
	}
	for _, route := range affected {
		delete(b.routes, fileRelayKey{route.a.client, route.a.id})
		delete(b.routes, fileRelayKey{route.c.client, route.c.id})
	}
	b.mu.Unlock()

	if len(affected) == 0 {
		return
	}
	// 通知另一端必须另起 goroutine 发, 不能在这里直接发: clientGone 是在 Hub.run()
	// 的 unregister 分支里**同步**调用的, 而 hub.broadcast 是无缓冲 channel、唯一的
	// 读取者正是 Hub.run() 自己 —— 在这里直接发就是自己等自己, 整个 hub 会就此永久
	// 卡死(现象: 之后所有连接的注册、所有消息转发全部无响应, 而且只在这个断线的
	// client 身上确实挂着中继路由时才触发, 所以表现为"第一次中继用完之后服务端就废了")。
	go func() {
		for _, route := range affected {
			other := route.c
			if c == route.c.client {
				other = route.a
			}
			body, _ := json.Marshal(FileRelayReady{Err: "peer disconnected"})
			other.client.hub.broadcast <- &CMessage{client: other.client,
				message: &Message{ID: other.id, Type: ConnFileRelay, Method: METHOD_CLOSE, Body: body}}
		}
	}()
}

// ---------- 订阅方(A 与 C 共用同一套客户端侧收发)----------

// fileRelaySession 订阅方侧一次文件中继的运行时: 把 msgPipe 接到这条 websocket 连接
// 上收发。A(发送)、C(接收)各自持有一份, 用完即弃——不像直连的 QUIC 连接那样跨多个
// 文件复用, 每次 -send 都是一条新连接、一次性的多个文件顺序传, 复用的意义不大,
// 也用不着直连那套"空闲回收"的复杂度。
type fileRelaySession struct {
	client *Client
	id     uint
	pipe   *msgPipe
}

// fileRelayReplyWaiters 按 (client, id) 存放等待某条信令回执的 channel。A 等
// d_file_ready、A 与 C 都可能在等对方的 METHOD_CLOSE(用作"发送方已关闭"通知), 统一
// 走这一张表——复用同一个机制而不是各开一个专门的等待队列。
var fileRelayReplyWaiters sync.Map // fileRelayKey -> chan *Message

// handleFileRelayClient 订阅方(A 或 C)侧处理文件中继消息。
//
// 先看 Type: 只认 ConnFileRelay。这一步是必须的——这个函数在 localReadPump 里排在
// 转发分发之前, 早先不看 Type 只按 (client,ID) 查 pipe, 号一撞就把别人的转发数据
// (RDP)推进了中继的字节流(见文件头部的说明)。
func handleFileRelayClient(c *Client, msg *Message) bool {
	if msg.Type != ConnFileRelay {
		return false
	}
	if msg.Method == METHOD_FILE_RELAY_READY {
		if ch, ok := fileRelayReplyWaiters.LoadAndDelete(fileRelayKey{c, msg.ID}); ok {
			ch.(chan *Message) <- msg
		}
		return true
	}
	if msg.Method == METHOD_FILE_RELAY_OPEN {
		go onFileRelayOpen(c, msg)
		return true
	}
	// 数据消息、ACK 与 CLOSE: 只有落在某条活跃 session 的 pipe 上才认。
	if p, ok := fileRelayPipes.Load(fileRelayKey{c, msg.ID}); ok {
		pipe := p.(*msgPipe)
		if msg.Method == METHOD_CLOSE {
			var r FileRelayReady
			_ = json.Unmarshal(msg.Body, &r)
			if r.Err != "" {
				pipe.closeWithError(errors.New(r.Err))
			} else {
				pipe.Close()
			}
			fileRelayPipes.Delete(fileRelayKey{c, msg.ID})
			return true
		}
		// ACK 必须在 push 之前拦掉, 否则会被当成文件数据推进字节流里, 直接把对端的
		// 帧边界搞乱。
		if msg.Method == METHOD_FILE_RELAY_ACK {
			pipe.onAck(int64(binary.BigEndian.Uint64(padAck(msg.Body))))
			return true
		}
		pipe.push(msg.Body)
		return true
	}
	return false
}

// padAck 容错: 确认值固定 8 字节大端, 但收到短包时不能让 binary 读越界 panic。
func padAck(b []byte) []byte {
	if len(b) >= 8 {
		return b[:8]
	}
	var out [8]byte
	copy(out[8-len(b):], b)
	return out[:]
}

// fileRelayPipes 活跃 session 的 (client,id) -> *msgPipe, 供 handleFileRelayClient
// 把收到的数据/关闭消息路由给正确的那一份传输。
var fileRelayPipes sync.Map

// newFileRelaySession 建一个新的中继 session: 分配本地 ID, 建好 msgPipe(写出去的
// 数据自动打包成 Message, ID/Type 固定), 登记进 fileRelayPipes 以便收数据。
func newFileRelaySession(client *Client, id uint) *fileRelaySession {
	s := &fileRelaySession{client: client, id: id}
	send := func(b []byte) error {
		body := append([]byte(nil), b...) // Write 之后调用方可能复用/修改 b, 必须复制
		// 要投递回执: hub 队列满时这条消息会被丢掉(见 CMessage.done), 而字节流少一段
		// 就是对端帧错位, 必须当场变成错误往上报, 不能装作发成功了。
		done := make(chan error, 1)
		client.hub.broadcast <- &CMessage{client: client,
			message: &Message{ID: id, Type: ConnFileRelay, Body: body}, done: done}
		return <-done
	}
	sendAck := func(n int64) error {
		var body [8]byte
		binary.BigEndian.PutUint64(body[:], uint64(n))
		client.hub.broadcast <- &CMessage{client: client,
			message: &Message{ID: id, Type: ConnFileRelay, Method: METHOD_FILE_RELAY_ACK, Body: body[:]}}
		return nil
	}
	s.pipe = newMsgPipe(send, sendAck)
	s.pipe.tag = client.tag
	fileRelayPipes.Store(fileRelayKey{client, id}, s.pipe)
	return s
}

// close 结束这次中继 session: 通知对端(带错误原因则说明是异常结束), 收掉本地登记。
func (s *fileRelaySession) close(errReason string) {
	fileRelayPipes.Delete(fileRelayKey{s.client, s.id})
	s.pipe.Close()
	body, _ := json.Marshal(FileRelayReady{Err: errReason})
	s.client.hub.broadcast <- &CMessage{client: s.client, message: &Message{ID: s.id, Type: ConnFileRelay, Method: METHOD_CLOSE, Body: body}}
}

// onFileRelayOpen C 侧收到中继请求: 按 email 查 receive.allow 里对应的 uuid, 派生
// 会话密钥把 msgPipe 包一层 AEAD(见 nat/relay_crypto.go), 再按 Op 分派到收文件
// (recvFileOver)或被取文件(servePull)——数据从这里开始就是解密后的明文, 谁能解得开
// 本身就是身份证明, 两条分支都不需要再单独核对身份。不要求开了 directAccept——中继
// 路径不依赖 QUIC 直连那一套, c.receive 在建这条 websocket 连接时就已经从配置里填好
// (见 handler.go)。
func onFileRelayOpen(c *Client, msg *Message) {
	var req FileRelayOpen
	if err := json.Unmarshal(msg.Body, &req); err != nil {
		return
	}
	cfg := c.receive
	logf := func(format string, args ...interface{}) {
		log.Printf("[%s] nat file relay: %s", c.tag, fmt.Sprintf(format, args...))
	}
	reply := func(errStr string) {
		body, _ := json.Marshal(FileRelayReady{Err: errStr})
		c.hub.broadcast <- &CMessage{client: c, message: &Message{ID: msg.ID, Type: ConnFileRelay, Method: METHOD_FILE_RELAY_READY, Body: body}}
	}
	if cfg.Dir == "" {
		// 同一个目录既是收文件的落地处, 也是可被取走的根, 所以两个方向共用这句判断。
		reply("peer does not accept files (websocket.client.receive.dir is not set)")
		return
	}
	// 只读只挡写入方向, 取件照常。放在解密之前: 拒绝的理由与身份无关, 没必要先把
	// 会话建起来再说。
	if cfg.ReadOnly && req.Op != fileRelayOpPull {
		reply(readOnlyRefusal)
		return
	}
	uuid, ok := cfg.Lookup(req.FromEmail)
	if !ok {
		reply(fmt.Sprintf("email %s is not in websocket.client.receive.allow", req.FromEmail))
		return
	}
	// 派生加密密钥前先校验格式: 配置里这条 uuid 要是本来就不合法(手改坏了), 拿它
	// 派生出的 key 毫无意义, 应该直接拒绝, 而不是让对端在解密阶段莫名其妙地失败。
	if !conf.IsValidUUID(uuid) {
		reply(fmt.Sprintf("configured uuid for %s is not a valid uuid", req.FromEmail))
		return
	}
	// senderKey/receiverKey 顺序要跟 sendFileViaRelay 那边反过来: 我是接收方, 写用
	// receiverKey、读用 senderKey。
	senderKey, receiverKey, err := deriveRelaySessionKeys(uuid, req.Salt)
	if err != nil {
		reply(fmt.Sprintf("bad salt: %v", err))
		return
	}
	reply("")

	s := newFileRelaySession(c, msg.ID)
	secured, err := newAEADConn(s.pipe, receiverKey, senderKey)
	if err != nil {
		logf("relay from %s: cannot set up decryption: %v", req.FromEmail, err)
		s.close(fmt.Sprintf("server-side decryption setup failed: %v", err))
		return
	}
	remote := fmt.Sprintf("relay:%s", req.FromEmail)
	if req.Op == fileRelayOpPull {
		servePull(secured, cfg, req.FromEmail, remote, logf)
	} else {
		recvFileOver(secured, cfg.Dir, req.FromEmail, remote, logf, nil)
	}
	fileRelayPipes.Delete(fileRelayKey{c, msg.ID})
}

// openRelayConn 建一次中继会话并返回加好密的通道: 走一遍 open/ready 信令, 派生会话
// 密钥, 把 msgPipe 包一层 AEAD。发文件与取文件共用, 只有 op 不同。
//
// client.uuid 是这次会话加密用的共享密钥来源, 必须配置(见 conf.WsClient.UUID)。
func openRelayConn(client *Client, toEmail, op string) (fileConn, *fileRelaySession, error) {
	if !conf.IsValidUUID(client.uuid) {
		return nil, nil, errors.New("websocket.client.uuid is empty or not a valid uuid, cannot start an encrypted relay session")
	}
	salt, err := newRelaySalt()
	if err != nil {
		return nil, nil, fmt.Errorf("generate session salt: %w", err)
	}

	reqID := client.nextRelayID()
	waitCh := make(chan *Message, 1)
	fileRelayReplyWaiters.Store(fileRelayKey{client, reqID}, waitCh)
	defer fileRelayReplyWaiters.Delete(fileRelayKey{client, reqID})

	body, err := json.Marshal(FileRelayOpen{Email: toEmail, Salt: salt, Op: op})
	if err != nil {
		return nil, nil, err
	}
	client.hub.broadcast <- &CMessage{client: client, message: &Message{ID: reqID, Type: ConnFileRelay, Method: METHOD_FILE_RELAY_OPEN, Body: body}}

	var ready FileRelayReady
	select {
	case msg := <-waitCh:
		if err := json.Unmarshal(msg.Body, &ready); err != nil {
			return nil, nil, fmt.Errorf("bad ready from server: %w", err)
		}
	case <-time.After(fileRelayPendingTTL + 5*time.Second):
		return nil, nil, fmt.Errorf("timed out waiting for %s to accept the relay request", toEmail)
	}
	if ready.Err != "" {
		return nil, nil, errors.New(ready.Err)
	}

	// 我是发起方: 写用 senderKey、读用 receiverKey, 跟 onFileRelayOpen 那边反过来。
	// 两把 key 是按**发起方/响应方**分的, 与字节流向无关, 所以取件不需要换方向。
	senderKey, receiverKey, err := deriveRelaySessionKeys(client.uuid, salt)
	if err != nil {
		return nil, nil, fmt.Errorf("derive session key: %w", err)
	}
	s := newFileRelaySession(client, reqID)
	secured, err := newAEADConn(s.pipe, senderKey, receiverKey)
	if err != nil {
		s.close(fmt.Sprintf("encryption setup failed: %v", err))
		return nil, nil, fmt.Errorf("set up encryption: %w", err)
	}
	return secured, s, nil
}

// sendFileViaRelay 经服务端中继(不打洞、不需要 directAccept)把一个文件发给 toEmail。
func sendFileViaRelay(client *Client, toEmail string, it fileItem, onProgress func(int64)) (string, error) {
	secured, sess, err := openRelayConn(client, toEmail, "")
	if err != nil {
		return "", err
	}
	// 进度条挂在对端真实确认(ACK)上, 不挂在本地读盘上——中继路径有 4MB 的发送
	// 窗口(见 msgPipe.waitWindow), 读盘触发的进度会在窗口打满前冲得飞快、之后又
	// 卡住, 跟数据有没有真送达完全脱钩。sendFileOver 这里就不再传 onProgress 了。
	if onProgress != nil {
		sess.pipe.setOnAcked(onProgress)
	}
	// sendFileOver 用完即关(defer conn.Close()), 这里不必再收尾。
	return sendFileOver(secured, it, nil)
}

// sendFileChunkViaRelay 是 sendFileViaRelay 的分块版, 供单文件并行分块传输用(见
// file_send.go 的 parallel 参数)。每一块各自调一次 openRelayConn——协议本身早就
// 支持"随时开一条新的加密会话"(每次都是独立的 salt/密钥), 不需要为分块单独改握手。
func sendFileChunkViaRelay(client *Client, toEmail string, it fileItem, offset, length int64, tid string, chunkIdx, chunkCount int, onProgress func(int64)) (string, error) {
	secured, sess, err := openRelayConn(client, toEmail, "")
	if err != nil {
		return "", err
	}
	// 原因同 sendFileViaRelay: 进度改成挂在 ACK 上。
	if onProgress != nil {
		sess.pipe.setOnAcked(onProgress)
	}
	return sendFileOverRange(secured, it, offset, length, tid, chunkIdx, chunkCount, nil)
}
