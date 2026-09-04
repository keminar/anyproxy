package nat

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/keminar/anyproxy/utils/conf"
	quic "github.com/quic-go/quic-go"
)

const (
	// directOfferWait 等服务端回 offer 的上限。信令走已建立的 websocket, 正常是毫秒级。
	directOfferWait = 10 * time.Second
	// directDialWait QUIC 拨号上限。要盖住"C 收到 punch -> 打洞包出去 -> 防火墙开洞"这段,
	// 但不能太长: 直连失败时按约定直接失败, 拖着只会让入口连接干等。
	directDialWait = 8 * time.Second
	// directPunchCount / directPunchGap C 收到 punch 后朝对端连发几个包, 覆盖单包丢失。
	directPunchCount = 5
	directPunchGap   = 150 * time.Millisecond
	// directTokenTTL 一次性凭证的有效期, 覆盖 punch 到 A 真正拨号之间的间隔。
	directTokenTTL = 30 * time.Second
	// directStreamHeadMax 流首部最大长度, 防止对端用超长首部撑爆内存。
	directStreamHeadMax = 4 * 1024
	// directALPN QUIC 的应用层协议标识, 两侧必须一致。
	directALPN = "anyproxy-direct"
)

// directPeer 一条 websocket 连接对应的直连运行时。挂在 wsClientConn 上(不是 Client),
// 因为 TCP 入口监听与 QUIC 监听只能起一次, 不能随 websocket 重连反复创建; 而 Client
// 每次重连都会新建。发信令时通过 curClient 取当前那个 Client。
type directPeer struct {
	tag     string
	cfg     conf.WsClient
	forward map[uint16]string // C 侧: 端口->内网目标, 与 websocket 转发路径共用同一张白名单

	curClient atomic.Value // *Client, 当前活跃的 websocket 连接; 断线期间可能为陈旧值

	// 收发两侧共用同一个 UDP socket, 由一个 quic.Transport 统一持有。
	//
	// 必须共用: 打洞包要和 QUIC 报文走同一个源端口, 对端防火墙上开出来的状态才对得上
	// (状态按 本地ip:port <-> 对端ip:port 记, 换个 socket 就是另一条状态)。
	// 必须经 Transport: quic-go 明确规定一个 PacketConn 只能交给一个 Transport, 交出去
	// 之后不能再自己 ReadFrom/WriteTo —— 所以打洞包走 Transport.WriteTo, 收到的非 QUIC
	// 包用 ReadNonQUICPacket 排掉。
	transportMu sync.Mutex
	udpConn     *net.UDPConn
	transport   *quic.Transport

	// 反射器探测状态: drainNonQUIC 收到反射器回包时投递给等待中的 probeEndpoint。
	// observed 为最近一次探测到的本机端点(反射器视角), 通告与请求都用它。
	probeMu   sync.Mutex
	probeWait chan string
	probeFrom string
	observed  string

	// C 侧(directAccept)
	listener    *quic.Listener
	fingerprint string
	tokens      *directTokenStore

	// A 侧(direct[] 入口)
	mu       sync.Mutex
	offers   map[uint]chan DirectOffer // 按请求ID等待服务端回 offer
	sessions map[string]*directSession // email -> 复用的 QUIC 连接
	reqInc   uint32                    // 请求ID采番, 与数据面的 ID 空间无关(仅用于匹配 offer)
}

// ensureTransport 建好(或复用)本地 udp6 socket 与其 Transport。A 侧拨号、C 侧监听、
// 两侧打洞全都经它, 保证共用同一个源端口。
func (d *directPeer) ensureTransport() (*quic.Transport, error) {
	d.transportMu.Lock()
	defer d.transportMu.Unlock()
	if d.transport != nil {
		return d.transport, nil
	}
	// 显式 udp6: 直连的前提就是双方都有可用 IPv6, 绑双栈只会把"其实没有 IPv6"这件事
	// 推迟到拨号阶段才暴露。
	conn, err := net.ListenUDP("udp6", &net.UDPAddr{})
	if err != nil {
		return nil, fmt.Errorf("listen udp6: %w", err)
	}
	tr := &quic.Transport{Conn: conn}
	d.udpConn = conn
	d.transport = tr
	d.logf("local udp6 socket %s", conn.LocalAddr())
	// 反射器回包与对端打洞包在 quic-go 看来都是无法解析的 QUIC 报文, 会交给
	// ReadNonQUICPacket。不读就会一直堆在内部队列里。
	go d.drainNonQUIC(tr)
	return tr, nil
}

// setObservedEndpoint 记下反射器观测到的本机端点。
func (d *directPeer) setObservedEndpoint(endpoint string) {
	d.probeMu.Lock()
	d.observed = endpoint
	d.probeMu.Unlock()
}

// observedEndpoint 取上次探测到的本机端点; 没探测过时返回空。
func (d *directPeer) observedEndpoint() string {
	d.probeMu.Lock()
	defer d.probeMu.Unlock()
	return d.observed
}

// localUDPPort 返回本地 QUIC socket 的端口。仅用于日志: 对端要用的地址必须来自反射器
// 观测(见 direct_reflect.go), 本机自报的地址不可靠。
func (d *directPeer) localUDPPort() uint16 {
	d.transportMu.Lock()
	defer d.transportMu.Unlock()
	if d.udpConn == nil {
		return 0
	}
	return uint16(d.udpConn.LocalAddr().(*net.UDPAddr).Port)
}

// directSession A 侧到某个 email 的 QUIC 连接。多条入口 TCP 连接复用同一条 QUIC 连接,
// 各自开独立的 stream —— QUIC 的 stream 之间互不阻塞, 不会像单条 TCP 复用那样队头阻塞。
type directSession struct {
	conn *quic.Conn
	addr string
}

func newDirectPeer(tag string, cfg conf.WsClient, forward map[uint16]string) *directPeer {
	return &directPeer{
		tag:      tag,
		cfg:      cfg,
		forward:  forward,
		tokens:   newDirectTokenStore(),
		offers:   make(map[uint]chan DirectOffer),
		sessions: make(map[string]*directSession),
	}
}

func (d *directPeer) logf(format string, args ...interface{}) {
	log.Printf("[%s] nat direct: %s", d.tag, fmt.Sprintf(format, args...))
}

// setClient 每次 websocket 认证成功后更新当前连接, 供入口监听与 QUIC 监听发信令使用。
func (d *directPeer) setClient(c *Client) {
	d.curClient.Store(c)
}

// client 取当前 websocket 连接; 断线期间返回的可能是已失效的连接, 发送会失败, 由调用方处理。
func (d *directPeer) client() *Client {
	c, _ := d.curClient.Load().(*Client)
	return c
}

// send 经 websocket 发一条直连信令。
func (d *directPeer) send(method string, id uint, payload interface{}) error {
	c := d.client()
	if c == nil {
		return errors.New("websocket not connected")
	}
	body, err := encodeDirect(payload)
	if err != nil {
		return err
	}
	// 与数据面共用 hub.broadcast: 它是无缓冲通道且不会被关闭, 直接写 client.send 会与
	// close 竞争(见 Hub.run 注释)。
	c.hub.broadcast <- &CMessage{client: c, message: &Message{ID: id, Type: ConnTCP, Method: method, Body: body}}
	return nil
}

// handleDirectClient 订阅方侧处理服务端下发的直连信令。返回 true 表示消息已消费。
func handleDirectClient(c *Client, msg *Message) bool {
	if !isDirectMethod(msg.Method) {
		return false
	}
	d := c.directPeerOf()
	if d == nil {
		log.Printf("nat direct: got %s but direct is not enabled on this connection", msg.Method)
		return true
	}
	switch msg.Method {
	case METHOD_DIRECT_PUNCH:
		d.onPunch(msg)
	case METHOD_DIRECT_OFFER:
		d.onOffer(msg)
	default:
		d.logf("unexpected %s from server", msg.Method)
	}
	return true
}

// directTokenStore C 侧待验证的一次性凭证。A 出示的 token 必须由服务端经 punch 提前
// 交给过 C, 且未过期、未用过 —— 这样 QUIC 端口即使被扫到, 也无法被任意来源利用。
type directTokenStore struct {
	mu     sync.Mutex
	tokens map[string]directTokenEntry
}

type directTokenEntry struct {
	port    uint16
	expires time.Time
}

func newDirectTokenStore() *directTokenStore {
	return &directTokenStore{tokens: make(map[string]directTokenEntry)}
}

func (s *directTokenStore) put(token string, port uint16) {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	// 顺带清掉过期项: 凭证只在 punch 到拨号这段短时间内有用, 不清会随连接数无限增长。
	for t, e := range s.tokens {
		if now.After(e.expires) {
			delete(s.tokens, t)
		}
	}
	s.tokens[token] = directTokenEntry{port: port, expires: now.Add(directTokenTTL)}
}

// take 校验并消费一个凭证, 一次性: 取走即删, 重放无效。
func (s *directTokenStore) take(token string) (uint16, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.tokens[token]
	if !ok {
		return 0, false
	}
	delete(s.tokens, token)
	if time.Now().After(e.expires) {
		return 0, false
	}
	return e.port, true
}

// directStreamHead A 打开 QUIC stream 后写的首部: 出示凭证并说明要用对方哪条转发规则。
type directStreamHead struct {
	Token string `json:"token"`
	Port  uint16 `json:"port"`
}

func writeStreamHead(w io.Writer, h directStreamHead) error {
	body, err := json.Marshal(h)
	if err != nil {
		return err
	}
	if len(body) > directStreamHeadMax {
		return errors.New("stream head too large")
	}
	var size [2]byte
	binary.BigEndian.PutUint16(size[:], uint16(len(body)))
	if _, err := w.Write(size[:]); err != nil {
		return err
	}
	_, err = w.Write(body)
	return err
}

func readStreamHead(r io.Reader) (directStreamHead, error) {
	var h directStreamHead
	var size [2]byte
	if _, err := io.ReadFull(r, size[:]); err != nil {
		return h, err
	}
	n := binary.BigEndian.Uint16(size[:])
	if int(n) > directStreamHeadMax {
		return h, fmt.Errorf("stream head too large: %d", n)
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return h, err
	}
	err := json.Unmarshal(body, &h)
	return h, err
}

// directCopy 在 QUIC stream 与普通连接之间双向搬字节, 返回两个方向的字节数。
func directCopy(a io.ReadWriteCloser, b io.ReadWriteCloser) (aToB, bToA int64) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		aToB, _ = io.Copy(b, a)
		// 关掉写方向即可, 让对端读到 EOF 后把自己那半也收干净; 直接 Close 会把还没
		// 读完的另一方向一起砍掉。QUIC stream 与 TCP 都支持半关。
		closeWrite(b)
	}()
	go func() {
		defer wg.Done()
		bToA, _ = io.Copy(a, b)
		closeWrite(a)
	}()
	wg.Wait()
	return
}

// closeWrite 尽量只关写方向; 类型不支持半关时退回整体关闭。
func closeWrite(c io.Closer) {
	type writeCloser interface{ CloseWrite() error }
	if wc, ok := c.(writeCloser); ok {
		_ = wc.CloseWrite()
		return
	}
	_ = c.Close()
}
