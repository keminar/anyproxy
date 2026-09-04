package nat

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/keminar/anyproxy/utils/conf"
	"github.com/keminar/anyproxy/utils/trace"
	quic "github.com/quic-go/quic-go"
)

// A 侧: 在本机起裸TCP入口监听, 每条进来的连接向服务端要一次对端端点, 然后用 IPv6 QUIC
// 直接连过去。数据全程不经服务端。
//
// 与服务端上的 forward 入口(nat/forward.go)相比, 这里少了 bridge 那一整套, 因为字节
// 是直连的, 不需要在 websocket 消息里搬运。

// startEntries 起所有 client.direct 入口监听。只在进程启动时调一次: 监听不能随
// websocket 重连反复创建。
func (d *directPeer) startEntries(rules []conf.ClientDirect) {
	for _, r := range rules {
		if r.Listen == "" || r.Email == "" {
			d.logf("skip direct rule with empty listen/email: %+v", r)
			continue
		}
		go d.listenEntry(r)
	}
}

func (d *directPeer) listenEntry(r conf.ClientDirect) {
	ln, err := net.Listen("tcp", r.Listen)
	if err != nil {
		d.logf("direct entry listen %s failed: %v", r.Listen, err)
		return
	}
	d.logf("direct entry listening on %s -> email %s (port %d)", r.Listen, r.Email, r.Port)
	for {
		conn, err := ln.Accept()
		if err != nil {
			d.logf("direct entry accept %s: %v", r.Listen, err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		go d.handleEntry(conn, r)
	}
}

// handleEntry 一条入口连接: 要端点 -> 直连 -> 开流 -> 搬字节。
// 按约定这里不做中继回落, 直连不成就关掉这条连接并把原因写进日志。
func (d *directPeer) handleEntry(conn net.Conn, r conf.ClientDirect) {
	defer conn.Close()
	id := uint(forwardInc.ID())
	src := conn.RemoteAddr()
	start := time.Now()
	log.Println(trace.ID(id), fmt.Sprintf("nat direct entry accept %s -> email %s (port %d)", src, r.Email, r.Port))

	stream, err := d.openStream(r)
	if err != nil {
		log.Println(trace.ID(id), fmt.Sprintf("nat direct entry %s failed: %v", src, err))
		return
	}
	defer stream.Close()

	up, down := directCopy(conn, stream)
	log.Println(trace.ID(id), fmt.Sprintf("nat direct entry closed %s up=%d down=%d dur=%s",
		src, up, down, time.Since(start).Round(time.Second)))
}

// openStream 拿到一条可用的 QUIC stream: 复用到该 email 的连接, 没有或已失效则重新建立。
func (d *directPeer) openStream(r conf.ClientDirect) (*quic.Stream, error) {
	// 已有连接: 直接开一条新 stream。QUIC 的 stream 相互独立, 一条连接上并发多个会话
	// 不会像单条 TCP 复用那样互相队头阻塞。
	if sess := d.session(r.Email); sess != nil {
		ctx, cancel := context.WithTimeout(context.Background(), directDialWait)
		defer cancel()
		stream, err := sess.conn.OpenStreamSync(ctx)
		if err == nil {
			if err = d.handshakeStream(stream, r, ""); err == nil {
				return stream, nil
			}
			stream.Close()
		}
		// 连接可能已经被对端关掉或超时老化, 丢弃后重建一次。
		d.dropSession(r.Email, sess)
		d.logf("reusing quic session to %s failed (%v), rebuilding", r.Email, err)
	}
	return d.dialNew(r)
}

// dialNew 完整走一遍信令 + 拨号。
func (d *directPeer) dialNew(r conf.ClientDirect) (*quic.Stream, error) {
	// A 侧也需要自己的 socket: QUIC 从它拨出去, 它的端点还要报给服务端, 好让 C 朝它
	// 打洞。没开 directAccept 的机器在这里按需建一个; 开了的复用监听那一个。
	tr, err := d.ensureTransport()
	if err != nil {
		return nil, fmt.Errorf("prepare local udp socket: %w", err)
	}
	token, offer, err := d.requestPeer(r)
	if err != nil {
		return nil, err
	}
	sess, err := d.connectPeer(tr, r.Email, offer.PeerAddr, offer.Fingerprint)
	if err != nil {
		return nil, err
	}
	return d.openHeadedStream(sess, token, r.Port)
}

// requestPeer 走一趟信令: 生成一次性凭证、把本机端点报给服务端(服务端据此让对端朝我们
// 打洞)、等回对端的端点与指纹。返回的 token 就是本次要在流首部出示的那个。
func (d *directPeer) requestPeer(r conf.ClientDirect) (string, DirectOffer, error) {
	var offer DirectOffer
	token, err := newDirectToken()
	if err != nil {
		return "", offer, err
	}
	// 每次都重新探测本机端点: 隐私临时地址会轮换, 上一次的结果可能已经作废。
	endpoint, err := d.probeEndpoint()
	if err != nil {
		return "", offer, fmt.Errorf("determine my own quic endpoint: %w", err)
	}
	d.setObservedEndpoint(endpoint)

	offerCh := make(chan DirectOffer, 1)
	d.mu.Lock()
	d.reqInc++
	reqID := uint(d.reqInc)
	d.offers[reqID] = offerCh
	d.mu.Unlock()
	defer func() {
		d.mu.Lock()
		delete(d.offers, reqID)
		d.mu.Unlock()
	}()

	req := DirectRequest{Email: r.Email, Port: r.Port, Token: token, Endpoint: endpoint}
	if err := d.send(METHOD_DIRECT_REQUEST, reqID, req); err != nil {
		return "", offer, fmt.Errorf("ask server for peer endpoint: %w", err)
	}

	select {
	case offer = <-offerCh:
	case <-time.After(directOfferWait):
		return "", offer, errors.New("timed out waiting for peer endpoint from server")
	}
	if offer.Err != "" {
		return "", offer, errors.New(offer.Err)
	}
	if offer.PeerAddr == "" || offer.Fingerprint == "" {
		return "", offer, errors.New("server returned an incomplete offer")
	}
	return token, offer, nil
}

// connectPeer 按服务端给的端点与指纹建立 QUIC 连接并登记复用。信令之外的部分独立成
// 一个方法, 便于不经 websocket 直接测试数据路径。
func (d *directPeer) connectPeer(tr *quic.Transport, email, peerAddr, fingerprint string) (*directSession, error) {
	udpAddr, err := net.ResolveUDPAddr("udp6", peerAddr)
	if err != nil {
		// 对端的 websocket 若是 IPv4 接入的, 这里拿到的就是 IPv4 地址, 直连做不了。
		// 按约定直接失败, 并把原因说清楚。
		return nil, fmt.Errorf("peer endpoint %s is not a usable IPv6 address (is its websocket connected over IPv6?): %w", peerAddr, err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), directDialWait)
	defer cancel()
	conn, err := tr.Dial(ctx, udpAddr, directClientTLS(fingerprint), directQUICConfig())
	if err != nil {
		return nil, fmt.Errorf("quic dial %s: %w", peerAddr, err)
	}
	d.logf("quic connected to email %s at %s", email, peerAddr)
	sess := &directSession{conn: conn, addr: peerAddr}
	d.putSession(email, sess)
	return sess, nil
}

// openHeadedStream 在已建立的连接上开一条流并写好首部。
func (d *directPeer) openHeadedStream(sess *directSession, token string, port uint16) (*quic.Stream, error) {
	ctx, cancel := context.WithTimeout(context.Background(), directDialWait)
	defer cancel()
	stream, err := sess.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, fmt.Errorf("open quic stream: %w", err)
	}
	if err := writeStreamHead(stream, directStreamHead{Token: token, Port: port}); err != nil {
		stream.Close()
		return nil, fmt.Errorf("write stream head: %w", err)
	}
	return stream, nil
}

// handshakeStream 写流首部。复用已有连接时没有现成的凭证, 需要重新走一次信令拿到 ——
// 凭证是一次性的, 不能跨 stream 复用。
func (d *directPeer) handshakeStream(stream *quic.Stream, r conf.ClientDirect, token string) error {
	if token == "" {
		var err error
		token, err = d.refreshToken(r)
		if err != nil {
			return err
		}
	}
	return writeStreamHead(stream, directStreamHead{Token: token, Port: r.Port})
}

// refreshToken 为复用连接上的新 stream 走一次信令, 拿一个新的一次性凭证 —— 凭证是
// 一次性的, 不能跨 stream 复用。这一趟同样会让对端再打一轮洞, 顺带刷新沿途防火墙状态。
func (d *directPeer) refreshToken(r conf.ClientDirect) (string, error) {
	token, _, err := d.requestPeer(r)
	return token, err
}

// onOffer 把服务端回的 offer 交给等待中的请求。
func (d *directPeer) onOffer(msg *Message) {
	var offer DirectOffer
	if err := decodeDirect(msg.Body, &offer); err != nil {
		d.logf("bad offer: %v", err)
		return
	}
	d.mu.Lock()
	ch, ok := d.offers[msg.ID]
	d.mu.Unlock()
	if !ok {
		d.logf("offer for unknown request id %d (timed out already?)", msg.ID)
		return
	}
	select {
	case ch <- offer:
	default: // 等待方已经超时退出, 丢弃即可
	}
}

func (d *directPeer) session(email string) *directSession {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.sessions[email]
}

func (d *directPeer) putSession(email string, s *directSession) {
	d.mu.Lock()
	d.sessions[email] = s
	d.mu.Unlock()
}

// dropSession 仅在当前记录仍是这条失效连接时删除, 避免把别的 goroutine 刚建好的新连接误删。
func (d *directPeer) dropSession(email string, stale *directSession) {
	d.mu.Lock()
	if d.sessions[email] == stale {
		delete(d.sessions, email)
	}
	d.mu.Unlock()
	if stale != nil && stale.conn != nil {
		_ = stale.conn.CloseWithError(0, "rebuilding")
	}
}
