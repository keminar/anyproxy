package nat

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/keminar/anyproxy/utils/conf"
)

// 测试里代替账号密码用的占位值。
const (
	testPassA        = "TestPassForUserA01"
	testPassC        = "TestPassForUserC01"
	testPassStranger = "TestPassForStranger01"
)

// fileRelayTestServer 起一个真实的 B: 真实的 ServerHub/ServerBridge/serveWs, 跑在一个
// httptest.Server 上, 不经 NewServer(那个会阻塞在 http.ListenAndServe 上)。
func fileRelayTestServer(t *testing.T, users []conf.ServerUser) string {
	t.Helper()
	oldCfg := conf.RouterConfig()
	oldHub, oldBridge, oldStart := ServerHub, ServerBridge, serverStart
	t.Cleanup(func() {
		conf.SetRouterConfig(oldCfg)
		ServerHub, ServerBridge, serverStart = oldHub, oldBridge, oldStart
	})
	conf.SetRouterConfig(&conf.Router{})
	conf.RouterConfig().Websocket.Server.Users = users

	ServerHub = newHub()
	go ServerHub.run()
	ServerBridge = newBridgeHub()
	go ServerBridge.run()
	serverStart = true

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		serveWs(ServerHub, w, r)
	}))
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

// fileRelayTestClient 建一条真实的订阅方 websocket 连接(复用 dialSender, A/C 双方
// 都用得上——它只是"一条已鉴权、跑着 read/write pump 的连接", 跟角色是发送方还是
// 接收方无关)。uuid 是这台"机器"的身份(websocket.client.uuid, 中继加密的密钥来源),
// 发起中继传输的一方(A)必须非空, 否则 sendFileViaRelay 会直接拒绝。
func fileRelayTestClient(t *testing.T, connect, user, pass, email, uuid string, receive conf.ClientReceive) *oneShotSender {
	t.Helper()
	s, err := dialSender(conf.WsClient{Connect: connect, User: user, Pass: pass, Email: email, UUID: uuid, Receive: receive}, "test")
	if err != nil {
		t.Fatalf("dial %s: %v", email, err)
	}
	t.Cleanup(s.close)
	return s
}

// 端到端: A 经 B 中继把文件发给 C, 不打洞、不需要 C 开 directAccept。
func TestFileRelayEndToEnd(t *testing.T) {
	connect := fileRelayTestServer(t, []conf.ServerUser{
		{User: "a", Pass: testPassA},
		{User: "c", Pass: testPassC},
	})

	recvDir := t.TempDir()
	_ = fileRelayTestClient(t, connect, "c", testPassC, "c@example.com", "",
		conf.ClientReceive{Dir: recvDir, Allow: []conf.AllowedSender{{Email: "a@example.com", UUID: testUUIDA}}})
	a := fileRelayTestClient(t, connect, "a", testPassA, "a@example.com", testUUIDA, conf.ClientReceive{})

	srcDir := t.TempDir()
	body := make([]byte, 2*1024*1024+37) // 凑一个不对齐的大小, 顺带盖住多次读写循环
	if _, err := rand.Read(body); err != nil {
		t.Fatalf("rand: %v", err)
	}
	srcPath := filepath.Join(srcDir, "relay.bin")
	if err := os.WriteFile(srcPath, body, 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	items, err := collectFiles([]string{srcPath})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	var lastProgress int64
	saved, err := sendFileViaRelay(a.client, "c@example.com", items[0], func(n int64) {
		if n < lastProgress {
			t.Fatalf("progress went backwards: %d -> %d", lastProgress, n)
		}
		lastProgress = n
	})
	if err != nil {
		t.Fatalf("send via relay: %v", err)
	}
	if saved != "relay.bin" {
		t.Fatalf("peer saved it as %q", saved)
	}
	// 进度现在挂在对端 ACK 上(见 nat/file_relay.go 的 sendFileViaRelay), 不再是
	// 精确的本地读盘计数: ACK 按 relayAckEvery(1MB) 门槛触发, 文件体最后不满 1MB
	// 的尾巴通常等不到下一次确认就传完了, 所以只要求落在合理区间, 不要求精确等于
	// len(body)——下界给足容忍度(90%), 上界放宽一点余量(AEAD 分帧 + 文件头尾开销)。
	if want := int64(len(body)); lastProgress < want*9/10 || lastProgress > want+4096 {
		t.Fatalf("progress ended at %d, want roughly close to %d", lastProgress, want)
	}
	got, err := os.ReadFile(filepath.Join(recvDir, "relay.bin"))
	if err != nil {
		t.Fatalf("read received: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("received %d bytes, content differs from the %d sent", len(got), len(body))
	}
}

// TestFileRelayLargeFileCrossesWindow 传一个明显大于流控窗口的文件, 逼着走完整的
// "发满窗口 -> 等确认 -> 继续发"循环。上面那条端到端用例的文件小于一个窗口, 一次
// 确认都不会触发, 盖不住流控本身写错(比如窗口算反了导致死等)这类问题。
func TestFileRelayLargeFileCrossesWindow(t *testing.T) {
	connect := fileRelayTestServer(t, []conf.ServerUser{
		{User: "a", Pass: testPassA},
		{User: "c", Pass: testPassC},
	})

	recvDir := t.TempDir()
	_ = fileRelayTestClient(t, connect, "c", testPassC, "c@example.com", "",
		conf.ClientReceive{Dir: recvDir, Allow: []conf.AllowedSender{{Email: "a@example.com", UUID: testUUIDA}}})
	a := fileRelayTestClient(t, connect, "a", testPassA, "a@example.com", testUUIDA, conf.ClientReceive{})

	// 3 个窗口那么大, 保证中间要等好几轮确认。
	body := make([]byte, relayWindow*3)
	if _, err := rand.Read(body); err != nil {
		t.Fatalf("rand: %v", err)
	}
	srcPath := filepath.Join(t.TempDir(), "big.bin")
	if err := os.WriteFile(srcPath, body, 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	items, err := collectFiles([]string{srcPath})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		_, err := sendFileViaRelay(a.client, "c@example.com", items[0], nil)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("send via relay: %v", err)
		}
	case <-time.After(60 * time.Second):
		t.Fatal("transfer stalled: the window never reopened (missing or mismatched acks?)")
	}

	got, err := os.ReadFile(filepath.Join(recvDir, "big.bin"))
	if err != nil {
		t.Fatalf("read received: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("received %d bytes, content differs from the %d sent", len(got), len(body))
	}
}

// 单文件分块并行传输在中继路径下的端到端: 每一块各开一次 openRelayConn(各自独立的
// salt/密钥), 并行发, C 端按 TransferID 把它们拼回同一个文件。
func TestChunkedFileTransferRelay(t *testing.T) {
	connect := fileRelayTestServer(t, []conf.ServerUser{
		{User: "a", Pass: testPassA},
		{User: "c", Pass: testPassC},
	})

	recvDir := t.TempDir()
	_ = fileRelayTestClient(t, connect, "c", testPassC, "c@example.com", "",
		conf.ClientReceive{Dir: recvDir, Allow: []conf.AllowedSender{{Email: "a@example.com", UUID: testUUIDA}}})
	a := fileRelayTestClient(t, connect, "a", testPassA, "a@example.com", testUUIDA, conf.ClientReceive{})

	srcDir := t.TempDir()
	body := make([]byte, 5*chunkMinSize+777) // 不对齐 chunkMinSize, 顺带盖住"最后一块拿余数"
	if _, err := rand.Read(body); err != nil {
		t.Fatalf("rand: %v", err)
	}
	srcPath := filepath.Join(srcDir, "chunked-relay.bin")
	if err := os.WriteFile(srcPath, body, 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}
	items, err := collectFiles([]string{srcPath})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	it := items[0]
	chunks := planChunks(it.size, 3)
	if len(chunks) < 2 {
		t.Fatalf("expected the test file to split into multiple chunks, got %d", len(chunks))
	}

	p := newProgress("test", it.size)
	sendChunk := func(it fileItem, offset, length int64, tid string, chunkIdx, chunkCount int, onProgress func(int64)) (string, error) {
		return sendFileChunkViaRelay(a.client, "c@example.com", it, offset, length, tid, chunkIdx, chunkCount, onProgress)
	}
	saved, err := sendParallel(it, chunks, sendChunk, p)
	if err != nil {
		t.Fatalf("chunked send via relay: %v", err)
	}
	if saved != "chunked-relay.bin" {
		t.Fatalf("peer saved it as %q", saved)
	}

	got, err := os.ReadFile(filepath.Join(recvDir, "chunked-relay.bin"))
	if err != nil {
		t.Fatalf("read received: %v", err)
	}
	if !bytes.Equal(got, body) {
		t.Fatalf("received %d bytes, content differs from the %d sent", len(got), len(body))
	}
}

// receive.allow 在中继路径下依然有效——这是选"复用已认证 websocket"这套设计而不是
// "新开公网转发端口"的全部理由。B 完全不知道、也不需要知道 uuid 是什么(见
// nat/relay_crypto.go); 这里故意让发送方自报一个不在 allow 列表里的 email, 验证
// 确实在早期(还没开始传字节)就被挡。
func TestFileRelayReceiveAllowList(t *testing.T) {
	connect := fileRelayTestServer(t, []conf.ServerUser{
		{User: "a", Pass: testPassA},
		{User: "stranger", Pass: testPassStranger},
	})

	recvDir := t.TempDir()
	_ = fileRelayTestClient(t, connect, "a", testPassA, "trusted@example.com", "",
		conf.ClientReceive{Dir: recvDir, Allow: []conf.AllowedSender{{Email: "trusted@example.com", UUID: testUUIDTrusted}}})
	stranger := fileRelayTestClient(t, connect, "stranger", testPassStranger, "stranger@example.com", testUUIDStranger, conf.ClientReceive{})

	src := filepath.Join(t.TempDir(), "x.txt")
	os.WriteFile(src, []byte("hi"), 0o644)
	items, _ := collectFiles([]string{src})

	_, err := sendFileViaRelay(stranger.client, "trusted@example.com", items[0], nil)
	if err == nil {
		t.Fatal("an email outside receive.allow must be refused")
	}
	if !strings.Contains(err.Error(), "receive.allow") {
		t.Fatalf("error should mention receive.allow, got %v", err)
	}
	if entries, _ := os.ReadDir(recvDir); len(entries) != 0 {
		t.Fatalf("nothing should have been written, found %d entries", len(entries))
	}
}

// 光把 email 报对还不够——这正是修复"任何合法账号都能自称任意 email"这个漏洞的
// 核心: uuid 对不上, 就算 email 命中了 allow 列表里的那一条也必须拒绝, 而且是在
// 解密阶段自然失败, 不依赖任何额外的比对逻辑。
func TestFileRelayReceiveRequiresMatchingUUID(t *testing.T) {
	connect := fileRelayTestServer(t, []conf.ServerUser{
		{User: "a", Pass: testPassA},
		{User: "c", Pass: testPassC},
	})

	recvDir := t.TempDir()
	_ = fileRelayTestClient(t, connect, "c", testPassC, "c@example.com", "",
		conf.ClientReceive{Dir: recvDir, Allow: []conf.AllowedSender{{Email: "a@example.com", UUID: testUUIDReal}}})
	// email 与 receive.allow 里的一致, 但 uuid 是瞎编的。
	a := fileRelayTestClient(t, connect, "a", testPassA, "a@example.com", testUUIDForged, conf.ClientReceive{})

	src := filepath.Join(t.TempDir(), "x.txt")
	os.WriteFile(src, []byte("hi"), 0o644)
	items, _ := collectFiles([]string{src})

	_, err := sendFileViaRelay(a.client, "c@example.com", items[0], nil)
	if err == nil {
		t.Fatal("a forged uuid must be refused even though the email matches")
	}
	if entries, _ := os.ReadDir(recvDir); len(entries) != 0 {
		t.Fatalf("nothing should have been written, found %d entries", len(entries))
	}
}

// 没配 receive.dir 的对端必须明确回绝——发送端要能从错误信息看出没传成, 而不是
// 干等到超时才失败。
func TestFileRelayRefusedWhenNoReceiveDir(t *testing.T) {
	connect := fileRelayTestServer(t, []conf.ServerUser{
		{User: "a", Pass: testPassA},
		{User: "c", Pass: testPassC},
	})
	_ = fileRelayTestClient(t, connect, "c", testPassC, "c@example.com", "", conf.ClientReceive{}) // 不设 Dir
	a := fileRelayTestClient(t, connect, "a", testPassA, "a@example.com", testUUIDA, conf.ClientReceive{})

	src := filepath.Join(t.TempDir(), "x.txt")
	os.WriteFile(src, []byte("hi"), 0o644)
	items, _ := collectFiles([]string{src})

	_, err := sendFileViaRelay(a.client, "c@example.com", items[0], nil)
	if err == nil {
		t.Fatal("a peer without receive.dir must refuse")
	}
	if !strings.Contains(err.Error(), "receive.dir") {
		t.Fatalf("error should say what to configure, got %v", err)
	}
}

// 目标 email 不在线时要当场报错, 不能让发送方一路等到超时。
func TestFileRelayNoSubscriberOnline(t *testing.T) {
	connect := fileRelayTestServer(t, []conf.ServerUser{{User: "a", Pass: testPassA}})
	a := fileRelayTestClient(t, connect, "a", testPassA, "a@example.com", testUUIDA, conf.ClientReceive{})

	src := filepath.Join(t.TempDir(), "x.txt")
	os.WriteFile(src, []byte("hi"), 0o644)
	items, _ := collectFiles([]string{src})

	start := time.Now()
	_, err := sendFileViaRelay(a.client, "nobody@example.com", items[0], nil)
	if err == nil {
		t.Fatal("sending to an offline email should fail")
	}
	if !strings.Contains(err.Error(), "no subscriber online") {
		t.Fatalf("error should say no subscriber online, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("should fail immediately, took %s", elapsed)
	}
}

// 不能把文件"中继"给自己——那不是这个功能的用途, 而且会在 A 自己的连接上同时扮演
// 发起方与接收方两个角色, 容易出些莫名其妙的状态问题, 不如直接拒绝。
func TestFileRelayRejectsSelf(t *testing.T) {
	connect := fileRelayTestServer(t, []conf.ServerUser{{User: "a", Pass: testPassA}})
	a := fileRelayTestClient(t, connect, "a", testPassA, "a@example.com", testUUIDA, conf.ClientReceive{Dir: t.TempDir()})

	src := filepath.Join(t.TempDir(), "x.txt")
	os.WriteFile(src, []byte("hi"), 0o644)
	items, _ := collectFiles([]string{src})

	_, err := sendFileViaRelay(a.client, "a@example.com", items[0], nil)
	if err == nil {
		t.Fatal("sending to yourself should be rejected")
	}
}

// TestFileRelaySendRefusesInvalidOwnUUID client.uuid 为空或者不是合法 uuid 格式(比如
// 状态文件被手改坏了)时, sendFileViaRelay 必须本地直接拒绝, 不该真去发一次
// relay-open 请求。
func TestFileRelaySendRefusesInvalidOwnUUID(t *testing.T) {
	connect := fileRelayTestServer(t, []conf.ServerUser{
		{User: "a", Pass: testPassA},
		{User: "c", Pass: testPassC},
	})

	recvDir := t.TempDir()
	_ = fileRelayTestClient(t, connect, "c", testPassC, "c@example.com", "",
		conf.ClientReceive{Dir: recvDir, Allow: []conf.AllowedSender{{Email: "a@example.com", UUID: testUUIDA}}})
	// 故意留空, 模拟 uuid 生成/持久化失败后的状态。
	a := fileRelayTestClient(t, connect, "a", testPassA, "a@example.com", "", conf.ClientReceive{})

	src := filepath.Join(t.TempDir(), "x.txt")
	os.WriteFile(src, []byte("hi"), 0o644)
	items, _ := collectFiles([]string{src})

	_, err := sendFileViaRelay(a.client, "c@example.com", items[0], nil)
	if err == nil {
		t.Fatal("an empty websocket.client.uuid must refuse to start a relay session")
	}
	if entries, _ := os.ReadDir(recvDir); len(entries) != 0 {
		t.Fatalf("nothing should have been written, found %d entries", len(entries))
	}
}

// TestFileRelayReceiveRefusesMalformedConfiguredUUID 哪怕发起方自报的 uuid 跟
// receive.allow 里配的一字不差, 只要它本身不是合法 uuid 格式, C 侧也必须拒绝——不能
// 让一次"巧合的字符串相等"通过身份校验、进而派生出一把看似正常实则毫无意义的密钥。
// 这里直接调用 onFileRelayOpen, 绕开 sendFileViaRelay 自己的格式校验, 专门盯住 C 侧。
func TestFileRelayReceiveRefusesMalformedConfiguredUUID(t *testing.T) {
	hub := newHub()
	go hub.run()

	c := &Client{
		hub:  hub,
		send: make(chan *Message, 4),
		receive: conf.ClientReceive{
			Dir:   t.TempDir(),
			Allow: []conf.AllowedSender{{Email: "a@example.com", UUID: "not-a-real-uuid"}},
		},
	}
	hub.register <- c

	body, err := json.Marshal(FileRelayOpen{FromEmail: "a@example.com", Salt: "test-salt"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	onFileRelayOpen(c, &Message{ID: 1, Type: ConnFileRelay, Method: METHOD_FILE_RELAY_OPEN, Body: body})

	select {
	case msg := <-c.send:
		var ready FileRelayReady
		if err := json.Unmarshal(msg.Body, &ready); err != nil {
			t.Fatalf("bad ready: %v", err)
		}
		if ready.Err == "" {
			t.Fatal("a matching-but-malformed configured uuid must still be refused")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no reply received from onFileRelayOpen")
	}
}

// TestFileRelayForwardMarksRouteReadyRegardlessOfDirection 回归用例: route.ready 曾经
// 被错放在"消息来自 A"这个分支里, 而实际发 ready 的是 C, 导致这个标志永远置不真——
// sweepLocked 会把任何存活超过 15s 的路由都当"没等到 ready"直接拆掉, 哪怕它已经在
// 正常传一个大文件。这里直接摆弄 broker 内部状态, 不需要真的发文件, 断言两件事:
// C 回 ready 之后 route.ready 必须变真; sweepLocked 不能拆掉一条已经 ready 的路由,
// 即使它的 deadline 早就过了。
func TestFileRelayForwardMarksRouteReadyRegardlessOfDirection(t *testing.T) {
	aHub := newHub()
	go aHub.run()
	cHub := newHub()
	go cHub.run()

	a := &Client{hub: aHub, send: make(chan *Message, 4), Email: "a@example.com"}
	c := &Client{hub: cHub, send: make(chan *Message, 4), Email: "c@example.com"}

	route := &fileRelayRoute{
		a:        fileRelaySide{client: a, id: 1},
		c:        fileRelaySide{client: c, id: 2},
		deadline: time.Now().Add(-time.Hour), // 早已过期, 专门用来确认只有 ready 才是关键
	}
	fileRelay.mu.Lock()
	fileRelay.routes[fileRelayKey{a, 1}] = route
	fileRelay.routes[fileRelayKey{c, 2}] = route
	fileRelay.mu.Unlock()
	defer fileRelay.drop(route)

	// C(route.c.client) 回 ready——真实场景里唯一会发生的方向。
	fileRelay.forward(c, &Message{ID: 2, Type: ConnFileRelay, Method: METHOD_FILE_RELAY_READY})

	fileRelay.mu.Lock()
	ready := route.ready
	fileRelay.mu.Unlock()
	if !ready {
		t.Fatal("a ready reply from C must mark the route ready, regardless of which side sent it")
	}

	fileRelay.mu.Lock()
	fileRelay.sweepLocked(time.Now())
	_, stillThere := fileRelay.routes[fileRelayKey{a, 1}]
	fileRelay.mu.Unlock()
	if !stillThere {
		t.Fatal("sweepLocked must not tear down a route that already received its ready reply")
	}
}

// TestClientGoneDoesNotDeadlockHub 回归用例: clientGone 是在 Hub.run() 的 unregister
// 分支里同步调用的, 一旦它自己往 hub.broadcast(无缓冲, 唯一读者就是 Hub.run())发消息,
// 就是自己等自己, 整个 hub 会永久卡死——现象是"中继成功传完一次、发送方进程退出断线
// 之后, 服务端就再也接不了任何新连接、也转发不了任何消息了", 而且因为只在断线的
// client 身上真的挂着中继路由时才触发, 看起来就是"第一次能用, 之后全废"。
func TestClientGoneDoesNotDeadlockHub(t *testing.T) {
	hub := newHub()
	go hub.run()

	a := &Client{hub: hub, send: make(chan *Message, 4), Email: "a@example.com"}
	c := &Client{hub: hub, send: make(chan *Message, 4), Email: "c@example.com"}
	hub.register <- a
	hub.register <- c

	route := &fileRelayRoute{
		a:        fileRelaySide{client: a, id: 1},
		c:        fileRelaySide{client: c, id: 2},
		deadline: time.Now().Add(time.Minute),
	}
	fileRelay.mu.Lock()
	fileRelay.routes[fileRelayKey{a, 1}] = route
	fileRelay.routes[fileRelayKey{c, 2}] = route
	fileRelay.mu.Unlock()
	defer fileRelay.drop(route)

	// A 断线: Hub.run() 会在 unregister 分支里调用 clientGone, 后者要通知另一端 C。
	hub.unregister <- a

	// hub 必须还活着: 再来一个注册请求应该立刻被处理, 而不是永远排不上队。
	done := make(chan struct{})
	go func() {
		hub.register <- &Client{hub: hub, send: make(chan *Message, 1)}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("hub is deadlocked: clientGone must not send to hub.broadcast from inside the hub goroutine")
	}
}

// TestFileRelayDoesNotStealSameIDForwardMessages 回归用例: 文件中继早先复用了
// ConnTCP, 而它的 ID 采番(fileRelay.nextID)与裸TCP转发的采番(forwardInc)互相独立、
// 都从 1 起步, 必然撞号; 订阅方那侧中继又排在转发分发之前, 于是撞上的转发数据
// (实测是 RDP over TLS)被中继抢走推进了加密字节流——文件这头帧边界错位, 报出
// 0x17030300 这种"帧长度"(其实就是 TLS 记录头 17 03 03), RDP 那头数据被偷走断线。
func TestFileRelayDoesNotStealSameIDForwardMessages(t *testing.T) {
	hub := newHub()
	go hub.run()
	c := &Client{hub: hub, send: make(chan *Message, 8), Email: "c@example.com"}
	hub.register <- c

	const id = uint(7)
	s := newFileRelaySession(c, id)
	defer fileRelayPipes.Delete(fileRelayKey{c, id})

	// 同号、但属于裸TCP转发的消息: 必须原样交还给调用方, 由转发那套逻辑处理。
	// 这里特意用 RDP over TLS 的记录头当负载, 就是当初被偷走的那种字节。
	tcpMsg := &Message{ID: id, Type: ConnTCP, Body: []byte{0x17, 0x03, 0x03, 0x00}}
	if handleFileRelayClient(c, tcpMsg) {
		t.Fatal("a ConnTCP message must not be swallowed by the file relay, even with a colliding ID")
	}
	if handleFileRelayServer(c, tcpMsg) {
		t.Fatal("server side must not swallow a ConnTCP message either")
	}

	// 同号且确实属于中继的消息才该被消费掉, 并且原样进到 pipe 里。
	relayMsg := &Message{ID: id, Type: ConnFileRelay, Body: []byte("payload")}
	if !handleFileRelayClient(c, relayMsg) {
		t.Fatal("a ConnFileRelay data message should be consumed by the relay")
	}
	buf := make([]byte, 16)
	n, err := s.pipe.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf[:n]) != "payload" {
		t.Fatalf("pipe got %q, want the relay payload only", buf[:n])
	}
}

// SendFiles 的 via 参数必须显式声明合法值, 传别的既不报错也不生效是最坏的情况。
func TestSendFilesRejectsUnknownVia(t *testing.T) {
	src := filepath.Join(t.TempDir(), "x.txt")
	os.WriteFile(src, []byte("hi"), 0o644)
	cfg := conf.WsClient{Connect: "127.0.0.1:1", User: "a", Pass: testPassA, Email: "a@example.com"}
	err := SendFiles(cfg, "c@example.com", []string{src}, "sideways", 1)
	if err == nil || !strings.Contains(err.Error(), "-via") {
		t.Fatalf("want a clear -via error, got %v", err)
	}
}

// TestSendFilesRejectsEscapingSubdir -to 里 scp 风格的 :子目录一旦想跳出
// receive.dir(比如带 ..), 要在真去拨号之前就拒绝, 不能指望对端 safeJoin 兜底。
func TestSendFilesRejectsEscapingSubdir(t *testing.T) {
	src := filepath.Join(t.TempDir(), "x.txt")
	os.WriteFile(src, []byte("hi"), 0o644)
	cfg := conf.WsClient{Connect: "127.0.0.1:1", User: "a", Pass: testPassA, Email: "a@example.com"}
	err := SendFiles(cfg, "c@example.com:../../etc", []string{src}, ViaDirect, 1)
	if err == nil || !strings.Contains(err.Error(), "escapes the receive directory") {
		t.Fatalf("want a clear escape error, got %v", err)
	}
}

// TestSendFilesToSubdir 端到端: -to 带 scp 风格的 :子目录时, 中继落到对端
// receive.dir 下对应的子目录, 而不是根目录。
func TestSendFilesToSubdir(t *testing.T) {
	connect := fileRelayTestServer(t, []conf.ServerUser{
		{User: "a", Pass: testPassA},
		{User: "c", Pass: testPassC},
	})

	recvDir := t.TempDir()
	_ = fileRelayTestClient(t, connect, "c", testPassC, "c@example.com", "",
		conf.ClientReceive{Dir: recvDir, Allow: []conf.AllowedSender{{Email: "a@example.com", UUID: testUUIDA}}})

	src := filepath.Join(t.TempDir(), "test.txt")
	if err := os.WriteFile(src, []byte("hello"), 0o644); err != nil {
		t.Fatalf("write source: %v", err)
	}

	cfg := conf.WsClient{Connect: connect, User: "a", Pass: testPassA, Email: "a@example.com", UUID: testUUIDA}
	if err := SendFiles(cfg, "c@example.com:/aaa/", []string{src}, ViaRelay, 1); err != nil {
		t.Fatalf("send: %v", err)
	}

	got, err := os.ReadFile(filepath.Join(recvDir, "aaa", "test.txt"))
	if err != nil {
		t.Fatalf("read received: %v", err)
	}
	if string(got) != "hello" {
		t.Fatalf("received %q, want %q", got, "hello")
	}
}

// TestRecvFilesRelayEndToEnd 端到端: A 经 B 中继主动从 C 取一整个目录。这条用例
// 覆盖的是整条链路 —— A 要清单、B 把 Op 原样转给 C(漏转的话 C 会当成收文件, 清单
// 那一步就失败)、C 展开目录、A 逐个取回并落盘。
func TestRecvFilesRelayEndToEnd(t *testing.T) {
	connect := fileRelayTestServer(t, []conf.ServerUser{
		{User: "a", Pass: testPassA},
		{User: "c", Pass: testPassC},
	})

	// C 的共享目录: 一个子目录 + 嵌套一层, 顺带盖住相对路径的重建。
	shareDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(shareDir, "backup", "sub"), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	want := map[string]string{
		filepath.Join("backup", "db.sql"):       "create table t;",
		filepath.Join("backup", "sub", "x.log"): "hello from sub",
	}
	for rel, body := range want {
		if err := os.WriteFile(filepath.Join(shareDir, rel), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	_ = fileRelayTestClient(t, connect, "c", testPassC, "c@example.com", "",
		conf.ClientReceive{Dir: shareDir, Allow: []conf.AllowedSender{{Email: "a@example.com", UUID: testUUIDA}}})

	localDir := t.TempDir()
	cfgA := conf.WsClient{Connect: connect, User: "a", Pass: testPassA,
		Email: "a@example.com", UUID: testUUIDA}
	if err := RecvFiles(cfgA, "c@example.com:backup", localDir, ViaRelay, 1); err != nil {
		t.Fatalf("recv: %v", err)
	}

	for rel, body := range want {
		got, err := os.ReadFile(filepath.Join(localDir, rel))
		if err != nil {
			t.Fatalf("read fetched %s: %v", rel, err)
		}
		if string(got) != body {
			t.Fatalf("fetched %s = %q, want %q", rel, got, body)
		}
	}
}

// readonly 在中继路径下同样有效: 取得走, 发不进来。与直连那条(见 file_test.go)是
// 两套不同的分派代码, 必须各测一遍 —— 只在一条路上拦住等于没拦。
func TestFileRelayReadOnlyServesButRefusesWrites(t *testing.T) {
	connect := fileRelayTestServer(t, []conf.ServerUser{
		{User: "a", Pass: testPassA},
		{User: "c", Pass: testPassC},
	})

	shareDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(shareDir, "pkg.tar"), []byte("payload"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = fileRelayTestClient(t, connect, "c", testPassC, "c@example.com", "",
		conf.ClientReceive{Dir: shareDir, ReadOnly: true,
			Allow: []conf.AllowedSender{{Email: "a@example.com", UUID: testUUIDA}}})

	cfgA := conf.WsClient{Connect: connect, User: "a", Pass: testPassA,
		Email: "a@example.com", UUID: testUUIDA}

	// 取: 照常。
	localDir := t.TempDir()
	if err := RecvFiles(cfgA, "c@example.com:pkg.tar", localDir, ViaRelay, 1); err != nil {
		t.Fatalf("a read-only directory must still serve files: %v", err)
	}
	if got, _ := os.ReadFile(filepath.Join(localDir, "pkg.tar")); string(got) != "payload" {
		t.Fatalf("fetched %q, want %q", got, "payload")
	}

	// 发: 必须被拒。
	src := filepath.Join(t.TempDir(), "unwanted.txt")
	if err := os.WriteFile(src, []byte("nope"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	err := SendFiles(cfgA, "c@example.com", []string{src}, ViaRelay, 1)
	if err == nil || !strings.Contains(err.Error(), "read-only") {
		t.Fatalf("want a read-only refusal, got %v", err)
	}
	if _, statErr := os.Stat(filepath.Join(shareDir, "unwanted.txt")); !os.IsNotExist(statErr) {
		t.Fatal("the refused file must not have been written")
	}
}

// TestRecvFilesRelayRejectsStranger 取文件复用的是 receive.allow 那份名单, 所以不在
// 名单里的人来取必须失败 —— 中继路径下"失败"表现为解密对不上(uuid 不对就派生不出
// 同一把 key), 而不是一句客气的拒绝。
func TestRecvFilesRelayRejectsStranger(t *testing.T) {
	connect := fileRelayTestServer(t, []conf.ServerUser{
		{User: "a", Pass: testPassA},
		{User: "c", Pass: testPassC},
	})
	shareDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(shareDir, "secret.txt"), []byte("nope"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	_ = fileRelayTestClient(t, connect, "c", testPassC, "c@example.com", "",
		conf.ClientReceive{Dir: shareDir, Allow: []conf.AllowedSender{{Email: "trusted@example.com", UUID: testUUIDTrusted}}})

	localDir := t.TempDir()
	cfgA := conf.WsClient{Connect: connect, User: "a", Pass: testPassA,
		Email: "a@example.com", UUID: testUUIDStranger}
	err := RecvFiles(cfgA, "c@example.com:secret.txt", localDir, ViaRelay, 1)
	if err == nil {
		t.Fatal("a peer that is not in receive.allow must not be able to fetch anything")
	}
	if entries, _ := os.ReadDir(localDir); len(entries) != 0 {
		t.Fatalf("nothing should have been fetched, found %d entries", len(entries))
	}
}
