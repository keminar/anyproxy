package nat

import (
	"errors"
	"io"
	"testing"
	"time"
)

func TestMsgPipeWriteSendsThroughCallback(t *testing.T) {
	var got []byte
	p := newMsgPipe(func(b []byte) error {
		got = append([]byte(nil), b...)
		return nil
	}, nil)
	n, err := p.Write([]byte("hello"))
	if err != nil || n != 5 {
		t.Fatalf("write: n=%d err=%v", n, err)
	}
	if string(got) != "hello" {
		t.Fatalf("send callback got %q", got)
	}
}

func TestMsgPipeReadBlocksUntilPush(t *testing.T) {
	p := newMsgPipe(func([]byte) error { return nil }, nil)
	done := make(chan struct{})
	var n int
	var err error
	buf := make([]byte, 32)
	go func() {
		defer close(done)
		n, err = p.Read(buf)
	}()

	select {
	case <-done:
		t.Fatal("Read returned before anything was pushed")
	case <-time.After(50 * time.Millisecond):
	}

	p.push([]byte("payload"))
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Read did not return after push")
	}
	if err != nil || string(buf[:n]) != "payload" {
		t.Fatalf("Read = %q, %v", buf[:n], err)
	}
}

// 一次 push 的数据可能比调用方的缓冲区大, 剩下的部分要留到下一次 Read 才吐出来,
// 不能丢掉——writeFrame/readFrame 是按精确字节数读的, 丢一个字节整个协议就错位了。
func TestMsgPipeReadSplitsAcrossMultipleReads(t *testing.T) {
	p := newMsgPipe(func([]byte) error { return nil }, nil)
	go p.push([]byte("abcdef"))

	buf := make([]byte, 4)
	n, err := p.Read(buf)
	if err != nil || string(buf[:n]) != "abcd" {
		t.Fatalf("first read = %q, %v", buf[:n], err)
	}
	n, err = p.Read(buf)
	if err != nil || string(buf[:n]) != "ef" {
		t.Fatalf("second read = %q, %v", buf[:n], err)
	}
}

func TestMsgPipeCloseUnblocksReadWithEOF(t *testing.T) {
	p := newMsgPipe(func([]byte) error { return nil }, nil)
	done := make(chan struct{})
	var err error
	go func() {
		defer close(done)
		_, err = p.Read(make([]byte, 8))
	}()
	time.Sleep(20 * time.Millisecond)
	p.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Read did not unblock after Close")
	}
	if err != io.EOF {
		t.Fatalf("want io.EOF, got %v", err)
	}

	// 关闭之后 Write 必须报错, 不能假装成功——那会让发送方以为数据发出去了。
	if _, err := p.Write([]byte("x")); err == nil {
		t.Fatal("write after Close should fail")
	}
}

// 带原因的关闭(对端主动喊停)要能把原因带出来, 不能被压成一个语焉不详的 EOF——
// 排查"到底是谁先断的、为什么"时这条信息不能丢。
func TestMsgPipeCloseWithErrorPropagates(t *testing.T) {
	p := newMsgPipe(func([]byte) error { return nil }, nil)
	wantErr := errors.New("peer said no forward target")
	done := make(chan struct{})
	var err error
	go func() {
		defer close(done)
		_, err = p.Read(make([]byte, 8))
	}()
	time.Sleep(20 * time.Millisecond)
	p.closeWithError(wantErr)
	<-done
	if err != wantErr {
		t.Fatalf("got %v, want %v", err, wantErr)
	}
}

func TestMsgPipeReadDeadline(t *testing.T) {
	p := newMsgPipe(func([]byte) error { return nil }, nil)
	p.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	start := time.Now()
	_, err := p.Read(make([]byte, 8))
	if err != errMsgPipeTimeout {
		t.Fatalf("want timeout error, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("took too long to time out: %s", elapsed)
	}

	// 清掉 deadline 之后不该再超时。
	p.SetReadDeadline(time.Time{})
	go p.push([]byte("ok"))
	buf := make([]byte, 8)
	n, err := p.Read(buf)
	if err != nil || string(buf[:n]) != "ok" {
		t.Fatalf("read after clearing deadline: %q, %v", buf[:n], err)
	}
}

// push 不能阻塞调用方: 它跑在订阅方处理**所有**入站消息的那一个 goroutine 上
// (localReadPump), 一旦卡住, 这条 websocket 上的 RDP 转发/心跳/其它一切全停摆——
// 这正是"一传文件, 同一台机器的 mstsc 就断"的成因。缓冲容量内的 push 必须立即返回。
func TestMsgPipePushDoesNotBlockWithinBuffer(t *testing.T) {
	p := newMsgPipe(func([]byte) error { return nil }, nil)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < msgPipeBuffer; i++ {
			p.push([]byte("x"))
		}
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatalf("push blocked before filling the %d-slot buffer; localReadPump would stall", msgPipeBuffer)
	}
}

// 在途字节超过窗口时 Write 必须等对端确认, 不能一路往下灌——灌满 hub 的发送队列
// 之后消息会被直接丢弃(见 Hub.run), 而字节流少一段就是对端帧错位。
func TestMsgPipeWriteBlocksUntilAcked(t *testing.T) {
	p := newMsgPipe(func([]byte) error { return nil }, nil)

	chunk := make([]byte, relayWindow/2)
	if _, err := p.Write(chunk); err != nil { // 第一块: 窗口空的, 直接过
		t.Fatalf("first write: %v", err)
	}
	if _, err := p.Write(chunk); err != nil { // 正好填满窗口
		t.Fatalf("second write: %v", err)
	}

	blocked := make(chan error, 1)
	go func() { _, err := p.Write(chunk); blocked <- err }()

	select {
	case err := <-blocked:
		t.Fatalf("third write should wait for an ack, returned %v", err)
	case <-time.After(200 * time.Millisecond):
	}

	// 对端确认了一半, 窗口腾出位置, 这次写就该放行。
	p.onAck(int64(relayWindow / 2))
	select {
	case err := <-blocked:
		if err != nil {
			t.Fatalf("write after ack: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("write did not resume after the peer acknowledged")
	}
}

// 单块大于整个窗口时不能死等自己——第一块永远放行。
func TestMsgPipeWriteAllowsOversizedFirstChunk(t *testing.T) {
	p := newMsgPipe(func([]byte) error { return nil }, nil)
	done := make(chan error, 1)
	go func() { _, err := p.Write(make([]byte, relayWindow*2)); done <- err }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("oversized first write: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("an oversized first chunk must not wait for an ack that can never come")
	}
}

// 收方要按消费进度回累计确认——确认必须发生在数据真的被上层取走之后, 这样窗口
// 保护的才是接收方的处理能力, 而不只是网络。
func TestMsgPipeReadSendsCumulativeAcks(t *testing.T) {
	acks := make(chan int64, 8)
	p := newMsgPipe(func([]byte) error { return nil }, func(n int64) error {
		acks <- n
		return nil
	})

	go func() {
		for i := 0; i < 3; i++ {
			p.push(make([]byte, relayAckEvery))
		}
	}()

	buf := make([]byte, relayAckEvery)
	var read int64
	for read < int64(relayAckEvery)*3 {
		n, err := p.Read(buf)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		read += int64(n)
	}

	select {
	case n := <-acks:
		if n < relayAckEvery {
			t.Fatalf("first ack should cover at least one ack interval, got %d", n)
		}
	case <-time.After(time.Second):
		t.Fatal("no ack was sent after consuming more than one ack interval")
	}
}

// 对端根本不回确认(比如版本太老)时, 发送方不能无限期挂着, 要给个说得清楚的错误。
func TestMsgPipeWriteTimesOutWithoutAcks(t *testing.T) {
	p := newMsgPipe(func([]byte) error { return nil }, nil)
	p.sent = relayWindow // 假装已经把窗口填满且一个确认都没收到

	// 用 done 提前唤醒来验证等待路径是可中断的(真实超时是 relayAckTimeout, 用例里
	// 不适合真等那么久)。
	go func() {
		time.Sleep(50 * time.Millisecond)
		p.closeWithError(errors.New("peer disconnected"))
	}()
	_, err := p.Write([]byte("x"))
	if err == nil {
		t.Fatal("write must fail rather than hang when the window never opens")
	}
}

// Write 失败(send 回调报错)必须原样冒泡, 不能吞掉——上层靠这个错误判断发送失败。
func TestMsgPipeWriteErrorPropagates(t *testing.T) {
	wantErr := errors.New("send failed")
	p := newMsgPipe(func([]byte) error { return wantErr }, nil)
	_, err := p.Write([]byte("x"))
	if err != wantErr {
		t.Fatalf("got %v, want %v", err, wantErr)
	}
}
