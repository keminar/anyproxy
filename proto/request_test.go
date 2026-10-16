package proto

import (
	"context"
	"crypto/aes"
	"net"
	"testing"
	"time"

	"github.com/keminar/anyproxy/utils/conf"
)

// getAesKey 要把任意长度的配置 token 归一化成 AES-128 能接受的16字节key, 且同一个
// token 每次派生结果必须一致(两端各自调用一次也要能对上), 否则加解密对不上。
func TestGetAesKeyNormalizesAnyLength(t *testing.T) {
	old := conf.RouterConfig()
	t.Cleanup(func() { conf.SetRouterConfig(old) })

	cases := []struct {
		name  string
		token string
	}{
		{"empty falls back to default", ""},
		{"exactly 16 bytes", "anyproxyproxyany"},
		{"shorter than 16", "short"},
		{"single char", "a"},
		{"longer than 16", "this-token-is-way-longer-than-16-bytes"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			conf.SetRouterConfig(&conf.Router{Token: c.token})
			key := getAesKey()
			if len(key) != 16 {
				t.Fatalf("getAesKey(%q) len = %d, want 16", c.token, len(key))
			}
			if _, err := aes.NewCipher(key); err != nil {
				t.Fatalf("aes.NewCipher(getAesKey(%q)): %v", c.token, err)
			}
			// 同一个 token 必须每次派生出相同的key, 否则两端各自算一遍会对不上。
			if again := getAesKey(); string(again) != string(key) {
				t.Fatalf("getAesKey(%q) not deterministic: %x vs %x", c.token, key, again)
			}
		})
	}
}

// dialToHandler 起一个回环监听, 把 accept 到的连接交给 h, 返回客户端侧的连接。
func dialToHandler(t *testing.T, h func(*net.TCPConn)) *net.TCPConn {
	t.Helper()
	ln, err := net.ListenTCP("tcp", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Skipf("cannot listen on loopback: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		c, err := ln.AcceptTCP()
		if err != nil {
			return
		}
		defer c.Close()
		h(c)
	}()
	c, err := net.DialTCP("tcp", nil, ln.Addr().(*net.TCPAddr))
	if err != nil {
		t.Skipf("cannot dial loopback: %v", err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// TestReadRequestTimesOutOnSilentClient 完成了 TCP 握手却一个字节都不发的客户端, 必须
// 被 ReadRequest 自己的 deadline 放掉, 而不是一直占着 goroutine 和 fd 等到 OS 的 TCP
// keepalive(默认 2 小时) —— 即 slowloris。
//
// 走真正的 ReadRequest(而不是自己另设一个 deadline 再调内部的 Peek): 那样测的是
// net.TCPConn 本来就有的超时能力, 就算 ReadRequest 里那几行被删掉用例照样绿, 等于什么
// 都没保证。代价是要真等满 readRequestTimeout, 所以挂 -short 跳过。
func TestReadRequestTimesOutOnSilentClient(t *testing.T) {
	if testing.Short() {
		t.Skipf("takes %v (waits out readRequestTimeout)", readRequestTimeout)
	}
	old := conf.RouterConfig()
	t.Cleanup(func() { conf.SetRouterConfig(old) })
	conf.SetRouterConfig(&conf.Router{})

	done := make(chan error, 1)
	dialToHandler(t, func(c *net.TCPConn) {
		req := NewRequest(context.Background(), c)
		_, err := req.ReadRequest("client")
		done <- err
	})

	// 客户端什么都不发, 就这么挂着。
	start := time.Now()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a silent client must not be accepted")
		}
		// 必须是被超时放掉的, 不是别的原因提前返回。
		if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
			t.Fatalf("got err %v, want a timeout", err)
		}
		// 且确实等满了 —— 否则可能是别处某个更短的超时碰巧生效。
		if waited := time.Since(start); waited < readRequestTimeout/2 {
			t.Errorf("returned after %v, expected to wait about %v", waited, readRequestTimeout)
		}
	case <-time.After(readRequestTimeout + 10*time.Second):
		t.Fatal("ReadRequest never returned: a silent client can hold the goroutine forever")
	}
}

// TestReadRequestDeadlineIsClearedAfterHeader 请求头读完之后必须把 deadline 清掉, 否则
// 30 秒后正在转发的长连接会被自己的读超时打断 —— 这个回归比超时本身更隐蔽。
func TestReadRequestDeadlineIsClearedAfterHeader(t *testing.T) {
	old := conf.RouterConfig()
	t.Cleanup(func() { conf.SetRouterConfig(old) })
	conf.SetRouterConfig(&conf.Router{})

	done := make(chan error, 1)
	srv := dialToHandler(t, func(c *net.TCPConn) {
		req := NewRequest(context.Background(), c)
		if _, err := req.ReadRequest("client"); err != nil {
			done <- err
			return
		}
		// 头读完了, deadline 应已清空: 这次读要一直等到客户端真的发来数据,
		// 而不是立刻超时返回。
		buf := make([]byte, 4)
		_, err := c.Read(buf)
		done <- err
	})

	if _, err := srv.Write([]byte("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n")); err != nil {
		t.Fatalf("write request: %v", err)
	}
	// 隔一会儿再发 body: 若 deadline 没清掉, 服务端那次 Read 会先超时失败。
	time.Sleep(300 * time.Millisecond)
	if _, err := srv.Write([]byte("data")); err != nil {
		t.Fatalf("write body: %v", err)
	}

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("read after header failed, deadline was not cleared: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("handler never finished")
	}
}
