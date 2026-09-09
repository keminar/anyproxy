package nat

import (
	"testing"
	"time"

	"github.com/keminar/anyproxy/utils/conf"
)

// TestConnectServerRefusesIncompleteEntry websocket.clients[] 是整个数组一起返回、
// 不逐项过滤的(见 conf.Websocket.ClientList 的注释), 漏配 connect(或 user/email)的
// 那一项必须在 ConnectServer 里被单独挡下, 不能真的拿一个空地址进入重连循环。用
// "很快返回、不阻塞"证明它走的是提前 return, 而不是卡在拨号里重试。
func TestConnectServerRefusesIncompleteEntry(t *testing.T) {
	cases := []struct {
		name string
		cfg  conf.WsClient
	}{
		{"missing connect", conf.WsClient{User: "a", Email: "a@example.com"}},
		{"missing user", conf.WsClient{Connect: "127.0.0.1:1", Email: "a@example.com"}},
		{"missing email", conf.WsClient{Connect: "127.0.0.1:1", User: "a"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			done := make(chan struct{})
			go func() {
				ConnectServer(c.cfg, 0)
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("ConnectServer should return immediately on an incomplete entry, not attempt to dial/retry")
			}
		})
	}
}

// TestConnectServerSkipsWithoutPersistentReason 一条完整(connect/user/email 齐全)
// 但没什么理由让常驻进程为它保持连接的配置不该真去拨号——要么是自动判断出
// subscribe/forward/direct/directAccept/receive.dir 全是空的(见
// conf.WsClient.WantsPersistentConnect), 要么是显式开了 sendRecvOnly 强制跳过。
// 两种都该走提前 return, 而不是真去拨一个不可能连通的地址、卡进重连循环。
func TestConnectServerSkipsWithoutPersistentReason(t *testing.T) {
	cases := []struct {
		name string
		cfg  conf.WsClient
	}{
		{
			name: "nothing configured, auto-detected",
			cfg:  conf.WsClient{Connect: "127.0.0.1:1", User: "a", Email: "a@example.com"},
		},
		{
			name: "explicit sendRecvOnly, nothing else configured",
			cfg:  conf.WsClient{Connect: "127.0.0.1:1", User: "a", Email: "a@example.com", SendRecvOnly: true},
		},
		{
			name: "explicit sendRecvOnly overrides a configured forward",
			cfg: conf.WsClient{
				Connect: "127.0.0.1:1", User: "a", Email: "a@example.com", SendRecvOnly: true,
				Forward: []conf.ClientForward{{Port: 22, Target: "127.0.0.1:22"}},
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			done := make(chan struct{})
			go func() {
				ConnectServer(c.cfg, 0)
				close(done)
			}()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("ConnectServer should return immediately, not attempt to dial/retry")
			}
		})
	}
}
