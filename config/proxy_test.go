package config

import "testing"

// TestSetProxyServer 覆盖全局代理首个代理的解析(供 tun_windows 排除/日志用):
// 单代理 / 无 scheme 默认 tunnel / 多代理取首个 / 带后缀剥离。
func TestSetProxyServer(t *testing.T) {
	reset := func() {
		ProxyScheme, ProxyServer, ProxyPort = "tunnel", "", 0
	}

	t.Run("single", func(t *testing.T) {
		reset()
		SetProxyServer("socks5://127.0.0.1:1080")
		if ProxyScheme != "socks5" || ProxyServer != "127.0.0.1" || ProxyPort != 1080 {
			t.Fatalf("got %s://%s:%d", ProxyScheme, ProxyServer, ProxyPort)
		}
	})

	t.Run("no-scheme defaults tunnel", func(t *testing.T) {
		reset()
		SetProxyServer("10.2.2.2:3001")
		if ProxyScheme != "tunnel" || ProxyServer != "10.2.2.2" || ProxyPort != 3001 {
			t.Fatalf("got %s://%s:%d", ProxyScheme, ProxyServer, ProxyPort)
		}
	})

	t.Run("multi takes first", func(t *testing.T) {
		reset()
		SetProxyServer("http://127.0.0.1:8888, http://127.0.0.1:7777")
		if ProxyScheme != "http" || ProxyServer != "127.0.0.1" || ProxyPort != 8888 {
			t.Fatalf("first proxy got %s://%s:%d", ProxyScheme, ProxyServer, ProxyPort)
		}
	})

	t.Run("suffix stripped", func(t *testing.T) {
		reset()
		SetProxyServer("socks5://192.168.122.11:10808, socks5://192.168.122.1:10808 local")
		if ProxyScheme != "socks5" || ProxyServer != "192.168.122.11" || ProxyPort != 10808 {
			t.Fatalf("got %s://%s:%d", ProxyScheme, ProxyServer, ProxyPort)
		}
	})

	t.Run("empty is noop", func(t *testing.T) {
		reset()
		SetProxyServer("")
		if ProxyServer != "" {
			t.Fatalf("empty spec mutated state: server=%q", ProxyServer)
		}
	})
}
