package nat

import (
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestCandidateBias(t *testing.T) {
	cases := []struct {
		host string
		want time.Duration
	}{
		{"127.0.0.1", biasLoopback},
		{"::1", biasLoopback},
		{"169.254.1.2", biasLinkLocal},
		{"fe80::1", biasLinkLocal},
		{"192.168.1.5", biasPrivate},
		{"10.0.0.7", biasPrivate},
		{"172.16.0.1", biasPrivate},
		{"fd00::1", biasPrivate},
		// CGNAT: net.IP.IsPrivate 不认这一段, 但运营商大内网里的对端走它才是同网直连。
		{"100.64.0.1", biasPrivate},
		{"100.127.255.254", biasPrivate},
		// 边界: 100.63 与 100.128 都在 100.64/10 之外, 是普通公网地址。
		{"100.63.255.255", biasPublic},
		{"100.128.0.1", biasPublic},
		{"1.1.1.1", biasPublic},
		{"2400:3200::1", biasPublic},
		{"not-an-ip", biasPublic},
	}
	for _, c := range cases {
		if got := candidateBias(c.host); got != c.want {
			t.Errorf("candidateBias(%s) = %s, want %s", c.host, got, c.want)
		}
	}
}

// 公网 IPv4 与公网 IPv6 必须平等竞争, 纯比 RTT —— 不能对任一族有先验偏好。
func TestSelectPublicFamiliesCompeteOnRTT(t *testing.T) {
	v4 := directCandidate{Addr: "1.2.3.4:100", Source: candSrcReflectV4}
	v6 := directCandidate{Addr: "[2400:3200::1]:100", Source: candSrcReflectV6}

	got, err := selectCandidate([]candidateResult{
		{Cand: v4, RTT: 40 * time.Millisecond},
		{Cand: v6, RTT: 20 * time.Millisecond},
	})
	if err != nil || got.Addr != v6.Addr {
		t.Fatalf("faster IPv6 should win: got %v err %v", got, err)
	}
	// 反过来同样成立。
	got, err = selectCandidate([]candidateResult{
		{Cand: v4, RTT: 20 * time.Millisecond},
		{Cand: v6, RTT: 40 * time.Millisecond},
	})
	if err != nil || got.Addr != v4.Addr {
		t.Fatalf("faster IPv4 should win: got %v err %v", got, err)
	}
}

// 偏置的意义: RTT 略高的近距离地址仍应胜出。
func TestSelectBiasBeatsSmallRTTGap(t *testing.T) {
	public := directCandidate{Addr: "1.2.3.4:100", Source: candSrcReflectV4}
	lan := directCandidate{Addr: "192.168.1.5:100", Source: candSrcLocal}

	// 私有地址慢 15ms, 但偏置 -20ms, 仍然应该赢。
	got, err := selectCandidate([]candidateResult{
		{Cand: public, RTT: 10 * time.Millisecond},
		{Cand: lan, RTT: 25 * time.Millisecond},
	})
	if err != nil || got.Addr != lan.Addr {
		t.Fatalf("LAN address should win a 15ms gap against -20ms bias: got %v", got)
	}
	// 慢 30ms 就超过偏置了, 该让公网赢 —— 偏置是让它"更容易"胜出, 不是无条件胜出。
	got, err = selectCandidate([]candidateResult{
		{Cand: public, RTT: 10 * time.Millisecond},
		{Cand: lan, RTT: 40 * time.Millisecond},
	})
	if err != nil || got.Addr != public.Addr {
		t.Fatalf("a 30ms gap should beat a -20ms bias: got %v", got)
	}
}

// 偏置的档次要能排出序: 同样 RTT 下 回环 > 链路本地 > 私有 > 公网。
func TestSelectBiasOrdering(t *testing.T) {
	rtt := 10 * time.Millisecond
	all := []candidateResult{
		{Cand: directCandidate{Addr: "1.2.3.4:1"}, RTT: rtt},
		{Cand: directCandidate{Addr: "192.168.0.1:1"}, RTT: rtt},
		{Cand: directCandidate{Addr: "169.254.0.1:1"}, RTT: rtt},
		{Cand: directCandidate{Addr: "127.0.0.1:1"}, RTT: rtt},
	}
	want := []string{"127.0.0.1:1", "169.254.0.1:1", "192.168.0.1:1", "1.2.3.4:1"}
	for _, w := range want {
		got, err := selectCandidate(all)
		if err != nil {
			t.Fatalf("select: %v", err)
		}
		if got.Addr != w {
			t.Fatalf("want %s next, got %s", w, got.Addr)
		}
		// 去掉刚选中的, 再看下一名。
		var rest []candidateResult
		for _, r := range all {
			if r.Cand.Addr != w {
				rest = append(rest, r)
			}
		}
		all = rest
	}
}

// 没通的候选不能参与择优, 哪怕它的地址类型更优。
func TestSelectSkipsFailures(t *testing.T) {
	got, err := selectCandidate([]candidateResult{
		{Cand: directCandidate{Addr: "127.0.0.1:1"}, Err: errors.New("no route")},
		{Cand: directCandidate{Addr: "1.2.3.4:1"}, RTT: 90 * time.Millisecond},
	})
	if err != nil {
		t.Fatalf("select: %v", err)
	}
	if got.Addr != "1.2.3.4:1" {
		t.Fatalf("a failed loopback candidate was selected: %v", got)
	}
}

// 一条都没通时, 报错要带上每条的原因 —— 只说"连不上"没法排查。
func TestSelectAllFailedExplains(t *testing.T) {
	_, err := selectCandidate([]candidateResult{
		{Cand: directCandidate{Addr: "1.2.3.4:1", Source: candSrcReflectV4}, Err: errors.New("timeout")},
		{Cand: directCandidate{Addr: "[2400::1]:1", Source: candSrcReflectV6}, Err: errors.New("no route to host")},
	})
	if err == nil {
		t.Fatal("want an error when nothing answered")
	}
	for _, want := range []string{"1.2.3.4:1", "timeout", "2400::1", "no route to host"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q does not mention %q", err, want)
		}
	}
}

func TestDedupCandidates(t *testing.T) {
	got := dedupCandidates([]directCandidate{
		{Addr: "1.2.3.4:1", Source: candSrcReflectV4},
		{Addr: "1.2.3.4:1", Source: candSrcLocal}, // 同一端点从两个来源冒出来
		{Addr: "", Source: candSrcLocal},          // 空地址丢掉
		{Addr: "[2400::1]:1", Source: candSrcReflectV6},
	})
	if len(got) != 2 {
		t.Fatalf("want 2 candidates after dedup, got %d: %v", len(got), got)
	}
	if got[0].Source != candSrcReflectV4 {
		t.Fatalf("dedup should keep the first occurrence, got %v", got[0])
	}
}

func TestLocalCandidates(t *testing.T) {
	if got := localCandidates(0); got != nil {
		t.Fatalf("port 0 means the socket is not bound yet, want no candidates, got %v", got)
	}
	got := localCandidates(4242)
	if len(got) == 0 {
		t.Skip("host reports no interface addresses")
	}
	for _, c := range got {
		if c.Source != candSrcLocal {
			t.Errorf("%v: wrong source", c)
		}
		host, port, err := net.SplitHostPort(c.Addr)
		if err != nil {
			t.Errorf("%v: not a host:port: %v", c, err)
			continue
		}
		if port != "4242" {
			t.Errorf("%v: want port 4242", c)
		}
		if host == "" {
			t.Errorf("%v: empty host", c)
		}
	}
}
