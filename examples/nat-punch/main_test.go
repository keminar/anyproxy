package main

import (
	"strings"
	"testing"
	"time"
)

func TestReflectorOnlyCountsPunchStatusAsActivity(t *testing.T) {
	now := time.Unix(1000, 0)
	activity := newPeerActivity(now)

	if reply, status := reflectorResponse(activity, "a:1000", whoamiMagic, now); status || reply != "a:1000" {
		t.Fatalf("WHOAMI response = %q, status=%v", reply, status)
	}
	if activity.active("a:1000", now) {
		t.Fatal("WHOAMI incorrectly marked a waiting client as punching")
	}

	if reply, status := reflectorResponse(activity, "c:3000", statusPrefix+"a:1000", now); !status || reply != "IDLE" {
		t.Fatalf("first C status response = %q, status=%v; want IDLE", reply, status)
	}
	if !activity.active("c:3000", now) {
		t.Fatal("STATUS did not mark its sender as punching")
	}

	if reply, _ := reflectorResponse(activity, "a:1000", statusPrefix+"c:3000", now.Add(time.Second)); reply != "ACTIVE" {
		t.Fatalf("A query for punching C = %q; want ACTIVE", reply)
	}
}

func TestPeerActivityExpiresAndCleansUp(t *testing.T) {
	now := time.Unix(1000, 0)
	activity := newPeerActivity(now)
	activity.mark("old:1", now)

	later := now.Add(peerActiveWindow)
	if activity.active("old:1", later) {
		t.Fatal("activity at the expiry boundary is still active")
	}
	activity.mark("new:2", later)
	if _, exists := activity.seen["old:1"]; exists {
		t.Fatal("expired activity was not removed during periodic cleanup")
	}
	if !activity.active("new:2", later) {
		t.Fatal("new activity was removed by cleanup")
	}
}

func TestValidatePunchArgs(t *testing.T) {
	tests := []struct {
		name               string
		port               int
		duration, interval time.Duration
		wantErrorSubstring string
	}{
		{name: "valid", port: 0, interval: time.Millisecond},
		{name: "valid maximum port", port: 65535, duration: time.Second, interval: time.Millisecond},
		{name: "negative port", port: -1, interval: time.Millisecond, wantErrorSubstring: "-local"},
		{name: "oversized port", port: 65536, interval: time.Millisecond, wantErrorSubstring: "-local"},
		{name: "negative duration", duration: -time.Second, interval: time.Millisecond, wantErrorSubstring: "-duration"},
		{name: "zero interval", wantErrorSubstring: "-interval"},
		{name: "negative interval", interval: -time.Millisecond, wantErrorSubstring: "-interval"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := validatePunchArgs(test.port, test.duration, test.interval)
			if test.wantErrorSubstring == "" && err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if test.wantErrorSubstring != "" && (err == nil || !strings.Contains(err.Error(), test.wantErrorSubstring)) {
				t.Fatalf("error = %v; want substring %q", err, test.wantErrorSubstring)
			}
		})
	}
}

func TestValidateNetwork(t *testing.T) {
	for _, network := range []string{"udp4", "udp6"} {
		if err := validateNetwork(network); err != nil {
			t.Fatalf("validateNetwork(%q): %v", network, err)
		}
	}
	for _, network := range []string{"", "udp", "tcp6", "UDP6"} {
		if err := validateNetwork(network); err == nil {
			t.Fatalf("validateNetwork(%q) succeeded; want error", network)
		}
	}
}

func TestNonEmptyTrimsAndDropsEmptyValues(t *testing.T) {
	got := nonEmpty([]string{" one:1 ", "", "  ", "two:2"})
	want := []string{"one:1", "two:2"}
	if len(got) != len(want) {
		t.Fatalf("nonEmpty result = %#v; want %#v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("nonEmpty result = %#v; want %#v", got, want)
		}
	}
}

func TestVerdictRequiresActualPunchActivityForFailure(t *testing.T) {
	if got := verdict(0, false, "udp4"); !strings.HasPrefix(got, "INCONCLUSIVE") {
		t.Fatalf("verdict without peer activity = %q", got)
	}
	if got := verdict(0, true, "udp4"); !strings.HasPrefix(got, "FAILED") || !strings.Contains(got, "CGNAT") {
		t.Fatalf("verdict with peer activity = %q", got)
	}
	if got := verdict(0, true, "udp6"); !strings.HasPrefix(got, "FAILED") || !strings.Contains(got, "IPv6") {
		t.Fatalf("IPv6 verdict with peer activity = %q", got)
	}
	if got := verdict(1, false, "udp6"); !strings.HasPrefix(got, "SUCCESS") {
		t.Fatalf("verdict after receive = %q", got)
	}
}
