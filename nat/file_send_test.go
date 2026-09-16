package nat

import (
	"strings"
	"testing"
)

func TestSplitSendTo(t *testing.T) {
	cases := []struct {
		in         string
		email      string
		subdir     string
		wantErrSub string
	}{
		{in: "c@example.com", email: "c@example.com", subdir: ""},
		{in: "c@example.com:", email: "c@example.com", subdir: ""},
		{in: "c@example.com:/", email: "c@example.com", subdir: ""},
		{in: "c@example.com:/aaa/", email: "c@example.com", subdir: "aaa"},
		{in: "c@example.com:aaa/bbb", email: "c@example.com", subdir: "aaa/bbb"},
		{in: "c@example.com:../etc", wantErrSub: "escapes"},
		{in: "c@example.com:aaa/../../etc", wantErrSub: "escapes"},
		{in: `c@example.com:aaa\bbb`, wantErrSub: "backslash or colon"},
	}
	for _, c := range cases {
		email, subdir, err := splitSendTo(c.in)
		if c.wantErrSub != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErrSub) {
				t.Errorf("splitSendTo(%q): want error containing %q, got %v", c.in, c.wantErrSub, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("splitSendTo(%q): unexpected error: %v", c.in, err)
			continue
		}
		if email != c.email || subdir != c.subdir {
			t.Errorf("splitSendTo(%q) = (%q, %q), want (%q, %q)", c.in, email, subdir, c.email, c.subdir)
		}
	}
}
