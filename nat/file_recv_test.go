package nat

import (
	"strings"
	"testing"

	"github.com/keminar/anyproxy/utils/conf"
)

func TestSplitRecvSpec(t *testing.T) {
	cases := []struct {
		in         string
		wantEmail  string
		wantPath   string
		wantErrSub string
	}{
		{in: "a@example.com:backup", wantEmail: "a@example.com", wantPath: "backup"},
		{in: "a@example.com:/backup/", wantEmail: "a@example.com", wantPath: "backup"},
		{in: "a@example.com:backup/db.sql", wantEmail: "a@example.com", wantPath: "backup/db.sql"},
		{in: "a@example.com:./x", wantEmail: "a@example.com", wantPath: "x"},
		// 不写冒号是最容易犯的错(照着旧的 -recv EMAIL 写), 报错要直接说清楚怎么改。
		{in: "a@example.com", wantErrSub: "does not say what to fetch"},
		{in: "a@example.com:", wantErrSub: "empty path"},
		{in: "a@example.com:/", wantErrSub: "empty path"},
		{in: "a@example.com:../../etc/passwd", wantErrSub: "escapes"},
		{in: `a@example.com:back\slash`, wantErrSub: "backslash"},
		{in: "a@example.com:C:/data", wantErrSub: "colon"},
	}
	for _, c := range cases {
		email, p, err := splitRecvSpec(c.in)
		if c.wantErrSub != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErrSub) {
				t.Errorf("splitRecvSpec(%q) error = %v, want one containing %q", c.in, err, c.wantErrSub)
			}
			continue
		}
		if err != nil {
			t.Errorf("splitRecvSpec(%q) unexpected error: %v", c.in, err)
			continue
		}
		if email != c.wantEmail || p != c.wantPath {
			t.Errorf("splitRecvSpec(%q) = (%q, %q), want (%q, %q)", c.in, email, p, c.wantEmail, c.wantPath)
		}
	}
}

func TestRecvFilesValidatesArgs(t *testing.T) {
	base := conf.WsClient{
		Connect: "127.0.0.1:1",
		Email:   "c@example.com",
		UUID:    testUUIDA,
	}

	cases := []struct {
		name       string
		recv, via  string
		wantErrSub string
	}{
		{"empty recv", "", ViaRelay, "-recv is required"},
		{"no path", "a@example.com", ViaRelay, "does not say what to fetch"},
		{"self recv", "c@example.com:x", ViaRelay, "own email"},
		{"empty email", ":x", ViaRelay, "empty email"},
		{"bad via", "a@example.com:x", "sideways", "-via"},
		{"escaping path", "a@example.com:../x", ViaRelay, "escapes"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := RecvFiles(base, c.recv, t.TempDir(), c.via)
			if err == nil || !strings.Contains(err.Error(), c.wantErrSub) {
				t.Fatalf("want error containing %q, got %v", c.wantErrSub, err)
			}
		})
	}
}

// 自己的 uuid 是对端认人的唯一凭证, 不合法就该就地拒绝, 而不是连上去跑一趟才被拒
// (同 sendFile 的做法)。
func TestRecvFilesRefusesInvalidOwnUUID(t *testing.T) {
	for _, uuid := range []string{"", "not-a-uuid"} {
		cfg := conf.WsClient{Connect: "127.0.0.1:1", Email: "c@example.com", UUID: uuid}
		err := RecvFiles(cfg, "a@example.com:x", t.TempDir(), ViaRelay)
		if err == nil || !strings.Contains(err.Error(), "uuid") {
			t.Fatalf("uuid %q: want a uuid complaint, got %v", uuid, err)
		}
	}
}
