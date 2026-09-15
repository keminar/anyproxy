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

// resolveVia 把 -via 解成"关键字"或"当作 VPS email 的盲转发直连"两类, 且不能与
// 两个保留关键字冲突。
func TestResolveVia(t *testing.T) {
	cases := []struct {
		via          string
		wantVia      string
		wantRelayVia string
	}{
		{ViaDirect, ViaDirect, ""},
		{ViaRelay, ViaRelay, ""},
		{"", ViaDirect, ""}, // 空值等价于默认的 direct
		{"vps@example.com", ViaDirect, "vps@example.com"},
		{"sideways", ViaDirect, "sideways"}, // 任意非关键字都当 VPS email, 不再报"-via 非法"
	}
	for _, c := range cases {
		gotVia, gotRelayVia := resolveVia(c.via)
		if gotVia != c.wantVia || gotRelayVia != c.wantRelayVia {
			t.Errorf("resolveVia(%q) = (%q, %q), want (%q, %q)", c.via, gotVia, gotRelayVia, c.wantVia, c.wantRelayVia)
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
		{"escaping path", "a@example.com:../x", ViaRelay, "escapes"},
		// via 填一台 VPS 的 email 时(盲转发直连打洞): 不能是自己, 也不能和取件对象相同。
		{"via-vps is self", "a@example.com:x", "c@example.com", "own email"},
		{"via-vps equals target", "a@example.com:x", "a@example.com", "different subscriber"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := RecvFiles(base, c.recv, t.TempDir(), c.via, 1)
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
		err := RecvFiles(cfg, "a@example.com:x", t.TempDir(), ViaRelay, 1)
		if err == nil || !strings.Contains(err.Error(), "uuid") {
			t.Fatalf("uuid %q: want a uuid complaint, got %v", uuid, err)
		}
	}
}
