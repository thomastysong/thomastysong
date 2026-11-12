package bench

import (
	"bytes"
	"testing"
)

func TestRewriteOldName(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"ls /etc/spoor/disabled; SPOOR_OUTBOX=1 Spoor", "ls /etc/hawkbell/disabled; HAWKBELL_OUTBOX=1 Hawkbell"},
		// The rule-id prefix only at an identifier boundary.
		{"SPR-EXEC-001 xSPR-EXEC-001 _SPR-1 -SPR-2 SPR-SPR-", "HB-EXEC-001 xSPR-EXEC-001 _SPR-1 -HB-2 HB-HB-"},
		// Globs only as whole tokens.
		{"/etc/[s]poor /etc/[sx]poor x[s]poor [s]poorx [s]poor[ [s]poor?", "/etc/[h]awkbell /etc/[hx]awkbell x[s]poor [s]poorx [s]poor[ [s]poor?"},
		{"/etc/[s][p]oo[r]/a /etc/[s][p]oor spoo[r] spo?r sp?or sp*r sp* sp*x spx", "/etc/[h][a]wkbel[l]/a /etc/[h][a]wkbell hawkbel[l] haw?bell ha?kbell ha*l ha* sp*x spx"},
		{"github.com/thomastysong/spoor/internal/rules https://github.com/thomastysong/spoor/security/advisories/new",
			"github.com/thomastysong/thomastysong/hawkbell/internal/rules https://github.com/thomastysong/thomastysong/security/advisories/new"},
		{"magic SPRNC1 cache", "magic HBNC1 cache"},
		// Raw JSON text: the byte before SPR- in "\nSPR-" is "n".
		{`\nSPR-EXEC-001 éspoor caféSPR-1`, `\nSPR-EXEC-001 éhawkbell caféHB-1`},
		{"no old name here", "no old name here"},
		{"", ""},
	} {
		if got := RewriteOldNameString(tc.in); got != tc.want {
			t.Errorf("RewriteOldName(%q)\n got %q\nwant %q", tc.in, got, tc.want)
		}
	}
	// Unchanged input is returned as is; changed input is not modified.
	in := []byte("nothing to do")
	if out := RewriteOldName(in); &out[0] != &in[0] {
		t.Error("unchanged input was copied")
	}
	in = []byte("/etc/spoor SPR-X-001 [s]poor")
	keep := append([]byte(nil), in...)
	RewriteOldName(in)
	if !bytes.Equal(in, keep) {
		t.Errorf("input modified: %q", in)
	}
	// Invalid UTF-8 passes through.
	if got := RewriteOldName([]byte("\xffspoor\xfe")); string(got) != "\xffhawkbell\xfe" {
		t.Errorf("non-UTF-8: %q", got)
	}
}
