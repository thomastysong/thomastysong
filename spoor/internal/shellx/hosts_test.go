package shellx

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/classify"
)

// classifyMarker is the shape package privacy recognises and rewrites
// (privacy.classifyMarkers): upper-case REDACTED, a kind of [a-z0-9_], and
// exactly eight lower-case hex digits.
var classifyMarker = regexp.MustCompile(`\[REDACTED:[a-z0-9_]{1,64}:[0-9a-f]{8}\]`)

func fp8(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:4])
}

func TestRedactUserinfo(t *testing.T) {
	tok := "Zx81kPwm" + "3RtY6vBn"
	cases := []struct {
		in, want string
	}{
		{"https://deploy:" + tok + "@git.example.com/org/repo.git",
			"https://[REDACTED:basic_auth_url:" + fp8("deploy:"+tok) + "]@git.example.com/org/repo.git"},
		// A long user part alone is a token (GitHub's x-access-token style).
		{"https://" + tok + tok + "@h.example/x",
			"https://[REDACTED:basic_auth_url:" + fp8(tok+tok) + "]@h.example/x"},
		// Bare short user names carry no secret.
		{"ssh://git@github.com/o/r.git", "ssh://git@github.com/o/r.git"},
		// '@' after the authority is path, not userinfo.
		{"https://h.example/a@b", "https://h.example/a@b"},
		{"https://h.example/?u=a:b@c", "https://h.example/?u=a:b@c"},
		{"no scheme user:pw@host", "no scheme user:pw@host"},
		{"https://@h.example/", "https://@h.example/"},
	}
	for _, c := range cases {
		got := redactUserinfo(c.in)
		if got != c.want {
			t.Errorf("redactUserinfo(%q)\n got %q\nwant %q", c.in, got, c.want)
		}
		if strings.Contains(got, "[redacted:") {
			t.Errorf("%q: lower-case marker, which privacy would not rewrite", got)
		}
		if got != c.in && (!classifyMarker.MatchString(got) || strings.Contains(got, tok)) {
			t.Errorf("%q: not a classify-shaped marker or the secret survived", got)
		}
	}
}

// The marker must stay byte-identical to classify's, because that is the
// shape privacy rewrites; drift here would ship an unkeyed fingerprint.
func TestUserinfoMarkerMatchesClassify(t *testing.T) {
	if userinfoKind != classify.KindBasicAuthURL {
		t.Fatalf("userinfoKind %q, classify uses %q", userinfoKind, classify.KindBasicAuthURL)
	}
	for _, u := range []string{
		"https://deploy:" + "Zx81kPwm3RtY6vBn" + "@git.example.com/org/repo.git",
		"https://" + strings.Repeat("Ab3", 10) + "@h.example/x",
		"ftp://user:p%40ss@files.example/",
	} {
		want := classify.RedactArgs([]string{u})
		if got := redactUserinfo(u); len(want) != 1 || got != want[0] {
			t.Errorf("%q: shellx %q, classify %q", u, got, want)
		}
	}
}

func TestFactsCarryClassifyMarker(t *testing.T) {
	tok := "Zx81kPwm" + "3RtY6vBn"
	f := Analyze("git clone https://deploy:"+tok+"@git.example.com/org/repo.git", "")
	if len(f.URLs) != 1 || !classifyMarker.MatchString(f.URLs[0]) || strings.Contains(f.URLs[0], tok) {
		t.Fatalf("urls %q", f.URLs)
	}
	if len(f.Hosts) != 1 || f.Hosts[0] != "git.example.com" {
		t.Fatalf("hosts %q", f.Hosts)
	}
}
