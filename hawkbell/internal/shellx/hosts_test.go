package shellx

import (
	"crypto/sha256"
	"encoding/hex"
	"regexp"
	"strings"
	"testing"

	"github.com/thomastysong/thomastysong/hawkbell/internal/classify"
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

// An authority longer than any host[:port] yields no host: it is a
// credential whose '@' was cut off (or padding), and its first label would
// otherwise be reported as the destination.
func TestURLHostOversizeAuthority(t *testing.T) {
	long := strings.Repeat("A", maxHostPort)
	cases := []struct{ in, want string }{
		{"https://deploy:" + long + "/x", ""},
		{"https://deploy:" + long, ""},
		{"https://u:" + long + "@git.example.com/x", "git.example.com"},
		{"https://git.example.com:443/x", "git.example.com"},
		{"https://" + strings.Repeat("a", 256) + ":1/", ""}, // fits host:port, but no name exceeds 255 bytes
		{"https://" + strings.Repeat("a", 240) + ".io:65535/", strings.Repeat("a", 240) + ".io"},
	}
	for _, c := range cases {
		if got := urlHost(c.in); got != c.want {
			t.Errorf("urlHost(%.40q...) = %q, want %q", c.in, got, c.want)
		}
	}
}

// The oversize authority is replaced whole by a classify-shaped marker, so
// privacy rewrites its fingerprint like any other.
func TestRedactUserinfoOversizeAuthority(t *testing.T) {
	tok := strings.Repeat("Zx81kPwm3RtY6vBn", 40)
	for _, in := range []string{
		"https://deploy:" + tok + "/org/repo.git",
		"https://deploy:" + tok,
		"https://u:p@" + tok + "/x",
	} {
		got := redactUserinfo(in)
		if strings.Contains(got, "Zx81kPwm3RtY6vBn") || !classifyMarker.MatchString(got) {
			t.Errorf("redactUserinfo(%.40q...) = %.80q", in, got)
		}
		if i := strings.Index(in[8:], "/"); i >= 0 && !strings.HasSuffix(got, in[8+i:]) {
			t.Errorf("path lost: %q", got)
		}
	}
}

// clipFact never leaves part of a marker: at every cut offset across one,
// the result holds the whole marker or none of it.
func TestClipFactKeepsMarkersWhole(t *testing.T) {
	marker := "[REDACTED:basic_auth_url:" + fp8("u:p") + "]"
	s := "https://" + strings.Repeat("h", 30) + marker + "@" + strings.Repeat("p", 60)
	start := strings.Index(s, marker)
	for n := 0; n <= len(s); n++ {
		got := clipFact(s, n)
		if len(got) > n || !strings.HasPrefix(s, got) {
			t.Fatalf("n=%d: %q is not a prefix of at most n bytes", n, got)
		}
		has := strings.Contains(got, marker)
		if k := strings.Index(got, "[REDACTED"); k >= 0 && !has {
			t.Fatalf("n=%d: partial marker %q", n, got[k:])
		}
		if n >= start+len(marker) && !has {
			t.Fatalf("n=%d: whole marker dropped", n)
		}
		if n > start && n < start+len(marker) && len(got) != start {
			t.Fatalf("n=%d: cut not moved to the marker start: %d", n, len(got))
		}
	}
	// Multi-byte runes are not split.
	if got := clipFact(strings.Repeat("é", 10), 5); got != "éé" {
		t.Fatalf("clipFact split a rune: %q", got)
	}
}

// A URL whose marker sits past the 2 KiB fact cap (an absurdly long
// scheme-like prefix handed to curl) does not leave a partial marker.
func TestURLFactLongPrefixNoPartialMarker(t *testing.T) {
	for pad := 2000; pad <= 2048; pad++ {
		cmd := "curl https" + strings.Repeat("s", pad) + "://u:Zx81kPwm3RtY6vBn@h.example/x"
		for _, u := range Analyze(cmd, "").URLs {
			if k := strings.Index(u, "[REDACTED"); k >= 0 && !classifyMarker.MatchString(u[k:]) {
				t.Fatalf("pad=%d: partial marker %q", pad, u[k:])
			}
			if strings.Contains(u, "Zx81kPwm3RtY6vBn") {
				t.Fatalf("pad=%d: credential in %q", pad, u[len(u)-40:])
			}
		}
	}
}
