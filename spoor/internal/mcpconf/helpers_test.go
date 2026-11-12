package mcpconf

import (
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/classify"
)

const (
	base62 = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	upper  = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
)

// synth returns a deterministic high-entropy string. Test credentials are
// generated instead of written out so that no credential-shaped literal is
// committed, and so that they are provably not real.
func synth(seed string, n int, alphabet string) string {
	var x uint64 = 1469598103934665603
	for i := 0; i < len(seed); i++ {
		x = (x ^ uint64(seed[i])) * 1099511628211
	}
	out := make([]byte, n)
	for i := range out {
		x = x*6364136223846793005 + 1442695040888963407
		out[i] = alphabet[(x>>33)%uint64(len(alphabet))]
	}
	return string(out)
}

func synthGitHubPAT(seed string) string { return "ghp_" + synth(seed, 36, base62) }
func synthAWSKeyID(seed string) string  { return "AKIA" + synth(seed, 16, upper) }

// requireClassify skips tests whose expectation depends on the real secret
// scanner while internal/classify is still the bootstrap placeholder.
func requireClassify(t *testing.T) {
	t.Helper()
	if len(classify.FindSecrets("aws_access_key_id="+synthAWSKeyID("probe"))) == 0 {
		t.Skip("internal/classify.FindSecrets finds nothing for an AWS-shaped key: " +
			"classify is still the bootstrap placeholder, so inline-secret detection cannot be verified")
	}
}

func mustParse(t *testing.T, path, data string, f Format) []Server {
	t.Helper()
	ss, err := Parse(path, []byte(data), f)
	if err != nil {
		t.Fatalf("Parse(%s, %q): %v", path, f, err)
	}
	return ss
}

// index returns servers by "project|name" ("name" alone at user scope).
func index(t *testing.T, ss []Server) map[string]Server {
	t.Helper()
	m := make(map[string]Server, len(ss))
	for _, s := range ss {
		k := s.Name
		if s.Project != "" {
			k = s.Project + "|" + s.Name
		}
		if _, dup := m[k]; dup {
			t.Fatalf("duplicate server key %q", k)
		}
		m[k] = s
	}
	return m
}

func names(ss []Server) []string {
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = s.Name
	}
	return out
}

func sortedMapKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func eq(t *testing.T, what string, got, want any) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s:\n  got  %#v\n  want %#v", what, got, want)
	}
}

func hasFlag(flags []string, f string) bool {
	for _, x := range flags {
		if x == f {
			return true
		}
	}
	return false
}

func enabledString(b *bool) string {
	switch {
	case b == nil:
		return "unset"
	case *b:
		return "true"
	}
	return "false"
}

// stdio builds a server from a launch line, the way a config that writes the
// whole line into "command" would.
func stdio(line string) Server {
	return Server{Name: "t", Transport: "stdio", Command: line}
}

func contains(haystack string, needles ...string) string {
	for _, n := range needles {
		if n != "" && strings.Contains(haystack, n) {
			return n
		}
	}
	return ""
}
