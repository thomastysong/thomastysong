package procmon

import (
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/platform"
)

func TestEmitArgs(t *testing.T) {
	const pw = "Zq7RbV2mKx9TwL4p"
	many := []string{"codex"}
	for i := 0; i < 200; i++ {
		many = append(many, "--add-dir=/srv/x")
	}
	// A secret-named flag at the last kept position: its value is the
	// first dropped argument and must still be seen as its value.
	edge := []string{"tool"}
	for len(edge) < maxEventArgs-2 {
		edge = append(edge, "x")
	}
	edge = append(edge, "--password", pw, "y", "z")
	// A 3000-byte key (a repeated letter would read as a placeholder).
	key := strings.Repeat("9fK2xQ7mW4", 300)
	big := []string{"claude", "--settings", `{"apiKey":"` + key + `"}`}
	readerFull := []string{"node", "x.js", strings.Repeat("a", maxCmdlineBytes-20) + `--password=` + pw[:4]}
	tests := []struct {
		name     string
		in       []string
		cut      bool
		maxLen   int
		lastMark bool
		check    func(t *testing.T, out []string)
	}{
		{name: "nil", in: nil},
		{name: "short", in: []string{"claude", "-p", "hi"}, maxLen: 3},
		{name: "redacted", in: []string{"curl", "--password", pw}, maxLen: 3, check: func(t *testing.T, out []string) {
			if !strings.HasPrefix(out[2], "[REDACTED:") {
				t.Errorf("not redacted: %q", out)
			}
		}},
		{name: "count", in: many, cut: true, maxLen: maxEventArgs, lastMark: true},
		{name: "secret at the edge", in: edge, cut: true, maxLen: maxEventArgs, lastMark: true},
		{name: "big json", in: big, maxLen: 3, check: func(t *testing.T, out []string) {
			if strings.Contains(out[2], key[:8]) || !strings.HasPrefix(out[2], `{"apiKey":"[REDACTED:`) {
				t.Errorf("value = %q", out[2])
			}
		}},
		{name: "reader limit", in: readerFull, cut: true, maxLen: 3, lastMark: true, check: func(t *testing.T, out []string) {
			if strings.Contains(strings.Join(out, " "), "aaaa") {
				t.Errorf("the argument cut by the read limit was emitted")
			}
		}},
	}
	for _, tc := range tests {
		out, cut := emitArgs(tc.in)
		if cut != tc.cut || len(out) > tc.maxLen && tc.maxLen > 0 {
			t.Errorf("%s: cut=%v len=%d", tc.name, cut, len(out))
		}
		total := 0
		for _, a := range out {
			if len(a) > maxEventArgBytes {
				t.Errorf("%s: argument of %d bytes", tc.name, len(a))
			}
			total += len(a)
		}
		if total > maxEventArgsSum {
			t.Errorf("%s: %d bytes in all", tc.name, total)
		}
		if strings.Contains(strings.Join(out, " "), pw) {
			t.Errorf("%s: secret emitted: %q", tc.name, out)
		}
		if tc.lastMark && (len(out) == 0 || !strings.HasPrefix(out[len(out)-1], "[TRUNCATED:")) {
			t.Errorf("%s: no placeholder for dropped arguments: %q", tc.name, out)
		}
		if tc.check != nil && len(out) > 0 {
			tc.check(t, out)
		}
	}
	// The size budget: many 1 KiB arguments.
	wide := []string{"x"}
	for i := 0; i < 20; i++ {
		wide = append(wide, strings.Repeat("w", 1000))
	}
	out, cut := emitArgs(wide)
	total := 0
	for _, a := range out {
		total += len(a)
	}
	if !cut || total > maxEventArgsSum || !strings.HasPrefix(out[len(out)-1], "[TRUNCATED:") {
		t.Errorf("size budget: cut=%v total=%d last=%q", cut, total, out[len(out)-1])
	}
}

func TestCutValue(t *testing.T) {
	marker := "[REDACTED:github_pat:406d6600]"
	s := strings.Repeat("a", 90) + marker + strings.Repeat("b", 100)
	for max := 20; max < len(s); max++ {
		got := cutValue(s, max)
		if len(got) > max {
			t.Fatalf("max %d: %d bytes", max, len(got))
		}
		if !strings.HasSuffix(got, "B]") || !strings.Contains(got, "[TRUNCATED:") {
			t.Fatalf("max %d: no marker: %q", max, got)
		}
		body := got[:strings.LastIndex(got, "[TRUNCATED:")]
		if i := strings.Index(body, "[RED"); i >= 0 && !strings.HasSuffix(body[i:], marker) && !strings.Contains(body[i:], marker) {
			t.Fatalf("max %d: marker split: %q", max, body[i:])
		}
	}
	if got := cutValue("héllo wörld", 9); len(got) > 9 && !strings.Contains(got, "[TRUNCATED:") {
		t.Errorf("rune cut = %q", got)
	}
	if got := cutValue("short", 10); got != "short" {
		t.Errorf("uncut = %q", got)
	}
	// A rune is never split.
	got := cutValue(strings.Repeat("é", 40), 30)
	if !strings.HasPrefix(got, "é") || strings.ContainsRune(got[:strings.Index(got, "[")], '�') {
		t.Errorf("rune cut = %q", got)
	}
}

func TestEmitName(t *testing.T) {
	const pw = "Zq7RbV2mKx9TwL4p"
	for in, want := range map[string]string{
		"node":                              "node",
		"npm install":                       "npm install",
		"npm exec @openai/codex --yolo":     "npm exec @openai/codex --yolo",
		"Code Helper (Plugin)":              "Code Helper (Plugin)",
		"":                                  "",
		"deploy --password=" + pw:           "deploy --password=[REDACTED:",
		"mysql -p" + pw + " db":             "mysql -p[REDACTED:",
		"x --token " + canaryToken + " y z": "x --token [REDACTED:",
		canaryToken:                         "[REDACTED:",
	} {
		got := emitName(in)
		if !strings.HasPrefix(got, want) || strings.Contains(got, pw) || strings.Contains(got, canaryToken) {
			t.Errorf("emitName(%q) = %q, want prefix %q", in, got, want)
		}
	}
	long := strings.Repeat("--password=x ", 60)
	if got := emitName(long); len(got) > maxNameBytes || !isCutName(got) {
		t.Errorf("long name: %d bytes %q", len(got), got)
	}
}

func TestRanExec(t *testing.T) {
	tests := []struct {
		name           string
		comm           string
		args           []string
		oldExe, curExe string
		want           bool
	}{
		{"npm title", "npm install", []string{"npm install"}, "/usr/bin/node", "/usr/bin/node", false},
		{"single-word title", "gemini", []string{"gemini"}, "/usr/bin/node", "/usr/bin/node", false},
		{"postgres title", "postgres: chec", []string{"postgres: checkpointer"}, "/usr/lib/postgresql/16/bin/postgres", "/usr/lib/postgresql/16/bin/postgres", false},
		{"different program", "git", []string{"git", "push"}, "/usr/bin/bash", "/usr/bin/git", true},
		{"same program again", "node", []string{"node", "b.js"}, "/usr/bin/node", "/usr/bin/node", true},
		{"script under the same interpreter", "build.sh", []string{"/bin/bash", "./build.sh"}, "/usr/bin/bash", "/usr/bin/bash", true},
		{"long script name", "a-very-long-scr", []string{"/bin/sh", "/x/a-very-long-script.sh"}, "/usr/bin/dash", "/usr/bin/dash", true},
		{"updated binary renamed", "claude-worker", []string{"claude-worker"}, "/usr/local/bin/claude (deleted)", "/usr/local/bin/claude", false},
		{"updated binary run again", "claude", []string{"claude"}, "/usr/local/bin/claude (deleted)", "/usr/local/bin/claude", true},
		{"unknown old exe", "x", []string{"x"}, "", "/usr/bin/x", true},
		{"unknown new exe", "x", []string{"x"}, "/usr/bin/y", "", true},
	}
	for _, tc := range tests {
		if got := ranExec(tc.comm, tc.args, tc.oldExe, tc.curExe); got != tc.want {
			t.Errorf("%s: ranExec = %v", tc.name, got)
		}
	}
}

func TestIsCanary(t *testing.T) {
	m := New(Options{Catalog: loadCatalog(t), NoOsquery: true})
	m.canaryParent = 7
	nonce := canaryPrefix + "00112233aabbccdd"
	rec := func(pid, ppid int, args ...string) *platform.Proc {
		return &platform.Proc{PID: pid, PPID: ppid, Args: args}
	}
	set := func(c canaryState) {
		m.mu.Lock()
		m.can = c
		m.mu.Unlock()
	}
	set(canaryState{pending: true, nonce: nonce})
	if !m.isCanary(rec(50, 7, "/usr/bin/true", nonce)) {
		t.Error("pending canary, pid not known yet: not recognised")
	}
	if m.isCanary(rec(51, 40, "sh", "-c", "x", nonce)) {
		t.Error("a process with another parent was taken for the canary")
	}
	if m.isCanary(rec(52, 7, "/usr/bin/true")) {
		t.Error("a child of the monitor without the nonce was taken for the canary")
	}
	set(canaryState{pending: true, nonce: nonce, pid: 50})
	if !m.isCanary(rec(50, 7, "/usr/bin/true", nonce)) || m.isCanary(rec(53, 7, "/usr/bin/true", nonce)) {
		t.Error("pid check")
	}
	set(canaryState{nonce: nonce, pid: 50}) // settled
	if m.isCanary(rec(50, 7, "/usr/bin/true", nonce)) {
		t.Error("a settled self-test still hides processes")
	}
	// osquery's view of the canary needs the parent too.
	set(canaryState{pending: true, nonce: nonce, pid: 50})
	if a, _, ok := m.osqAttribute(50, 7); !ok || a != canaryAgent {
		t.Errorf("osquery canary row = %q %v", a, ok)
	}
	if a, _, _ := m.osqAttribute(50, 40); a == canaryAgent {
		t.Error("an osquery row with another parent was taken for the canary")
	}
}

func TestArgsDigestIgnoresFingerprints(t *testing.T) {
	a := []string{"curl", "-H", "Authorization: Bearer [REDACTED:bearer:11111111]", "[REDACTED:github_pat:2222aaaa]x"}
	b := []string{"curl", "-H", "Authorization: Bearer [REDACTED:bearer:99999999]", "[REDACTED:github_pat:3333bbbb]x"}
	k := argsKey()
	if argsDigest(k, a) != argsDigest(k, b) {
		t.Error("the event id depends on the secrets' fingerprints")
	}
	if argsDigest(k, a) == argsDigest(k, []string{"curl"}) {
		t.Error("digest ignores the arguments")
	}
	for in, want := range map[string]string{
		"x [REDACTED:password:f52fbd32] y": "x [REDACTED:password] y",
		"[REDACTED:kind]":                  "[REDACTED:kind]",
		"[REDACTED:unterminated":           "[REDACTED:unterminated",
		"plain":                            "plain",
		"[REDACTED:a:1][REDACTED:b:2]":     "[REDACTED:a][REDACTED:b]",
	} {
		if got := stripFingerprints(in); got != want {
			t.Errorf("stripFingerprints(%q) = %q", in, got)
		}
	}
}
