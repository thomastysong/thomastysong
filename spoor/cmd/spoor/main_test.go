package main

import (
	"bytes"
	"context"
	"encoding/json"
	"math/rand"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// testApp is an app with captured output, a fixed environment and no
// network unless a test sets a client.
type testApp struct {
	*app
	out, errb *bytes.Buffer
	env       map[string]string
}

func newTestApp(t *testing.T) *testApp {
	t.Helper()
	out, errb := &bytes.Buffer{}, &bytes.Buffer{}
	env := map[string]string{}
	ta := &testApp{out: out, errb: errb, env: env}
	ta.app = &app{
		stdin:      strings.NewReader(""),
		stdout:     out,
		stderr:     errb,
		getenv:     func(k string) string { return env[k] },
		now:        time.Now,
		executable: func() (string, error) { return "/usr/bin/spoor", nil },
		ctx:        context.Background(),
		client:     &http.Client{Timeout: 5 * time.Second},
		// Unroutable by default: a test that forgets to point the
		// registries at a fake server fails instead of using the network.
		npmRegistry:  "http://127.0.0.1:1",
		pypiRegistry: "http://127.0.0.1:1",
	}
	return ta
}

// run runs one command line and returns its exit code.
func (ta *testApp) run(args ...string) int {
	ta.out.Reset()
	ta.errb.Reset()
	return ta.main(args)
}

func (ta *testApp) mustRun(t *testing.T, want int, args ...string) string {
	t.Helper()
	if got := ta.run(args...); got != want {
		t.Fatalf("spoor %s: exit %d, want %d\nstdout:\n%s\nstderr:\n%s", strings.Join(args, " "), got, want, clip(ta.out.String(), 4000), ta.errb.String())
	}
	return ta.out.String()
}

// testConfig writes a configuration rooted in a temporary data directory
// and returns its path and the data directory.
func testConfig(t *testing.T, extra string) (cfgPath, dataDir string) {
	t.Helper()
	dir := t.TempDir()
	dataDir = filepath.Join(dir, "data")
	cfgPath = filepath.Join(dir, "spoor.yaml")
	writeTestFile(t, cfgPath, "data_dir: "+dataDir+"\n"+extra, 0o644)
	return cfgPath, dataDir
}

func writeTestFile(t *testing.T, path, content string, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
}

// fakeToken builds a provider-shaped credential at run time, so that no
// credential-format literal is ever committed (push protection).
func fakeToken(prefix string, n int, seed int64) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"
	r := rand.New(rand.NewSource(seed))
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return prefix + string(b)
}

func decodeJSON(t *testing.T, s string, v any) {
	t.Helper()
	if err := json.Unmarshal([]byte(s), v); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, clip(s, 2000))
	}
}

func TestIsExtension(t *testing.T) {
	for _, tc := range []struct {
		argv []string
		want bool
	}{
		{[]string{"/usr/lib/spoor/spoor.ext", "--socket", "/var/osquery/osquery.em"}, true},
		{[]string{"/usr/lib/spoor/spoor.ext"}, true},
		{[]string{`C:\Program Files\spoor\spoor.ext.exe`}, true},
		{[]string{`C:\Program Files\spoor\SPOOR.EXT.EXE`, "--socket", `\\.\pipe\osquery.em`}, true},
		{[]string{"/usr/bin/spoor", "--socket", "/x", "--timeout", "3"}, true},
		{[]string{"/usr/bin/spoor", "--timeout=3", "--socket=/x"}, true},
		{[]string{"/usr/bin/spoor", "doctor", "--socket", "/x"}, false},
		{[]string{"/usr/bin/spoor", "hook", "--agent", "codex"}, false},
		{[]string{"/usr/bin/spoor"}, false},
		{[]string{"/usr/bin/spoor", "--help"}, false},
		{[]string{"/usr/bin/extract"}, false},
		{nil, false},
	} {
		if got := isExtension(tc.argv); got != tc.want {
			t.Errorf("isExtension(%q) = %v, want %v", tc.argv, got, tc.want)
		}
	}
}

func TestParseExtArgs(t *testing.T) {
	e := parseExtArgs([]string{"--socket", "/var/osquery/osquery.em", "--timeout", "3", "--interval=5", "--verbose", "--new-flag", "x"})
	if e.socket != "/var/osquery/osquery.em" || e.timeout != 3*time.Second || e.interval != 5*time.Second {
		t.Fatalf("got %+v", e)
	}
	// Hostile or odd values mean "osquery's default", never a panic.
	e = parseExtArgs([]string{"--timeout", "-4", "--interval", "999999", "--socket"})
	if e.timeout != 0 || e.interval != 0 || e.socket != "" {
		t.Fatalf("got %+v", e)
	}
}

func TestExtensionNeedsSocket(t *testing.T) {
	var b bytes.Buffer
	if code := runExtension([]string{"--timeout", "3"}, &b); code != exitUsage {
		t.Fatalf("exit %d", code)
	}
}

func TestUsageAndDispatch(t *testing.T) {
	ta := newTestApp(t)
	if code := ta.run(); code != exitUsage || !strings.Contains(ta.errb.String(), "Exit codes:") {
		t.Fatalf("no args: exit %d\n%s", code, ta.errb.String())
	}
	out := ta.mustRun(t, exitOK, "--help")
	for _, c := range []string{"run", "hook", "scan", "detect", "hooks", "rules", "bench", "doctor", "privacy", "export", "bundle", "catalog", "ci", "version", "licenses"} {
		if !strings.Contains(out, "  "+c+" ") {
			t.Errorf("help lacks command %q", c)
		}
	}
	if !strings.Contains(out, "3  detect, ci exec") {
		t.Error("help lacks the exit code table")
	}
	ta.mustRun(t, exitUsage, "frobnicate")
	ta.mustRun(t, exitUsage, "hooks")
	ta.mustRun(t, exitOK, "hooks", "--help")
	ta.mustRun(t, exitUsage, "hooks", "nope")
	out = ta.mustRun(t, exitOK, "help", "detect")
	if !strings.Contains(out, "--fail-on") {
		t.Errorf("help detect:\n%s", out)
	}
	ta.mustRun(t, exitOK, "detect", "--help")
	ta.mustRun(t, exitUsage, "detect", "--no-such-flag")
	ta.mustRun(t, exitOK, "help", "hook")
}

func TestParseInterspersed(t *testing.T) {
	ta := newTestApp(t)
	fs := ta.newFlags("x", "x", "")
	j := fs.Bool("json", false, "")
	n := fs.Int("n", 0, "")
	pos, code, done := ta.parse(fs, []string{"a", "--json", "b", "-n", "3", "--", "--json", "-x"})
	if done || code != 0 {
		t.Fatalf("done=%v code=%d", done, code)
	}
	if !*j || *n != 3 || strings.Join(pos, " ") != "a b --json -x" {
		t.Fatalf("json=%v n=%d pos=%q", *j, *n, pos)
	}
}

func TestVersion(t *testing.T) {
	ta := newTestApp(t)
	out := ta.mustRun(t, exitOK, "version")
	if !strings.HasPrefix(out, "spoor ") {
		t.Fatalf("version: %q", out)
	}
	var b buildInfo
	decodeJSON(t, ta.mustRun(t, exitOK, "version", "--json"), &b)
	if b.Version == "" || b.GoVersion == "" || b.OS == "" {
		t.Fatalf("version json: %+v", b)
	}
	if versionString() == "" {
		t.Fatal("empty version string")
	}
}

func TestLicenses(t *testing.T) {
	ta := newTestApp(t)
	out := ta.mustRun(t, exitOK, "licenses")
	if !strings.Contains(out, "Apache License 2.0") {
		t.Fatalf("licenses: %s", out)
	}
	var v struct {
		Spoor   string          `json:"spoor"`
		Modules []moduleLicense `json:"modules"`
	}
	decodeJSON(t, ta.mustRun(t, exitOK, "licenses", "--json"), &v)
	if v.Spoor != "Apache-2.0" {
		t.Fatalf("%+v", v)
	}
}
