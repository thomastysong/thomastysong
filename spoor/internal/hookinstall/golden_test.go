package hookinstall

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
)

var update = flag.Bool("update", false, "rewrite the golden files under testdata/golden")

// goldenCase is one rendered hook file.
type goldenCase struct {
	name   string
	agent  string
	scope  event.Scope
	goos   string
	binary string
	mutate func(*Options)
}

func goldenCases() []goldenCase {
	var out []goldenCase
	agents := []string{"claude-code", "codex", "copilot-cli", "gemini-cli", "cursor"}
	for _, a := range agents {
		for _, sc := range []event.Scope{event.ScopeManaged, event.ScopeUser} {
			for _, goos := range []string{"linux", "darwin", "windows"} {
				out = append(out, goldenCase{
					name:  fmt.Sprintf("%s-%s-%s", a, sc, goos),
					agent: a, scope: sc, goos: goos, binary: binFor(goos),
				})
			}
		}
	}
	// Codex has a third, non-policy machine tier.
	for _, goos := range []string{"linux", "windows"} {
		out = append(out, goldenCase{name: "codex-system-" + goos, agent: "codex", scope: event.ScopeSystem, goos: goos, binary: binFor(goos)})
	}
	// Shell variants: a path without spaces is written bare for the
	// Windows fields that may meet cmd.exe; quotes inside a path must
	// survive every shell's quoting rules.
	for _, a := range []string{"codex", "copilot-cli", "gemini-cli", "cursor"} {
		out = append(out,
			goldenCase{name: a + "-user-windows-plainpath", agent: a, scope: event.ScopeUser, goos: "windows", binary: `C:\spoor\spoor.exe`},
			goldenCase{name: a + "-user-windows-quote", agent: a, scope: event.ScopeUser, goos: "windows", binary: `C:\Users\O'Brien Tools\spoor.exe`},
			goldenCase{name: a + "-user-linux-quote", agent: a, scope: event.ScopeUser, goos: "linux", binary: "/opt/O'Brien Tools/spoor"},
		)
	}
	out = append(out,
		goldenCase{name: "claude-code-user-linux-quote", agent: "claude-code", scope: event.ScopeUser, goos: "linux", binary: "/opt/O'Brien Tools/spoor"},
		goldenCase{name: "claude-code-managed-linux-guard-failclosed", agent: "claude-code", scope: event.ScopeManaged, goos: "linux", binary: unixBin,
			mutate: func(o *Options) { o.Guard, o.FailClosed = true, true }},
		goldenCase{name: "cursor-managed-linux-guard-failclosed", agent: "cursor", scope: event.ScopeManaged, goos: "linux", binary: unixBin,
			mutate: func(o *Options) { o.Guard, o.FailClosed = true, true }},
		goldenCase{name: "claude-code-managed-linux-otel", agent: "claude-code", scope: event.ScopeManaged, goos: "linux", binary: unixBin,
			mutate: func(o *Options) { o.OTel = "http://127.0.0.1:4319" }},
		goldenCase{name: "gemini-cli-user-linux-otel", agent: "gemini-cli", scope: event.ScopeUser, goos: "linux", binary: unixBin,
			mutate: func(o *Options) { o.OTel = "http://127.0.0.1:4319/v1/logs" }},
		goldenCase{name: "claude-code-user-linux-timeout30", agent: "claude-code", scope: event.ScopeUser, goos: "linux", binary: unixBin,
			mutate: func(o *Options) { o.Timeout = 30 }},
	)
	return out
}

// TestGolden renders every (agent, scope, OS, shell variant) on an empty
// machine and compares the files with testdata/golden. Run with -update
// after an intended format change and review the diff.
func TestGolden(t *testing.T) {
	c := testCatalog(t)
	for _, gc := range goldenCases() {
		t.Run(gc.name, func(t *testing.T) {
			o := opts(t, gc.goos, gc.scope, gc.agent)
			o.Binary = gc.binary
			if gc.mutate != nil {
				gc.mutate(&o)
			}
			plans := mustPlan(t, c, o)
			var b bytes.Buffer
			for _, p := range plans {
				if p.Action == ActionUnsupported {
					t.Fatalf("unsupported: %s", p.Note)
				}
				rel := filepath.ToSlash(strings.TrimPrefix(p.Path, o.Root))
				fmt.Fprintf(&b, "# agent: %s\n# scope: %s\n# path: %s\n# action: %s\n", p.AgentID, p.Scope, rel, p.Action)
				b.Write(p.After)
				b.WriteString("# ----\n")
			}
			path := filepath.Join("testdata", "golden", gc.name+".golden")
			if *update {
				if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
				return
			}
			want, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("missing golden file (run with -update): %v", err)
			}
			if !bytes.Equal(b.Bytes(), want) {
				t.Errorf("%s differs from the golden file\n--- got ---\n%s", path, b.String())
			}
		})
	}
}

// TestGoldenFilesParse checks that every golden file is valid in the
// format the agent reads, independently of this package's own parser.
func TestGoldenFilesParse(t *testing.T) {
	files, err := filepath.Glob(filepath.Join("testdata", "golden", "*.golden"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no golden files: %v", err)
	}
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, part := range strings.Split(string(data), "# ----\n") {
			if strings.TrimSpace(part) == "" {
				continue
			}
			var path string
			var body strings.Builder
			for _, line := range strings.SplitAfter(part, "\n") {
				if strings.HasPrefix(line, "# path: ") {
					path = strings.TrimSpace(strings.TrimPrefix(line, "# path: "))
					continue
				}
				if strings.HasPrefix(line, "# agent: ") || strings.HasPrefix(line, "# scope: ") || strings.HasPrefix(line, "# action: ") {
					continue
				}
				body.WriteString(line)
			}
			if err := checkContent(filepath.Base(path), []byte(body.String()), nil); err != nil {
				t.Errorf("%s (%s): %v", f, path, err)
			}
			if strings.HasSuffix(path, ".json") && !json.Valid([]byte(body.String())) {
				t.Errorf("%s (%s): encoding/json rejects it", f, path)
			}
		}
	}
}
