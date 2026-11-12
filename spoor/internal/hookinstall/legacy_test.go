package hookinstall

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
)

// goldenPart is one file of a file in the golden format.
type goldenPart struct {
	path string // slash path under Options.Root
	body []byte
}

func readGoldenParts(t *testing.T, file string) []goldenPart {
	t.Helper()
	data, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	var out []goldenPart
	for _, part := range strings.Split(string(data), "# ----\n") {
		if strings.TrimSpace(part) == "" {
			continue
		}
		var gp goldenPart
		var body strings.Builder
		for _, line := range strings.SplitAfter(part, "\n") {
			switch {
			case strings.HasPrefix(line, "# path: "):
				gp.path = strings.TrimSpace(strings.TrimPrefix(line, "# path: "))
			case strings.HasPrefix(line, "# agent: "), strings.HasPrefix(line, "# scope: "), strings.HasPrefix(line, "# action: "):
			default:
				body.WriteString(line)
			}
		}
		gp.body = []byte(body.String())
		out = append(out, gp)
	}
	return out
}

func goldenCaseNamed(t *testing.T, name string) goldenCase {
	t.Helper()
	for _, gc := range goldenCases() {
		if gc.name == name {
			return gc
		}
	}
	t.Fatalf("no golden case %q", name)
	return goldenCase{}
}

func (gc goldenCase) options(t *testing.T) Options {
	o := opts(t, gc.goos, gc.scope, gc.agent)
	o.Binary = gc.binary
	if gc.mutate != nil {
		gc.mutate(&o)
	}
	return o
}

// TestLegacyEntries works on files exactly as the release before the
// missing-binary guard wrote them: testdata/legacy holds that release's
// golden files verbatim. They must still be recognised as spoor's own, be
// reported as older rather than tampered with, be upgraded by install and
// be removed by uninstall.
func TestLegacyEntries(t *testing.T) {
	c := testCatalog(t)
	files, err := filepath.Glob(filepath.Join("testdata", "legacy", "*.golden"))
	if err != nil || len(files) == 0 {
		t.Fatalf("no legacy fixtures: %v", err)
	}
	for _, f := range files {
		name := strings.TrimSuffix(filepath.Base(f), ".golden")
		t.Run(name, func(t *testing.T) {
			gc := goldenCaseNamed(t, name)
			old := readGoldenParts(t, f)
			cur := readGoldenParts(t, filepath.Join("testdata", "golden", name+".golden"))
			if len(old) != 1 || len(cur) != 1 || old[0].path != cur[0].path {
				t.Fatalf("fixture shape: %d old, %d current parts", len(old), len(cur))
			}
			// A Windows path cmd.exe can read unquoted is written bare in
			// both releases; such a file is simply current.
			unchanged := bytes.Equal(old[0].body, cur[0].body)
			installed := StatusUser
			if gc.scope != event.ScopeUser {
				installed = StatusManaged
			}
			place := func(o Options) string {
				p := filepath.Join(o.Root, filepath.FromSlash(old[0].path))
				writeFile(t, p, old[0].body, 0o644)
				return p
			}

			// Status, with the binary given and with the binary read from
			// the old entries.
			for _, given := range []bool{true, false} {
				o := gc.options(t)
				if !given {
					o.Binary = ""
				}
				place(o)
				s := stateOf(t, c, o, gc.agent)
				switch {
				case unchanged:
					if s.Status != installed {
						t.Errorf("binary given=%v: %+v", given, s)
					}
				case s.Status != StatusModified || !strings.HasPrefix(s.Detail, legacyDetail):
					t.Errorf("binary given=%v: want %s with the legacy detail, got %+v", given, StatusModified, s)
				}
			}
			// The same file with one entry changed by hand is tampering, not
			// an older release.
			if !unchanged {
				o := gc.options(t)
				p := place(o)
				data := readBytes(t, p)
				i := bytes.LastIndex(data, []byte(hookMarker+gc.agent))
				if i < 0 {
					t.Fatalf("no marker in fixture")
				}
				writeFile(t, p, append(append(append([]byte{}, data[:i]...), " --debug"...), data[i:]...), 0o644)
				if s := stateOf(t, c, o, gc.agent); s.Status != StatusModified || strings.HasPrefix(s.Detail, legacyDetail) {
					t.Errorf("hand-edited old entry: %+v", s)
				}
			}

			// Install replaces the old entries with the current ones.
			o := gc.options(t)
			path := place(o)
			p := only(t, mustPlan(t, c, o), gc.agent)
			if unchanged {
				if p.Action != ActionUnchanged {
					t.Fatalf("current file: action %s (%s)", p.Action, p.Note)
				}
			} else {
				if p.Action != ActionMerge && p.Action != ActionAppend {
					t.Fatalf("upgrade: action %s (%s)", p.Action, p.Note)
				}
				// A merge keeps the file's own layout, so only the TOML block,
				// which is rewritten whole, can be compared byte for byte.
				if strings.HasSuffix(path, ".toml") && !bytes.Equal(p.After, cur[0].body) {
					t.Errorf("upgraded block is not what a fresh install writes:\n%s", p.After)
				}
				mustApply(t, []Plan{p})
			}
			if s := stateOf(t, c, o, gc.agent); s.Status != installed {
				t.Errorf("after upgrade: %+v", s)
			}
			if again := only(t, mustPlan(t, c, o), gc.agent); again.Action != ActionUnchanged {
				t.Errorf("second install: %s (%s)", again.Action, again.Note)
			}

			// Uninstall straight from the old file removes it: it holds
			// nothing but spoor's entries.
			o = gc.options(t)
			path = place(o)
			u := only(t, mustUnplan(t, c, o), gc.agent)
			if u.Action != ActionRemove {
				t.Fatalf("uninstall: action %s (%s)", u.Action, u.Note)
			}
			mustApply(t, []Plan{u})
			if exists(path) {
				t.Errorf("%s still exists after uninstall", path)
			}
		})
	}
}

// TestLegacyUninstallKeepsForeignHooks adds the old entries to a file with
// somebody else's hooks the way the previous release did, and checks that
// uninstall gives the original bytes back.
func TestLegacyUninstallKeepsForeignHooks(t *testing.T) {
	c := testCatalog(t)
	cases := []struct {
		agent, goos, dialect string
		kind                 fileKind
		foreign              string
	}{
		{"copilot-cli", "linux", "copilot", kindFlat,
			"{\n  \"version\": 1,\n  \"hooks\": {\n    \"preToolUse\": [\n      {\"type\": \"command\", \"bash\": \"./check.sh\", \"powershell\": \"./check.ps1\"}\n    ]\n  },\n  \"x-note\": \"kept\"\n}\n"},
		{"gemini-cli", "windows", "gemini", kindGroups,
			"{\"ui\": {\"theme\": \"dark\"}, \"hooks\": {\"BeforeTool\": [{\"matcher\": \"run_shell_command\", \"hooks\": [{\"type\": \"command\", \"command\": \"lint.cmd\"}]}]}}\n"},
		{"codex", "windows", "codex", kindGroups,
			"{\n\t\"hooks\": {\n\t\t\"Stop\": [{\"hooks\": [{\"type\": \"command\", \"command\": \"say done\"}]}]\n\t}\n}\n"},
		{"cursor", "linux", "cursor", kindFlat,
			"{\"version\":1,\"hooks\":{\"stop\":[{\"command\":\"./audit.sh\"}]}}"},
	}
	for _, tc := range cases {
		t.Run(tc.agent+"-"+tc.goos, func(t *testing.T) {
			o := opts(t, tc.goos, event.ScopeUser, tc.agent)
			want, ok := dialects[tc.dialect].entries(params{
				binary: o.Binary, agentID: tc.agent, goos: tc.goos,
				timeout: defaultTimeout, legacy: true,
			})
			if !ok {
				t.Fatal("no entries")
			}
			for i := range want {
				for _, l := range commandLines(nodeOf(t, want[i].handler)) {
					if strings.Contains(l, posixGuardHead) || strings.Contains(l, pwshGuardHead) {
						t.Fatalf("legacy rendering carries a guard: %s", l)
					}
				}
			}
			mixed, err := addEntries([]byte(tc.foreign), want, tc.kind)
			if err != nil {
				t.Fatal(err)
			}
			path := targetPath(t, c, o, tc.agent)
			writeFile(t, path, mixed, 0o644)
			s := stateOf(t, c, o, tc.agent)
			if s.Status != StatusModified || !strings.HasPrefix(s.Detail, legacyDetail) {
				t.Errorf("status of old entries beside foreign ones: %+v", s)
			}
			u := only(t, mustUnplan(t, c, o), tc.agent)
			if u.Action != ActionMerge || !bytes.Equal(u.After, []byte(tc.foreign)) {
				t.Fatalf("uninstall %s:\n%s\nwant\n%s", u.Action, u.After, tc.foreign)
			}
		})
	}
}

// nodeOf parses a rendered handler the way a hook file is read.
func nodeOf(t *testing.T, h jobj) *node {
	t.Helper()
	d, err := parseJSON(newDocument([]entry{{event: "X", handler: h}}, kindFlat, nil))
	if err != nil {
		t.Fatal(err)
	}
	sc := scanHooks(d, kindFlat)
	if len(sc.handlers) != 1 {
		t.Fatalf("%d handlers", len(sc.handlers))
	}
	return sc.handlers[0].node
}
