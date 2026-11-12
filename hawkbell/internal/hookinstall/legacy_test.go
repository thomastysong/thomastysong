package hookinstall

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
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
// golden files verbatim. They must still be recognised as hawkbell's own, be
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
			// The detail says that hook commands lack the check only when a
			// command the agent runs on this OS differs.
			wantDetail := legacyDetail
			if sameRunFields(t, gc.agent, gc.goos, old[0].path, old[0].body, cur[0].body) {
				wantDetail = legacyRunsCurrent
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
				case s.Status != StatusModified || !strings.HasPrefix(s.Detail, wantDetail):
					t.Errorf("binary given=%v: want %s with the detail %q, got %+v", given, StatusModified, wantDetail, s)
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
				if s := stateOf(t, c, o, gc.agent); s.Status != StatusModified || strings.HasPrefix(s.Detail, legacyPrefix) {
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
			// nothing but hawkbell's entries.
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

// runKeyFor is the handler field an agent executes on goos, restated here
// from the vendor sources independently of dialectSpec.runKey: Codex runs
// commandWindows on Windows when it is present (codex-rs/hooks/src/engine/
// discovery.rs), Copilot CLI bash on unix and powershell on Windows, the
// others their single command field.
func runKeyFor(agent, goos string) string {
	switch {
	case agent == "codex" && goos == "windows":
		return "commandWindows"
	case agent == "copilot-cli" && goos == "windows":
		return "powershell"
	case agent == "copilot-cli":
		return "bash"
	}
	return "command"
}

// sameRunFields reports whether two renderings of one hook file give the
// agent the same commands to run on goos.
func sameRunFields(t *testing.T, agent, goos, path string, a, b []byte) bool {
	t.Helper()
	key := runKeyFor(agent, goos)
	vals := func(data []byte) []string {
		var out []string
		for _, f := range renderedFields(t, path, data) {
			if f.key == key {
				out = append(out, f.value+"\x00"+strings.Join(f.args, "\x00"))
			}
		}
		sort.Strings(out)
		return out
	}
	va, vb := vals(a), vals(b)
	return len(va) > 0 && slices.Equal(va, vb)
}

// TestLegacyCodexWindowsPlainPath: Codex on Windows runs commandWindows,
// which the release before the missing-binary check wrote exactly as it is
// written now for a path that needs no quoting (bare, so that cmd.exe can
// run it too). Only the POSIX "command" differs, so Status must not say
// that the hook commands fail when the binary is missing and that an
// install changes that: the field Codex runs stays the same after it.
func TestLegacyCodexWindowsPlainPath(t *testing.T) {
	c := testCatalog(t)
	gc := goldenCaseNamed(t, "codex-user-windows-plainpath")
	old := readGoldenParts(t, filepath.Join("testdata", "legacy", gc.name+".golden"))
	cur := readGoldenParts(t, filepath.Join("testdata", "golden", gc.name+".golden"))
	if !sameRunFields(t, gc.agent, gc.goos, old[0].path, old[0].body, cur[0].body) {
		t.Fatal("fixture: commandWindows differs between the releases")
	}
	if sameRunFields(t, gc.agent, "linux", old[0].path, old[0].body, cur[0].body) {
		t.Fatal("fixture: command does not differ between the releases")
	}
	for _, given := range []bool{true, false} {
		o := gc.options(t)
		if !given {
			o.Binary = ""
		}
		writeFile(t, filepath.Join(o.Root, filepath.FromSlash(old[0].path)), old[0].body, 0o644)
		s := stateOf(t, c, o, gc.agent)
		if s.Status != StatusModified || !strings.HasPrefix(s.Detail, legacyRunsCurrent) || strings.HasPrefix(s.Detail, legacyDetail) {
			t.Errorf("binary given=%v: %s %q", given, s.Status, s.Detail)
		}
	}
	o := gc.options(t)
	path := filepath.Join(o.Root, filepath.FromSlash(old[0].path))
	writeFile(t, path, old[0].body, 0o644)
	mustApply(t, []Plan{only(t, mustPlan(t, c, o), gc.agent)})
	if !sameRunFields(t, gc.agent, gc.goos, old[0].path, old[0].body, readBytes(t, path)) {
		t.Errorf("install changed what Codex runs on Windows:\n%s", readBytes(t, path))
	}
}

// TestLegacyDetailNamesWhatRuns renders what the release before the
// missing-binary check wrote for every agent, tier and OS, with a path
// that needs quoting and one that does not, and checks the Status detail:
// it says the hook commands lack the check exactly when a command the
// agent runs on that OS differs from what install writes now.
func TestLegacyDetailNamesWhatRuns(t *testing.T) {
	c := testCatalog(t)
	dialectOf := map[string]string{"codex": "codex", "copilot-cli": "copilot", "gemini-cli": "gemini", "cursor": "cursor"}
	var nOld, nCurrent int
	for agent, dialect := range dialectOf {
		for _, goos := range []string{"linux", "darwin", "windows"} {
			bins := []string{binFor(goos)}
			if goos == "windows" {
				bins = append(bins, `C:\hawkbell\hawkbell.exe`)
			}
			scopes := []event.Scope{event.ScopeManaged, event.ScopeUser}
			if agent == "codex" {
				scopes = append(scopes, event.ScopeSystem)
			}
			for _, bin := range bins {
				for _, sc := range scopes {
					where := agent + "/" + goos + "/" + string(sc) + " " + bin
					o := opts(t, goos, sc, agent)
					o.Binary = bin
					p := only(t, mustPlan(t, c, o), agent)
					if p.Action == ActionUnsupported {
						continue
					}
					if p.Action != ActionCreate {
						t.Fatalf("%s: action %s", where, p.Action)
					}
					render := func(legacy bool) []byte {
						es, ok := dialects[dialect].entries(params{binary: bin, agentID: agent, goos: goos, timeout: defaultTimeout, legacy: legacy})
						if !ok {
							t.Fatalf("%s: no entries", where)
						}
						switch {
						case strings.HasSuffix(p.Path, ".toml"):
							return []byte(hooksBlock(es, "\n"))
						case agent == "copilot-cli" || agent == "cursor":
							return newDocument(es, kindFlat, nil)
						}
						return newDocument(es, kindGroups, nil)
					}
					if cur := render(false); !bytes.Equal(cur, p.After) {
						t.Fatalf("%s: the test renders another file than install:\n%s\nwant\n%s", where, cur, p.After)
					}
					old := render(true)
					if bytes.Equal(old, p.After) {
						continue
					}
					writeFile(t, p.Path, old, 0o644)
					s := stateOf(t, c, o, agent)
					want := legacyDetail
					if sameRunFields(t, agent, goos, p.Path, old, p.After) {
						want = legacyRunsCurrent
						nCurrent++
					} else {
						nOld++
					}
					if s.Status != StatusModified || !strings.HasPrefix(s.Detail, want) {
						t.Errorf("%s: %s %q, want the detail %q", where, s.Status, s.Detail, want)
					}
				}
			}
		}
	}
	// Codex on Windows with a plain path, user, system and managed
	// (requirements.toml) tiers, is the case that runs current commands.
	if nCurrent < 3 || nOld == 0 {
		t.Errorf("coverage: %d current, %d older", nCurrent, nOld)
	}
}
