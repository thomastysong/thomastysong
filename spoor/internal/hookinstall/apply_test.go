package hookinstall

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
)

func TestApplyCreateMergeBackup(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeUser, "gemini-cli")
	path := targetPath(t, c, o, "gemini-cli")
	if exists(filepath.Dir(path)) {
		t.Fatal("fixture: directory should not exist yet")
	}
	plans := mustPlan(t, c, o)
	mustApply(t, plans)
	if got := readBytes(t, path); !bytes.Equal(got, plans[0].After) {
		t.Fatal("written bytes differ from the plan")
	}
	if b := backups(t, filepath.Dir(path)); len(b) != 0 {
		t.Errorf("a created file needs no backup: %v", b)
	}
	if l := leftovers(t, filepath.Dir(path)); len(l) != 0 {
		t.Errorf("temporary files left: %v", l)
	}

	// The owner edits the file; a reinstall with a new timeout merges and
	// keeps the previous version.
	edited := bytes.Replace(readBytes(t, path), []byte("{\n"), []byte("{\n  \"theme\": \"dark\",\n"), 1)
	writeFile(t, path, edited, 0o644)
	o.Timeout = 20
	plans = mustPlan(t, c, o)
	if plans[0].Action != ActionMerge {
		t.Fatalf("action %s", plans[0].Action)
	}
	mustApply(t, plans)
	b := backups(t, filepath.Dir(path))
	if len(b) != 1 || !bytes.Equal(readBytes(t, b[0]), edited) {
		t.Fatalf("backup: %v", b)
	}
	if !strings.Contains(filepath.Base(b[0]), ".spoor-") || strings.HasSuffix(b[0], ".json") {
		t.Errorf("backup name %s", b[0])
	}
	if !contains(readBytes(t, path), `"theme": "dark"`) || !contains(readBytes(t, path), "20000") {
		t.Error("merge lost the owner's edit or the new timeout")
	}
}

func TestApplyDetectsConcurrentChange(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeUser, "claude-code")
	path := targetPath(t, c, o, "claude-code")
	writeFile(t, path, []byte(`{"a": 1}`), 0o644)
	plans := mustPlan(t, c, o)
	writeFile(t, path, []byte(`{"a": 2}`), 0o644)
	err := Apply(plans)
	if !errors.Is(err, ErrChanged) {
		t.Fatalf("want ErrChanged, got %v", err)
	}
	if got := readBytes(t, path); string(got) != `{"a": 2}` {
		t.Errorf("file touched after a conflict: %s", got)
	}

	// A file that appears between plan and apply is not overwritten.
	o = opts(t, "linux", event.ScopeUser, "claude-code")
	path = targetPath(t, c, o, "claude-code")
	plans = mustPlan(t, c, o)
	writeFile(t, path, []byte(`{"mine": true}`), 0o644)
	if err := Apply(plans); !errors.Is(err, ErrChanged) {
		t.Fatalf("create over a new file: %v", err)
	}

	// A removal of a file that changed is refused too.
	o = opts(t, "linux", event.ScopeManaged, "copilot-cli")
	mustApply(t, mustPlan(t, c, o))
	un := mustUnplan(t, c, o)
	path = un[0].Path
	writeFile(t, path, append(readBytes(t, path), ' '), 0o644)
	if err := Apply(un); !errors.Is(err, ErrChanged) {
		t.Fatalf("remove after change: %v", err)
	}
	if !exists(path) {
		t.Error("changed file was removed")
	}
}

func TestApplyContinuesAfterAFailure(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeUser, "claude-code", "gemini-cli")
	plans := mustPlan(t, c, o)
	// Make the first plan stale.
	writeFile(t, only(t, plans, "claude-code").Path, []byte(`{}`), 0o644)
	err := Apply(plans)
	if err == nil || !strings.Contains(err.Error(), "claude-code") {
		t.Fatalf("error %v", err)
	}
	if !exists(only(t, plans, "gemini-cli").Path) {
		t.Error("the independent plan was not applied")
	}
}

func TestApplyRejectsBadPlans(t *testing.T) {
	root := t.TempDir()
	good := []byte("{\"hooks\": {}}\n")
	in := func(name string) string { return filepath.Join(root, "x", name) }
	cases := []struct {
		name string
		p    Plan
	}{
		{"unknown action", Plan{Action: "explode", Path: in("a.json"), After: good}},
		{"empty content", Plan{Action: ActionCreate, Path: in("a.json")}},
		{"not json", Plan{Action: ActionCreate, Path: in("a.json"), After: []byte("hooks: {}")}},
		{"jsonc into strict", Plan{Action: ActionCreate, Path: in("a.json"), After: []byte("{// x\n}")}},
		{"not toml", Plan{Action: ActionCreate, Path: in("a.toml"), After: []byte("[[[")}},
		{"other extension", Plan{Action: ActionCreate, Path: in("a.yaml"), After: good}},
		{"relative path", Plan{Action: ActionCreate, Path: "x/a.json", After: good}},
		{"control char", Plan{Action: ActionCreate, Path: in("a\n.json"), After: good}},
		{"directory", Plan{Action: ActionCreate, Path: root + string(filepath.Separator), After: good}},
		{"outside root", Plan{Action: ActionCreate, Path: filepath.Join(t.TempDir(), "a.json"), After: good, root: root}},
		{"traversal out of root", Plan{Action: ActionCreate, Path: root + "/../escape.json", After: good, root: root}},
		{"huge", Plan{Action: ActionCreate, Path: in("a.json"), After: append([]byte(`{"a":"`), append(bytes.Repeat([]byte("x"), maxFileSize), '"', '}')...)}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := Apply([]Plan{tc.p}); err == nil {
				t.Fatal("applied")
			}
		})
	}
	if ents, _ := os.ReadDir(filepath.Dir(root)); len(ents) > 0 {
		for _, e := range ents {
			if e.Name() == "escape.json" {
				t.Error("wrote outside the root")
			}
		}
	}
}

func TestApplyRefusesSymlinkedFile(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeUser, "claude-code")
	path := targetPath(t, c, o, "claude-code")
	real := filepath.Join(o.Root, "dotfiles", "settings.json")
	writeFile(t, real, []byte(`{"a": 1}`), 0o644)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, path); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	p := only(t, mustPlan(t, c, o), "claude-code")
	if p.Action != ActionUnsupported || !strings.Contains(p.Note, "symbolic link") {
		t.Fatalf("plan: %s %s", p.Action, p.Note)
	}
	// A plan made by hand still cannot go through the link.
	forged := Plan{AgentID: "claude-code", Path: path, Scope: event.ScopeUser, Action: ActionMerge,
		Before: []byte(`{"a": 1}`), After: []byte(`{"a": 2}`)}
	if err := Apply([]Plan{forged}); !errors.Is(err, ErrSymlink) {
		t.Fatalf("want ErrSymlink, got %v", err)
	}
	if got := readBytes(t, real); string(got) != `{"a": 1}` {
		t.Errorf("link target written: %s", got)
	}
	if s := stateOf(t, c, o, "claude-code"); s.Status != StatusUnsupported {
		t.Errorf("status %s", s.Status)
	}
	// Uninstall refuses it as well.
	if u := only(t, mustUnplan(t, c, o), "claude-code"); u.Action != ActionUnsupported {
		t.Errorf("uninstall: %s", u.Action)
	}
}

// TestApplyRefusesLinkUnderHostRoot: below a host root no link is
// followed, because it would resolve against this machine's file system.
func TestApplyRefusesLinkUnderHostRoot(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeManaged, "claude-code")
	outside := t.TempDir()
	etc := filepath.Join(o.Root, "etc")
	if err := os.MkdirAll(etc, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(etc, "claude-code")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	p := only(t, mustPlan(t, c, o), "claude-code")
	if p.Action != ActionUnsupported || !strings.Contains(p.Note, "symbolic link") {
		t.Fatalf("plan: %s %s", p.Action, p.Note)
	}
	forged := p
	forged.Action, forged.After = ActionCreate, []byte("{\"hooks\": {}}\n")
	if err := Apply([]Plan{forged}); !errors.Is(err, ErrSymlink) {
		t.Fatalf("want ErrSymlink, got %v", err)
	}
	if ents, _ := os.ReadDir(outside); len(ents) != 0 {
		t.Errorf("wrote through the link: %v", ents)
	}
	if s := stateOf(t, c, o, "claude-code"); s.Status != StatusInsecure {
		t.Errorf("status %s %s", s.Status, s.Detail)
	}
	// A relative link is refused just the same.
	o2 := opts(t, "linux", event.ScopeManaged, "gemini-cli")
	if err := os.MkdirAll(filepath.Join(o2.Root, "etc", "elsewhere"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("elsewhere", filepath.Join(o2.Root, "etc", "gemini-cli")); err != nil {
		t.Fatal(err)
	}
	if p := only(t, mustPlan(t, c, o2), "gemini-cli"); p.Action != ActionUnsupported {
		t.Errorf("relative link: %s", p.Action)
	}
}
