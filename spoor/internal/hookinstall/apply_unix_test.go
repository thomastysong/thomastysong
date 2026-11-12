//go:build unix

package hookinstall

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/event"
)

func perm(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func TestApplyModesIgnoreUmask(t *testing.T) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeUser, "copilot-cli")
	plans := mustPlan(t, c, o)
	mustApply(t, plans)
	path := plans[0].Path
	if m := perm(t, path); m != 0o644 {
		t.Errorf("new file mode %o, want 644", m)
	}
	for d := filepath.Dir(path); d != o.Root; d = filepath.Dir(d) {
		if m := perm(t, d); m != 0o755 {
			t.Errorf("created directory %s mode %o, want 755", d, m)
		}
	}
	// An existing private file stays private.
	o2 := opts(t, "linux", event.ScopeUser, "claude-code")
	p2 := targetPath(t, c, o2, "claude-code")
	writeFile(t, p2, []byte(`{"env": {"ANTHROPIC_API_KEY": "x"}}`), 0o600)
	mustApply(t, mustPlan(t, c, o2))
	if m := perm(t, p2); m != 0o600 {
		t.Errorf("existing file widened to %o", m)
	}
	for _, b := range backups(t, filepath.Dir(p2)) {
		if m := perm(t, b); m != 0o600 {
			t.Errorf("backup %s mode %o", b, m)
		}
	}
}

// TestManagedHardening: a managed install repairs a directory chain a
// non-admin could write to, and Status flags tampering afterwards.
func TestManagedHardening(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeManaged, "claude-code")
	path := targetPath(t, c, o, "claude-code")
	dropDir := filepath.Dir(path)
	ccDir := filepath.Dir(dropDir)
	if err := os.MkdirAll(dropDir, 0o777); err != nil {
		t.Fatal(err)
	}
	for _, d := range []string{ccDir, dropDir} {
		if err := os.Chmod(d, 0o777); err != nil {
			t.Fatal(err)
		}
	}
	if s := stateOf(t, c, o, "claude-code"); s.Status != StatusMissing {
		t.Fatalf("before: %s", s.Status)
	}
	mustApply(t, mustPlan(t, c, o))
	for _, d := range []string{ccDir, dropDir} {
		if m := perm(t, d); m != 0o755 {
			t.Errorf("%s mode %o after install", d, m)
		}
	}
	if m := perm(t, path); m != 0o644 {
		t.Errorf("file mode %o", m)
	}
	if s := stateOf(t, c, o, "claude-code"); s.Status != StatusManaged {
		t.Fatalf("after install: %s %s", s.Status, s.Detail)
	}

	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	s := stateOf(t, c, o, "claude-code")
	if s.Status != StatusInsecure || !strings.Contains(s.Detail, "writable") {
		t.Errorf("world-writable file: %s %s", s.Status, s.Detail)
	}
	_ = os.Chmod(path, 0o644)
	if err := os.Chmod(ccDir, 0o775); err != nil {
		t.Fatal(err)
	}
	if s := stateOf(t, c, o, "claude-code"); s.Status != StatusInsecure {
		t.Errorf("group-writable directory: %s %s", s.Status, s.Detail)
	}
	// Reinstalling with the same content repairs it.
	p := only(t, mustPlan(t, c, o), "claude-code")
	if p.Action != ActionMerge || !strings.Contains(p.Note, "repair") {
		t.Fatalf("repair plan: %s %s", p.Action, p.Note)
	}
	mustApply(t, []Plan{p})
	if m := perm(t, ccDir); m != 0o755 {
		t.Errorf("directory not repaired: %o", m)
	}
	if p := only(t, mustPlan(t, c, o), "claude-code"); p.Action != ActionUnchanged {
		t.Errorf("after repair: %s", p.Action)
	}

	// A managed file owned by someone else.
	if os.Geteuid() == 0 {
		if err := os.Lchown(path, 4242, 4242); err != nil {
			t.Fatal(err)
		}
		if s := stateOf(t, c, o, "claude-code"); s.Status != StatusInsecure || !strings.Contains(s.Detail, "4242") {
			t.Errorf("foreign owner: %s %s", s.Status, s.Detail)
		}
		// The next write gives it back to root.
		o.Timeout = 11
		mustApply(t, mustPlan(t, c, o))
		if fi, _ := os.Lstat(path); fi.Sys().(*syscall.Stat_t).Uid != 0 {
			t.Error("managed file not returned to root")
		}
	}
}

func TestApplyGivesUserFilesToTheirOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeUser, "claude-code", "codex")
	home := filepath.Join(o.Root, "home", "dev")
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(home, 1234, 1234); err != nil {
		t.Fatal(err)
	}
	// Codex's directory already exists with a private file owned by the user.
	cfg := filepath.Join(home, ".codex", "hooks.json")
	writeFile(t, cfg, []byte(`{"hooks": {}}`), 0o600)
	for _, p := range []string{filepath.Dir(cfg), cfg} {
		if err := os.Chown(p, 1234, 1234); err != nil {
			t.Fatal(err)
		}
	}
	mustApply(t, mustPlan(t, c, o))
	check := func(p string) {
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st := fi.Sys().(*syscall.Stat_t); st.Uid != 1234 || st.Gid != 1234 {
			t.Errorf("%s owned by %d:%d", p, st.Uid, st.Gid)
		}
	}
	check(filepath.Join(home, ".claude"))
	check(filepath.Join(home, ".claude", "settings.json"))
	check(cfg)
	for _, b := range backups(t, filepath.Dir(cfg)) {
		check(b)
	}
	if m := perm(t, cfg); m != 0o600 {
		t.Errorf("mode %o", m)
	}
}

// TestUntrustedLinkInPath: when root edits a user's settings, a directory
// link that the user planted is never followed; links made by root (the
// system layout) are.
func TestUntrustedLinkInPath(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to own and plant links for another uid")
	}
	c := testCatalog(t)
	o := Options{Binary: unixBin, Scope: event.ScopeUser, Agents: []string{"claude-code"}, GOOS: "linux"}
	base := t.TempDir()
	o.Home = filepath.Join(base, "home")
	victim := filepath.Join(base, "victim")
	for _, d := range []string{o.Home, victim} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(o.Home, ".claude")
	if err := os.Symlink(victim, link); err != nil {
		t.Fatal(err)
	}
	if err := os.Lchown(link, 4242, 4242); err != nil {
		t.Fatal(err)
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
	if ents, _ := os.ReadDir(victim); len(ents) != 0 {
		t.Errorf("wrote through the user's link: %v", ents)
	}

	// The same link made by root is system layout and is followed.
	if err := os.Lchown(link, 0, 0); err != nil {
		t.Fatal(err)
	}
	plans := mustPlan(t, c, o)
	if plans[0].Action != ActionCreate {
		t.Fatalf("root link: %s %s", plans[0].Action, plans[0].Note)
	}
	mustApply(t, plans)
	if !exists(filepath.Join(victim, "settings.json")) {
		t.Error("trusted link not followed")
	}
}

func TestOwnLinkIsFollowedWhenUnprivileged(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("covered by TestUntrustedLinkInPath as root")
	}
	c := testCatalog(t)
	base := t.TempDir()
	o := Options{Binary: unixBin, Scope: event.ScopeUser, Agents: []string{"claude-code"}, GOOS: "linux", Home: filepath.Join(base, "home")}
	real := filepath.Join(base, "dotfiles")
	_ = os.MkdirAll(o.Home, 0o755)
	_ = os.MkdirAll(real, 0o755)
	if err := os.Symlink(real, filepath.Join(o.Home, ".claude")); err != nil {
		t.Fatal(err)
	}
	mustApply(t, mustPlan(t, c, o))
	if !exists(filepath.Join(real, "settings.json")) {
		t.Error("own link not followed")
	}
}

func TestFIFOIsNotOpened(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeUser, "gemini-cli")
	path := targetPath(t, c, o, "gemini-cli")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(path, 0o644); err != nil {
		t.Skipf("mkfifo: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		if p := only(t, mustPlan(t, c, o), "gemini-cli"); p.Action != ActionUnsupported {
			t.Errorf("fifo: %s", p.Action)
		}
		if s := stateOf(t, c, o, "gemini-cli"); s.Status != StatusUnsupported {
			t.Errorf("fifo status: %s", s.Status)
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("blocked on a FIFO")
	}
}

func TestRootRefusesThirdPartyFile(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root")
	}
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeUser, "gemini-cli")
	path := targetPath(t, c, o, "gemini-cli")
	writeFile(t, path, []byte(`{"a": 1}`), 0o644)
	if err := os.Chown(filepath.Dir(path), 1234, 1234); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(path, 5678, 5678); err != nil {
		t.Fatal(err)
	}
	p := only(t, mustPlan(t, c, o), "gemini-cli")
	if p.Action != ActionUnsupported || !strings.Contains(p.Note, "5678") {
		t.Fatalf("%s %s", p.Action, p.Note)
	}
	forged := p
	forged.Action, forged.After = ActionMerge, []byte(`{"a": 2}`)
	if err := Apply([]Plan{forged}); err == nil || !strings.Contains(err.Error(), "5678") {
		t.Errorf("apply: %v", err)
	}
	// The directory owner's own file is fine.
	if err := os.Chown(path, 1234, 1234); err != nil {
		t.Fatal(err)
	}
	if p := only(t, mustPlan(t, c, o), "gemini-cli"); p.Action != ActionMerge {
		t.Errorf("owner's file: %s %s", p.Action, p.Note)
	}
}
