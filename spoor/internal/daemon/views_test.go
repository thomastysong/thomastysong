package daemon

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/thomastysong/spoor/internal/catalog"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/hookinstall"
	"github.com/thomastysong/spoor/internal/platform"
	"github.com/thomastysong/spoor/internal/procmon"
	"github.com/thomastysong/spoor/internal/sink"
)

func TestCombineHookStates(t *testing.T) {
	st := func(agent string, scope event.Scope, status string) hookinstall.State {
		return hookinstall.State{AgentID: agent, Scope: scope, Status: status}
	}
	got := combineHookStates([]hookinstall.State{
		st("claude-code", event.ScopeManaged, hookinstall.StatusShadowed),
		st("claude-code", event.ScopeUser, hookinstall.StatusUser),
		st("codex", event.ScopeManaged, hookinstall.StatusMissing),
		st("codex", event.ScopeUser, hookinstall.StatusForeignOnly),
		st("gemini-cli", event.ScopeManaged, hookinstall.StatusInsecure),
		st("gemini-cli", event.ScopeUser, hookinstall.StatusMissing),
		st("copilot-cli", event.ScopeManaged, hookinstall.StatusShadowed),
		st("copilot-cli", event.ScopeUser, hookinstall.StatusMissing),
		st("cursor", event.ScopeManaged, hookinstall.StatusManaged),
		st("cursor", event.ScopeUser, hookinstall.StatusModified),
		st("kiro-cli", event.ScopeUser, hookinstall.StatusUnsupported),
	})
	want := map[string]string{
		"claude-code": "user",
		"codex":       "missing",
		"gemini-cli":  "modified",
		"copilot-cli": "shadowed",
		"cursor":      "managed",
		"kiro-cli":    "unsupported",
	}
	for a, w := range want {
		if got[a] != w {
			t.Errorf("%s = %q, want %q", a, got[a], w)
		}
	}
}

func TestRefreshHooksView(t *testing.T) {
	f := newFixture(t)
	var gotOpts []hookinstall.Options
	f.hooks = func(c *catalog.Catalog, o hookinstall.Options) ([]hookinstall.State, error) {
		gotOpts = append(gotOpts, o)
		return []hookinstall.State{{AgentID: "claude-code", Scope: event.ScopeManaged, Status: hookinstall.StatusManaged}}, nil
	}
	d, _ := f.unitDaemon()
	defer d.pipe.Close()
	alt := filepath.Join(f.root, "alt")
	mustMkdir(t, alt, 0o755)
	d.procs.set([]procmon.AgentProc{{AgentID: "claude-code", User: event.User{ID: f.user.UID}, ConfigHome: alt}}, d.users)
	d.scans.refreshHooks()
	if len(gotOpts) != 1 || gotOpts[0].Home != f.user.Home || gotOpts[0].Env["CLAUDE_CONFIG_DIR"] != alt {
		t.Fatalf("hookinstall options = %+v", gotOpts)
	}
	for _, who := range []string{"alice", f.user.UID} {
		if got := d.hooks.lookup("claude-code", who); got != "managed" {
			t.Errorf("Hooked(claude-code, %s) = %q", who, got)
		}
	}
	if got := d.hooks.lookup("codex", "alice"); got != "" {
		t.Errorf("unknown agent = %q", got)
	}
	// A failing status call leaves the account out, it does not invent a state.
	f.hooks = func(*catalog.Catalog, hookinstall.Options) ([]hookinstall.State, error) {
		return nil, errors.New("boom")
	}
	d.scans.refreshHooks()
	if got := d.hooks.lookup("claude-code", "alice"); got != "" {
		t.Errorf("after a failed refresh = %q", got)
	}
	if d.board.get("hooks.status_errors") != 1 {
		t.Error("status error not counted")
	}
}

func TestConfigHomeDir(t *testing.T) {
	dir := t.TempDir()
	real := filepath.Join(dir, "real")
	mustMkdir(t, real, 0o755)
	file := filepath.Join(dir, "file")
	mustWrite(t, file, "x", 0o600)
	uid := currentUID()
	cases := map[string]bool{
		real:                              true,
		real + string(filepath.Separator): true,
		"relative/dir":                    false,
		"":                                false,
		real + string(filepath.Separator) + ".." + string(filepath.Separator) + "real": false, // not clean
		file:                          false,
		filepath.Join(dir, "missing"): false,
		"/x\x00y":                     false,
	}
	if runtime.GOOS != "windows" {
		link := filepath.Join(dir, "link")
		if err := os.Symlink(real, link); err != nil {
			t.Fatal(err)
		}
		cases[link] = false
	}
	for in, want := range cases {
		if _, ok := configHomeDir(in, uid); ok != want {
			t.Errorf("configHomeDir(%q) = %v, want %v", in, ok, want)
		}
	}
	if runtime.GOOS != "windows" {
		if _, ok := configHomeDir(real, "424242"); ok {
			t.Error("a directory owned by another account was accepted")
		}
	}
}

func TestProcViewRootSawAndEnv(t *testing.T) {
	users := newUserSet()
	users.set([]platform.UserHome{{Name: "alice", UID: currentUID(), Home: t.TempDir()}})
	v := newProcView()
	dir := t.TempDir()
	v.set([]procmon.AgentProc{
		{AgentID: "codex", User: event.User{Name: "alice", ID: currentUID()}, ConfigHome: dir},
	}, users)
	if !v.rootSaw("codex", "alice") || !v.rootSaw("codex", currentUID()) {
		t.Error("rootSaw misses the account by name or uid")
	}
	if v.rootSaw("codex", "bob") || v.rootSaw("claude-code", "alice") || v.rootSaw("", "") {
		t.Error("rootSaw answered for another agent or account")
	}
	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	if env := v.envFor(currentUID(), cat); env["CODEX_HOME"] != dir {
		t.Errorf("envFor = %v", env)
	}
	// Homes are bounded per agent and remembered after the process exits.
	for i := 0; i < maxHomesPerAgent+3; i++ {
		d := filepath.Join(t.TempDir(), fmt.Sprint(i))
		mustMkdir(t, d, 0o755)
		v.set([]procmon.AgentProc{{AgentID: "codex", User: event.User{ID: currentUID()}, ConfigHome: d}}, users)
	}
	v.set(nil, users)
	if n := len(v.configHomes()[currentUID()]["codex"]); n != maxHomesPerAgent {
		t.Errorf("homes kept = %d", n)
	}
}

func TestBoardBounds(t *testing.T) {
	b := newBoard()
	for i := 0; i < maxBoardKeys+50; i++ {
		b.add(fmt.Sprintf("hook_errors.hook_x%d", i), 1)
	}
	m := b.counters()
	if len(m) > maxBoardKeys+1 {
		t.Errorf("%d counter names", len(m))
	}
	if m["daemon.counters_omitted"] == 0 {
		t.Error("overflow not counted")
	}
	b.surface(event.SurfaceStatus{Name: "b"})
	b.update("a", func(s *event.SurfaceStatus) { s.Errors = 3 })
	s := b.surfaces()
	if len(s) != 2 || s[0].Name != "a" || s[0].Status != "ok" || s[0].Errors != 3 {
		t.Errorf("surfaces = %+v", s)
	}
}

func TestUserSetHome(t *testing.T) {
	u := newUserSet()
	u.set([]platform.UserHome{
		{Name: "alice", UID: "1000", Home: "/home/alice"},
		{Name: "alice", UID: "1000", Home: "/ci/home"}, // a second home of the same account
		{Name: "nohome", UID: "1001"},
	})
	if got := u.homeOf("1000", ""); got != "/home/alice" {
		t.Errorf("homeOf uid = %q", got)
	}
	if got := u.homeOf("", "alice"); got != "/home/alice" {
		t.Errorf("homeOf name = %q", got)
	}
	if got := u.homeOf("1001", "nohome"); got != "" {
		t.Errorf("account without home = %q", got)
	}
	if len(u.all()) != 2 {
		t.Errorf("all = %v", u.all())
	}
}

func TestTeeSink(t *testing.T) {
	a, b := &captureSink{}, &captureSink{}
	tee := &teeSink{sinks: []sink.Sink{a, b}}
	ev := event.New(event.KindHealth, event.TypeHealthHeartbeat, event.SourceSensor)
	if err := tee.Write([]*event.Event{ev}); err != nil {
		t.Fatal(err)
	}
	if len(a.all()) != 1 || len(b.all()) != 1 {
		t.Error("tee did not write to every sink")
	}
	if tee.Flush() != nil || tee.Close() != nil || tee.Name() != "tee" {
		t.Error("tee flush/close")
	}
}

func TestValidUID(t *testing.T) {
	for in, want := range map[string]bool{
		"0": true, "1000": true, "S-1-5-21-1004336348-1177238915-682003330-1001": true,
		"": false, "..": false, "1000/../0": false, "-1": false, "S-1": false, "12345678901": false,
	} {
		if validUID(in) != want {
			t.Errorf("validUID(%q) != %v", in, want)
		}
	}
}
