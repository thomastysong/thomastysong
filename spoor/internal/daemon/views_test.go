package daemon

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/catalog"
	"github.com/thomastysong/spoor/internal/engine"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/hookinstall"
	"github.com/thomastysong/spoor/internal/platform"
	"github.com/thomastysong/spoor/internal/privacy"
	"github.com/thomastysong/spoor/internal/procmon"
	"github.com/thomastysong/spoor/internal/rules"
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
	b.set("early.gauge", 7)
	for i := 0; i < 1000; i++ {
		b.add(fmt.Sprintf("hook_errors.hook_%s", strings.Repeat("x", 40)+fmt.Sprint(i)), 1)
	}
	m := b.counters()
	enc, _ := json.Marshal(func() map[string]uint64 {
		w := map[string]uint64{}
		for k := range m {
			w[k] = ^uint64(0) // the widest value a counter can take
		}
		return w
	}())
	if len(enc) > maxBoardBytes {
		t.Errorf("the board encodes to %d bytes with %d names, over its %d byte bound", len(enc), len(m), maxBoardBytes)
	}
	if m[omittedCounter] == 0 {
		t.Error("overflow not counted")
	}
	// A gauge set after the board is full is refused, and counted; one set
	// before keeps updating; unset frees room.
	b.set("late.gauge", 1)
	if _, ok := b.counters()["late.gauge"]; ok {
		t.Error("a new name was admitted beyond the bound")
	}
	before := b.get(omittedCounter)
	b.set("early.gauge", 8)
	if b.get("early.gauge") != 8 || b.get(omittedCounter) != before {
		t.Error("an existing gauge was refused")
	}
	b.unset("early.gauge")
	b.set("late.gauge", 1)
	if b.get("late.gauge") != 1 {
		t.Error("unset did not free room")
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
	var mirrorErrs int
	tee := &teeSink{primary: a, mirrors: []sink.Sink{b}, onMirrorError: func(string, error) { mirrorErrs++ }}
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
	if mirrorErrs != 0 {
		t.Errorf("mirror errors = %d", mirrorErrs)
	}

	// A failing mirror (stdout closed) is counted, never reported as a
	// failure of the outbox write: the pipeline would count the records as
	// dropped although the outbox holds them.
	c := &captureSink{}
	tee = &teeSink{primary: c, mirrors: []sink.Sink{failSink{}}, onMirrorError: func(string, error) { mirrorErrs++ }}
	if err := tee.Write([]*event.Event{ev}); err != nil {
		t.Errorf("a mirror failure failed the write: %v", err)
	}
	if err := tee.Flush(); err != nil {
		t.Errorf("a mirror failure failed the flush: %v", err)
	}
	if err := tee.Close(); err != nil {
		t.Errorf("a mirror failure failed the close: %v", err)
	}
	if len(c.all()) != 1 || mirrorErrs != 3 {
		t.Errorf("primary got %d records, mirror errors = %d", len(c.all()), mirrorErrs)
	}
	// A failing primary is the write's result.
	tee = &teeSink{primary: failSink{}, mirrors: []sink.Sink{c}}
	if err := tee.Write([]*event.Event{ev}); err == nil {
		t.Error("a primary failure was hidden")
	}
}

type failSink struct{}

func (failSink) Name() string               { return "fail" }
func (failSink) Write([]*event.Event) error { return errors.New("closed") }
func (failSink) Flush() error               { return errors.New("closed") }
func (failSink) Close() error               { return errors.New("closed") }

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

// TestHeartbeatFitsWithFullBoard: with the board filled to its bound
// (maxBoardBytes, every value at its widest) and every surface the daemon
// reports set, the heartbeat still fits the default line without the
// engine cutting surfaces or counters, with room left for what this test
// cannot fill (every stream's accounting, wider engine counter values).
func TestHeartbeatFitsWithFullBoard(t *testing.T) {
	f := newFixture(t)
	d, _ := f.unitDaemon()
	d.pipe.Close()
	for i := 0; ; i++ {
		name := fmt.Sprintf("daemon.filler.%s.%03d", strings.Repeat("n", 30), i)
		d.board.set(name, ^uint64(0))
		if d.board.get(omittedCounter) > 0 {
			break
		}
	}
	for _, n := range []string{"adapters", "hooks", "transcripts", "processes", "osquery", "otel", "outbox", "scan"} {
		d.board.surface(event.SurfaceStatus{Name: n, Status: "degraded", Reason: "exec_selftest_failed", Errors: ^uint64(0),
			Events: ^uint64(0), SchemaDrift: true, LastEvent: event.At(time.Now())})
	}
	sinkC := &captureSink{}
	set, err := rules.Load(map[string][]byte{"test.yaml": []byte(testRulePack)})
	if err != nil {
		t.Fatal(err)
	}
	host, src := d.env.host()
	pipe, err := engine.New(engine.Options{
		Config: f.cfg, Catalog: d.cat, Rules: set, Outbox: sinkC, Host: host, HostIDSource: src,
		Mode: engine.ModeDaemon, Now: time.Now, Disabled: func() bool { return false },
		Surfaces: d.board.surfaces, Gauges: d.board.counters,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := pipe.Close(); err != nil {
		t.Fatal(err)
	}
	var hb *event.Event
	for _, e := range sinkC.all() {
		if e.Type == event.TypeHealthHeartbeat {
			hb = e
		}
	}
	if hb == nil || hb.Health == nil {
		t.Fatal("no heartbeat")
	}
	if len(hb.Truncated) > 0 || len(hb.Health.Surfaces) < 8 {
		t.Errorf("a full board pushed the heartbeat over its line: truncated %v, %d surfaces", hb.Truncated, len(hb.Health.Surfaces))
	}
	for k := range d.board.counters() {
		if _, ok := hb.Health.Counters[k]; !ok {
			t.Errorf("board counter %s missing from the heartbeat", k)
			break
		}
	}
	line, err := hb.MarshalLine()
	if err != nil {
		t.Fatal(err)
	}
	budget := f.cfg.Output.MaxLine - privacy.LineHeadroom - 1 - 512
	t.Logf("heartbeat %d bytes of %d with %d counters", len(line), budget, len(hb.Health.Counters))
	if room := budget - len(line); room < 3<<10 {
		t.Errorf("only %d bytes left in the heartbeat line with a full board", room)
	}
}
