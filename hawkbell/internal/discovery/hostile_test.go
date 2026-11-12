package discovery

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/platform"
)

func TestHostileTrees(t *testing.T) {
	f := newFixture(t)
	h := "/home/alice"
	// A config over the 20 MiB cap.
	big := make([]byte, maxConfigBytes+10)
	copy(big, `{"mcpServers":{"big":{"command":"x"}}`)
	f.bytes(h+"/.cursor/mcp.json", big)
	// Pathological nesting in every syntax.
	f.file(h+"/.claude.json", strings.Repeat(`{"a":`, 100000)+strings.Repeat("}", 100000), 0o644)
	f.file(h+"/.codex/config.toml", "x = "+strings.Repeat("[", 50000)+strings.Repeat("]", 50000)+"\n", 0o644)
	// TOML nesting hidden behind a multi-line string, and a dotted key whose
	// parts make the TOML decoder's memory quadratic.
	f.file("/etc/codex/requirements.toml", hiddenTOMLNesting(100_000), 0o644)
	f.file(h+"/.kimi-code/config.toml", strings.Repeat("k.", 4000)+"k = 1\n", 0o644)
	f.file(h+"/.config/goose/config.yaml", strings.Repeat("- ", 50000)+"x\n", 0o644)
	// Invalid UTF-8, control characters and a credential in names.
	tok := f.canary("github")
	f.file(h+"/.gemini/settings.json", `{"mcpServers":{"bad\u001b[31m-`+tok+`":{"command":"x"},"‮evil":{"command":"y"}}}`, 0o644)
	f.dir(h + "/.claude/skills/\xff\xfeweird")
	f.file(h+"/.claude/skills/\xff\xfeweird/SKILL.md", "x", 0o644)
	// A directory with more entries than the listing cap.
	for i := 0; i <= maxChildren; i++ {
		if i == 0 {
			f.dir(h + "/.claude/commands")
		}
		if err := os.WriteFile(f.real(h+"/.claude/commands/c"+strconv.Itoa(i)+".md"), []byte("x"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	// A skill tree that is too deep to hash (no partial hash).
	deep := h + "/.claude/skills/deep"
	f.file(deep+"/SKILL.md", "x", 0o644)
	p := deep
	for i := 0; i < 2*maxWalkDepth+3; i++ {
		p += "/d"
	}
	f.file(p+"/f", "x", 0o644)
	// Project paths from hostile agent state.
	f.file(h+"/.gemini/projects.json", `{"projects":{"../../../etc":"a","relative/dir":"b","/nonexistent/x":"c","`+strings.Repeat("/a", 3000)+`":"d"}}`, 0o644)
	f.file(h+"/.claude/projects/-etc/1.jsonl", strings.Repeat("x", maxHeadBytes*2)+"\n", 0o644)

	o := f.opts(f.user("alice"))
	done := make(chan struct{})
	var res *Result
	var err error
	go func() {
		res, err = Scan(context.Background(), o)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("scan of a hostile tree did not finish")
	}
	if err != nil {
		t.Fatal(err)
	}
	x := fixtureIndex{events: res.Events}
	if l := x.find(event.AssetMCPServer, "big"); len(l) != 0 {
		t.Error("an over-cap config was parsed")
	}
	for _, e := range res.Events {
		b, _ := e.MarshalLine()
		if strings.Contains(string(b), tok) {
			t.Errorf("credential in a name leaked: %s", b)
		}
		if strings.ContainsAny(e.Asset.Name, "\x1b‮") || !isValidUTF8(e.Asset.Name) || !isValidUTF8(e.Asset.Path) {
			t.Errorf("unsafe name emitted: %q", e.Asset.Name)
		}
		if e.Asset.Kind == event.AssetCommand {
			t.Errorf("a directory over the listing cap was partially reported: %s", e.Asset.Name)
		}
		if pr := e.Asset.Detail["project"]; pr != "" && !strings.HasPrefix(pr, "/home/alice") {
			t.Errorf("project from hostile state scanned: %q", pr)
		}
	}
	if d := x.one(t, event.AssetSkill, "deep"); d.SHA256 != "" || !strings.HasPrefix(d.Detail["hash"], "none:") {
		t.Errorf("deep skill hashed partially: %+v", d)
	}
	if res.Ledger.Errors == 0 || res.Ledger.Skipped == 0 {
		t.Errorf("ledger did not record the hostile input: %+v", res.Ledger)
	}
	for _, want := range []string{"could not parse /etc/codex/requirements.toml", "could not parse /home/alice/.kimi-code/config.toml"} {
		found := false
		for _, n := range res.Ledger.Notes {
			found = found || strings.HasPrefix(n, want)
		}
		if !found {
			t.Errorf("no ledger note %q in %v", want, res.Ledger.Notes)
		}
	}
}

func isValidUTF8(s string) bool { return strings.ToValidUTF8(s, "") == s }

// TestWithoutHostRoot scans a home given by its real path (no container
// root), exercising the ordinary open path.
func TestWithoutHostRoot(t *testing.T) {
	home := filepath.Join(t.TempDir(), "alice")
	write := func(rel, body string, mode os.FileMode) {
		p := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), mode); err != nil {
			t.Fatal(err)
		}
	}
	for _, m := range adrBasic {
		write(".claude/skills/basic/"+m.rel, m.body, m.mode)
	}
	write(".cursor/mcp.json", `{"mcpServers":{"plain-home":{"command":"npx","args":["-y","x"]}}}`, 0o644)
	if err := os.Symlink("/etc/passwd", filepath.Join(home, ".cursor", "hooks.json")); err != nil {
		t.Fatal(err)
	}
	u := platform.UserHome{Name: "alice", UID: strconv.Itoa(os.Geteuid()), Home: home}
	res, err := Scan(context.Background(), Options{
		Catalog: testCatalog(t), Users: []platform.UserHome{u},
		Host: &event.Host{ID: "h"}, Deadline: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	x := fixtureIndex{events: res.Events}
	var mine []*event.Event
	for _, e := range res.Events {
		if strings.HasPrefix(e.Asset.Path, home) {
			mine = append(mine, e)
		}
	}
	xm := fixtureIndex{events: mine}
	if s := xm.one(t, event.AssetSkill, "basic"); s.SHA256 != adrBasicHash {
		t.Errorf("hash %s", s.SHA256)
	}
	xm.one(t, event.AssetMCPServer, "plain-home")
	for _, e := range x.events {
		if e.Asset.Kind == event.AssetHook && strings.HasPrefix(e.Asset.Path, home) {
			t.Errorf("hook read through a link to /etc/passwd: %+v", e.Asset)
		}
	}
}

func TestPersonalDirectoriesRefused(t *testing.T) {
	f := newFixture(t)
	// A project that lives in ~/Documents is allowed (an agent pointed
	// there); a skills directory the catalog does not name is not read.
	f.file("/home/alice/Documents/code/proj/.mcp.json", `{"mcpServers":{"in-docs":{"command":"x"}}}`, 0o644)
	f.file("/home/alice/.claude.json", `{"projects":{"/home/alice/Documents/code/proj":{}}}`, 0o644)
	f.file("/home/alice/Documents/Cline/Hooks/PreToolUse", "#!/bin/sh\n", 0o755)
	f.file("/home/alice/Desktop/.mcp.json", `{"mcpServers":{"desk":{"command":"x"}}}`, 0o644)
	res, err := Scan(context.Background(), f.opts(f.user("alice")))
	if err != nil {
		t.Fatal(err)
	}
	x := fixtureIndex{events: res.Events}
	x.one(t, event.AssetMCPServer, "in-docs")
	if l := x.find(event.AssetMCPServer, "desk"); len(l) != 0 {
		t.Error("a personal directory was read")
	}
	g, err := newGate(context.Background(), newLedger(), f.root, false, "linux")
	if err != nil {
		t.Fatal(err)
	}
	defer g.close()
	if _, _, err := g.readFile(loc{root: "/home/alice", rel: "Desktop/.mcp.json", home: true, user: true}, "", 1<<20); err != errPersonal {
		t.Errorf("Desktop read: %v", err)
	}
	g.allowPath("/home/alice/Desktop")
	if _, _, err := g.readFile(loc{root: "/home/alice", rel: "Desktop/.mcp.json", home: true, user: true}, "", 1<<20); err != nil {
		t.Errorf("allowed Desktop read: %v", err)
	}
}

func TestContainerUsersFromPasswd(t *testing.T) {
	f := newFixture(t)
	f.file("/etc/passwd", "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\ndev:x:1000:1000::/home/dev:/bin/zsh\nghost:x:1001:1001::/home/ghost:/bin/sh\n", 0o644)
	f.file("/home/dev/.cursor/mcp.json", `{"mcpServers":{"ctr":{"command":"x"}}}`, 0o644)
	f.dir("/root")
	if os.Geteuid() == 0 {
		for _, p := range []string{"/home/dev", "/home/dev/.cursor", "/home/dev/.cursor/mcp.json"} {
			if err := os.Lchown(f.real(p), 1000, 1000); err != nil {
				t.Fatal(err)
			}
		}
	}
	o := f.opts()
	o.Users = nil
	o.Container = &event.Container{ID: "abc", Runtime: "containerd"}
	res, err := Scan(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	x := fixtureIndex{events: res.Events}
	a := x.one(t, event.AssetMCPServer, "ctr")
	if a.Owner != "dev" {
		t.Errorf("owner = %q", a.Owner)
	}
	for _, e := range res.Events {
		if e.Container == nil || e.Container.ID != "abc" {
			t.Errorf("container not stamped on %s", e.Asset.Name)
		}
	}
}

func TestFolderHashCaps(t *testing.T) {
	f := newFixture(t)
	dir := "/home/alice/s"
	f.file(dir+"/SKILL.md", "x", 0o644)
	f.symlink(dir+"/link", "/etc/passwd") // links are not part of the tree
	g, err := newGate(context.Background(), newLedger(), f.root, false, "linux")
	if err != nil {
		t.Fatal(err)
	}
	defer g.close()
	s := &scanner{g: g, led: g.led, goos: "linux"}
	uc := &userCtx{u: f.user("alice"), home: "/home/alice"}
	sum, n, reason := s.folderHash(dir, uc, "")
	if reason != "" || n != 1 || sum == "" {
		t.Fatalf("%s %d %s", sum, n, reason)
	}
	g.hashLeft = 0
	if _, _, reason := s.folderHash(dir, uc, ""); reason != "hash_budget_exhausted" {
		t.Errorf("budget: %q", reason)
	}
}

// TestRepoCodexConfigCannotKillScan: a repository that ships a 4 MB
// .codex/config.toml (under the 20 MiB cap) whose nesting hides behind a
// multi-line string once killed the scanning process with "fatal error:
// stack overflow", which no recover can catch. The scan runs in a child
// process so a regression is reported instead of killing the test binary.
func TestRepoCodexConfigCannotKillScan(t *testing.T) {
	if os.Getenv("HAWKBELL_DISCOVERY_CHILD") == "codex-config" {
		dir := t.TempDir()
		if err := os.MkdirAll(dir+"/.codex", 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dir+"/.codex/config.toml", []byte(hiddenTOMLNesting(2_000_000)), 0o644); err != nil {
			t.Fatal(err)
		}
		u := platform.UserHome{Name: "u", UID: strconv.Itoa(os.Geteuid()), Home: t.TempDir()}
		o := Options{Catalog: testCatalog(t), Host: &event.Host{ID: "h"}, Deadline: time.Minute}
		res, err := ScanProject(context.Background(), dir, u, o)
		if err != nil {
			t.Fatal(err)
		}
		if res.Ledger.Errors == 0 {
			t.Errorf("the refused config was not counted: %+v", res.Ledger)
		}
		return
	}
	if testing.Short() {
		t.Skip("spawns a child scan")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestRepoCodexConfigCannotKillScan$", "-test.count=1")
	cmd.Env = append(os.Environ(), "HAWKBELL_DISCOVERY_CHILD=codex-config")
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := string(out)
		if i := strings.Index(msg, "fatal error"); i >= 0 {
			msg = msg[i:]
		}
		if len(msg) > 600 {
			msg = msg[:600]
		}
		t.Fatalf("ScanProject on a repository with a crafted .codex/config.toml failed: %v\n%s", err, msg)
	}
}

// TestEntryBudgetPerHome: the directory-entry budget belongs to each home,
// so one user cannot spend it for everybody scanned after them. Mallory's
// ~/.claude/projects holds empty directories whose names decode into a
// 4999-entry directory she owns; decoding them lists it again and again.
func TestEntryBudgetPerHome(t *testing.T) {
	f := newFixture(t)
	m := "/home/mallory"
	for i := 0; i < maxChildren-1; i++ {
		if err := os.MkdirAll(f.real(m+"/big/d"+strconv.Itoa(i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 45; i++ {
		f.dir(m + "/.claude/projects/-home-mallory-big-zzz" + strconv.Itoa(i))
	}
	f.file("/home/victim/.claude/skills/victim-skill/SKILL.md", "---\nname: victim-skill\n---\nx\n", 0o644)
	o := f.opts(f.user("mallory"), f.user("victim"))
	res, err := Scan(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if len((fixtureIndex{events: res.Events}).find(event.AssetSkill, "victim-skill")) == 0 {
		t.Errorf("victim's skill not inventoried after mallory's home spent its budget (ledger %+v)", res.Ledger)
	}
	// The decodes share listings: the big directory is listed once.
	s, cancel, err := newScanner(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	defer s.g.close()
	uc := s.userCtx(f.user("mallory"))
	ps := &projSet{s: s, uc: uc, m: map[string]*projCand{}, decodesLeft: maxUserDecodes}
	for i := 0; i < 45; i++ {
		s.decodeClaudeDir(ps, "-home-mallory-big-zzz"+strconv.Itoa(i))
	}
	if used := maxUserDecodes - ps.decodesLeft; used > 8 {
		t.Errorf("45 decodes into one directory made %d uncached listings", used)
	}
}
