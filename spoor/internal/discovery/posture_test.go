package discovery

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/platform"
)

const spoorDropIn = `{"hooks":{"PreToolUse":[{"hooks":[{"type":"command","command":"/usr/bin/spoor","args":["hook","--agent","claude-code"]}]}]}}`

// TestManagedDirectoryPosture: a managed file is only as trustworthy as the
// directory holding it. A world-writable drop-in directory lets anyone add
// a drop-in even with the sticky bit set.
func TestManagedDirectoryPosture(t *testing.T) {
	f := newFixture(t)
	f.dir("/home/alice/.claude")
	f.file("/usr/local/lib/node_modules/@anthropic-ai/claude-code/package.json", `{"name":"@anthropic-ai/claude-code","version":"2.0.0"}`, 0o644)
	f.file("/etc/claude-code/managed-settings.d/50-spoor.json", spoorDropIn, 0o644)
	if err := os.Chmod(f.real("/etc/claude-code/managed-settings.d"), 0o1777); err != nil {
		t.Fatal(err)
	}
	a := claudeAsset(t, f, f.opts(f.user("alice")))
	if !has(a.RiskFlags, flagManagedWorldWritable) || a.Telemetry == nil || a.Telemetry.Hooks != hooksModified {
		t.Errorf("sticky world-writable drop-in dir: flags %v telemetry %+v", a.RiskFlags, a.Telemetry)
	}
}

func TestManagedDirectoryOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to hand the directory to another uid")
	}
	f := newFixture(t)
	f.dir("/home/alice/.claude")
	f.file("/usr/local/lib/node_modules/@anthropic-ai/claude-code/package.json", `{"name":"@anthropic-ai/claude-code","version":"2.0.0"}`, 0o644)
	f.file("/etc/claude-code/managed-settings.d/50-spoor.json", spoorDropIn, 0o644)
	if err := os.Lchown(f.real("/etc/claude-code/managed-settings.d"), 1001, 1001); err != nil {
		t.Fatal(err)
	}
	a := claudeAsset(t, f, f.opts(f.user("alice")))
	if !has(a.RiskFlags, flagManagedWorldWritable) || a.Telemetry.Hooks != hooksModified {
		t.Errorf("drop-in dir owned by uid 1001: flags %v telemetry %+v", a.RiskFlags, a.Telemetry)
	}
}

// TestHiddenLaunchPathForms: the same hidden directory is recognised
// whatever spelling of the home the config uses, and on Windows whatever
// case and trailing dots or spaces (which Win32 drops).
func TestHiddenLaunchPathForms(t *testing.T) {
	s, cancel, err := newScanner(context.Background(), Options{Catalog: testCatalog(t), Host: &event.Host{ID: "h"}})
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	defer s.g.close()

	s.goos = "windows"
	win := s.userCtx(platform.UserHome{Name: "alice", UID: "S-1-5-21-1-2-3-1001", Home: `C:\Users\alice`})
	for p, want := range map[string]bool{
		`%USERPROFILE%\.evil\srv.exe`:                 true,
		`$env:USERPROFILE\.evil\srv.ps1`:              true,
		`${env:USERPROFILE}\.evil\srv.ps1`:            true,
		`C:\Users\Alice\.EVIL. \srv.exe`:              true,
		`C:\Users\alice\.c\x.js`:                      true, // not ".claude"
		`%userprofile%\.claude\hooks\x.js`:            false,
		`C:\Users\alice\.CODEX\x.js`:                  false,
		`C:\Users\alice\.vscode\extensions\x\srv.js`:  false,
		`C:\Users\alice\proj\srv.js`:                  false,
		`C:\Users\bob\.evil\srv.js`:                   false, // another home: not this user's hidden dir
		`%USERPROFILE%\..\bob\x.js`:                   false,
		`%USERPROFILEX%\.evil\x.js`:                   false,
		`C:\Users\alice\. \x.js`:                      false,
		`C:\Users\alice\AppData\Roaming\npm\srv.cmd`:  false,
		`C:\Users\alice\.local\bin\uvx.exe`:           false,
		`C:\Users\alice\.gemini\extensions\x\srv.js`:  false,
		`C:\Users\alice\.copilot\mcp\srv.js`:          false,
		`C:\Users\alice\.cursor\extensions\x\srv.js`:  false,
		`C:\Users\alice\.ssh\x.js`:                    true,
		`C:\Users\alice\.config\x\srv.js`:             false,
		`C:\Users\alice\.npm-global\bin\srv.cmd`:      false,
		`C:\Users\alice\.vscode-server\bin\x\node.js`: false,
	} {
		if got := s.hiddenOutsideTools(p, win); got != want {
			t.Errorf("windows %q: hidden=%v, want %v", p, got, want)
		}
	}

	s.goos = "linux"
	lin := s.userCtx(platform.UserHome{Name: "alice", UID: "1000", Home: "/home/alice"})
	for p, want := range map[string]bool{
		"~/.evil/x.js":                  true,
		"$HOME/.evil/x.js":              true,
		"${HOME}/.evil/x.js":            true,
		"/home/alice/.evil/x.js":        true,
		"/home/alice/.EVIL/x.js":        true, // a different directory on Linux, still hidden
		"$HOMEDIR/.evil/x.js":           false,
		"~/.local/share/x/server.js":    false,
		"$HOME/.claude/hooks/x.sh":      false,
		"/home/alice/src/app/x.js":      false,
		"/opt/tools/.hidden/x":          false,
		"~/.codeium/windsurf/server.js": false,
	} {
		if got := s.hiddenOutsideTools(p, lin); got != want {
			t.Errorf("linux %q: hidden=%v, want %v", p, got, want)
		}
	}
}

// TestScanProjectForeignOwner: ScanProject takes its directory from a
// session event, which the monitored user controls. A privileged scan
// reads only files the named user owns, so pointing it at another user's
// repository yields nothing and is counted as denied.
func TestScanProjectForeignOwner(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create files owned by another user")
	}
	f := newFixture(t)
	repo := "/home/bob/repo"
	f.file(repo+"/.mcp.json", `{"mcpServers":{"bobs":{"command":"x"}}}`, 0o644)
	f.file(repo+"/.git/config", "[core]\n\tfsmonitor = ./x.sh\n", 0o644)
	for _, p := range []string{"/home/bob", repo, repo + "/.mcp.json", repo + "/.git", repo + "/.git/config"} {
		if err := os.Lchown(f.real(p), 1001, 1001); err != nil {
			t.Fatal(err)
		}
	}
	alice := f.user("alice")
	alice.UID = "1000"
	res, err := ScanProject(context.Background(), repo, alice, f.opts())
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Events) != 0 {
		for _, e := range res.Events {
			t.Errorf("read another user's file for alice: %s %s", e.Asset.Kind, e.Asset.Name)
		}
	}
	if res.Ledger.Denied == 0 {
		t.Errorf("refusals not counted: %+v", res.Ledger)
	}
	// The owner gets the same project scanned.
	bob := f.user("bob")
	bob.UID = "1001"
	res, err = ScanProject(context.Background(), repo, bob, f.opts())
	if err != nil {
		t.Fatal(err)
	}
	x := fixtureIndex{events: res.Events}
	if a := x.one(t, event.AssetMCPServer, "bobs"); a.Owner != "bob" {
		t.Errorf("owner = %q", a.Owner)
	}
}

// TestProcessAttributionSharedUID: two scanned homes with one uid (a home
// without a passwd entry is reported with its owner's uid) must not both be
// marked as running the same process. The account name decides; a process
// naming neither is reported machine-wide.
func TestProcessAttributionSharedUID(t *testing.T) {
	f := newFixture(t)
	f.dir("/root/.claude")
	f.dir("/home/user/.claude")
	root := platform.UserHome{Name: "root", UID: "0", Home: "/root"}
	other := platform.UserHome{Name: "user", UID: "0", Home: "/home/user"}
	o := f.opts(root, other)
	o.Processes = []platform.Proc{
		{PID: 42, Name: "claude", Exe: "/usr/local/bin/claude", Args: []string{"claude"}, UID: "0", User: "root"},
		{PID: 43, Name: "claude", Exe: "/usr/local/bin/claude", Args: []string{"claude", "-p", "x"}, UID: "0"},
	}
	res, err := Scan(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	byOwner := map[string]*event.Asset{}
	for _, a := range (fixtureIndex{events: res.Events}).find(event.AssetAgent, "claude-code") {
		byOwner[a.Owner] = a
	}
	if a := byOwner["root"]; a == nil || !a.Running || a.PID != 42 {
		t.Errorf("root's claude-code = %+v", a)
	}
	if a := byOwner["user"]; a == nil || a.Running {
		t.Errorf("user's claude-code = %+v (must exist from its state dir, not running)", a)
	}
	if a := byOwner[""]; a == nil || !a.Running || a.PID != 43 || a.Scope != event.ScopeSystem {
		t.Errorf("unattributable process: machine-wide asset = %+v", a)
	}
}

// TestScanProjectForeignListings: a privileged scan lists a directory in a
// user's tree only when that user owns it, and reports a skill only once
// its SKILL.md was read through the owner check. Otherwise another user's
// skill names and paths would be reported as this user's assets.
func TestScanProjectForeignListings(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create files owned by another user")
	}
	chown := func(f *fx, uid int, paths ...string) {
		t.Helper()
		for _, p := range paths {
			if err := os.Lchown(f.real(p), uid, uid); err != nil {
				t.Fatal(err)
			}
		}
	}
	alice := func(f *fx) platform.UserHome {
		u := f.user("alice")
		u.UID = "1000"
		return u
	}
	// Bob's whole repository.
	f := newFixture(t)
	repo := "/home/bob/repo"
	f.file(repo+"/.claude/skills/acquisition-plan/SKILL.md", "---\nname: acquisition-plan\n---\nsecret\n", 0o644)
	chown(f, 1001, "/home/bob", repo, repo+"/.claude", repo+"/.claude/skills",
		repo+"/.claude/skills/acquisition-plan", repo+"/.claude/skills/acquisition-plan/SKILL.md")
	res, err := ScanProject(context.Background(), repo, alice(f), f.opts())
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range res.Events {
		t.Errorf("alice's scan of bob's repository reported %s %q at %s", e.Asset.Kind, e.Asset.Name, e.Asset.Path)
	}
	if res.Ledger.Denied == 0 {
		t.Errorf("refused listing not counted: %+v", res.Ledger)
	}
	// Alice's repository with bob's entries planted inside (a shared
	// group-writable checkout): bob's directory is not listed, bob's
	// skill is not reported, alice's own skill is.
	f = newFixture(t)
	repo = "/srv/shared/app"
	f.file(repo+"/.claude/skills/mine/SKILL.md", "---\nname: mine\n---\nx\n", 0o644)
	f.file(repo+"/.claude/skills/bobs-skill/SKILL.md", "---\nname: bobs-skill\n---\nx\n", 0o644)
	f.file(repo+"/.claude/commands/bobs-command.md", "x\n", 0o644)
	chown(f, 1000, repo, repo+"/.claude", repo+"/.claude/skills", repo+"/.claude/skills/mine", repo+"/.claude/skills/mine/SKILL.md")
	chown(f, 1001, repo+"/.claude/skills/bobs-skill", repo+"/.claude/skills/bobs-skill/SKILL.md",
		repo+"/.claude/commands", repo+"/.claude/commands/bobs-command.md")
	res, err = ScanProject(context.Background(), repo, alice(f), f.opts())
	if err != nil {
		t.Fatal(err)
	}
	x := fixtureIndex{events: res.Events}
	if len(x.find(event.AssetSkill, "mine")) != 1 {
		t.Errorf("alice's own skill not reported: %+v", res.Ledger)
	}
	for _, e := range res.Events {
		if strings.HasPrefix(e.Asset.Name, "bobs") {
			t.Errorf("bob's %s %q reported as alice's", e.Asset.Kind, e.Asset.Name)
		}
	}
	// Directories in alice's home that bob owns (an Options.Env relocation
	// or a planted tree): entries named only by a listing, a plugin per
	// entry and an editor extension per directory name, are not hers.
	f = newFixture(t)
	h := "/home/alice"
	f.dir(h + "/.openclaw/extensions/bobs-plugin")
	f.file(h+"/.vscode/extensions/github.copilot-chat-0.30.0/package.json", `{"publisher":"GitHub","name":"copilot-chat","version":"0.30.0"}`, 0o644)
	f.dir(h + "/.openclaw/own")
	chown(f, 1000, h, h+"/.openclaw", h+"/.vscode")
	chown(f, 1001, h+"/.openclaw/extensions", h+"/.openclaw/extensions/bobs-plugin", h+"/.vscode/extensions",
		h+"/.vscode/extensions/github.copilot-chat-0.30.0", h+"/.vscode/extensions/github.copilot-chat-0.30.0/package.json")
	o := f.opts(alice(f))
	o.Projects = false
	full, err := Scan(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range full.Events {
		if e.Asset.Kind == event.AssetPlugin || e.Asset.Kind == event.AssetIDEExtension {
			t.Errorf("listing of bob's directory reported %s %q for alice", e.Asset.Kind, e.Asset.Name)
		}
	}
	if full.Ledger.Denied < 2 {
		t.Errorf("refused listings not counted: %+v", full.Ledger)
	}
}
