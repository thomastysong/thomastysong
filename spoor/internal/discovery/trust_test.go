package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/platform"
)

// The owner rule as a decision table: it runs on every OS and needs no
// privilege (the scan test below needs root to create foreign files).
func TestUntrustedWhy(t *testing.T) {
	g := &gate{adminUID: "0"}
	g.acctOnce.Do(func() {})
	g.acct = &acctDB{
		// alice (1000) has a private group 1000; staff (50) is bob's
		// primary group and alice is a member; root's group 0 is private.
		primary: map[string][]string{"0": {"0"}, "1000": {"1000"}, "50": {"1001"}, "60": {"1000"}},
		name:    map[string]string{"0": "root", "1000": "alice", "1001": "bob"},
		members: map[string][]string{"50": {"alice"}, "60": {"bob"}},
	}
	for _, tc := range []struct {
		name  string
		m     fmeta
		ok    bool
		cause string
	}{
		{"account owns it, 0644", fmeta{owner: "1000", group: "1000", perm: 0o644, nlink: 1}, true, ""},
		{"account owns it, 0600", fmeta{owner: "1000", group: "1000", perm: 0o600, nlink: 1}, true, ""},
		{"account, hard-linked by itself", fmeta{owner: "1000", group: "1000", perm: 0o644, nlink: 3}, true, ""},
		{"root provisioned it read-only", fmeta{owner: "0", group: "0", perm: 0o644, nlink: 1}, true, ""},
		{"root-owned with two links", fmeta{owner: "0", group: "0", perm: 0o640, nlink: 2}, false, "links"},
		{"another account owns it", fmeta{owner: "1001", group: "1001", perm: 0o644, nlink: 1}, false, "owned by uid 1001"},
		{"world-writable", fmeta{owner: "1000", group: "1000", perm: 0o666, nlink: 1}, false, "every account"},
		{"world-writable root file", fmeta{owner: "0", group: "0", perm: 0o646, nlink: 1}, false, "every account"},
		{"group-writable, private group (umask 002)", fmeta{owner: "1000", group: "1000", perm: 0o664, nlink: 1}, true, ""},
		{"group-writable, shared group", fmeta{owner: "1000", group: "50", perm: 0o664, nlink: 1}, false, "group 50"},
		{"group-writable, alice's primary but bob is a member", fmeta{owner: "1000", group: "60", perm: 0o664, nlink: 1}, false, "group 60"},
		{"group-writable, unknown group", fmeta{owner: "1000", group: "4242", perm: 0o660, nlink: 1}, false, "group 4242"},
		{"group-writable root file, root's private group", fmeta{owner: "0", group: "0", perm: 0o664, nlink: 1}, true, ""},
		// Provisioned by root for the account to edit: writable by root and
		// the account only.
		{"group-writable root file, the account's private group", fmeta{owner: "0", group: "1000", perm: 0o664, nlink: 1}, true, ""},
		{"group-writable root file, a group bob is in", fmeta{owner: "0", group: "60", perm: 0o664, nlink: 1}, false, "group 60"},
		{"group-writable root file, bob's group", fmeta{owner: "0", group: "50", perm: 0o664, nlink: 1}, false, "group 50"},
		{"group-writable account file, root's private group", fmeta{owner: "1000", group: "0", perm: 0o664, nlink: 1}, true, ""},
		{"bob's file in the account's private group", fmeta{owner: "1001", group: "1000", perm: 0o644, nlink: 1}, false, "owned by uid 1001"},
	} {
		why := g.untrustedWhy(tc.m, "1000")
		if (why == "") != tc.ok || !strings.Contains(why, tc.cause) {
			t.Errorf("%s: untrustedWhy = %q, want ok=%v (%q)", tc.name, why, tc.ok, tc.cause)
		}
	}
	// The account is root: a root-owned file with several links is its own.
	if why := g.untrustedWhy(fmeta{owner: "0", group: "0", perm: 0o644, nlink: 2}, "0"); why != "" {
		t.Errorf("root's own hard link refused: %s", why)
	}
	// Without an account database no group is private.
	g2 := &gate{adminUID: "0"}
	g2.acctOnce.Do(func() {})
	if why := g2.untrustedWhy(fmeta{owner: "1000", group: "1000", perm: 0o664, nlink: 1}, "1000"); why == "" {
		t.Error("group-writable file trusted without an account database")
	}
}

// checkFile: system files and files outside the home keep their rules;
// inside the home the owner rule applies whatever the privilege, and a
// refusal wraps errUntrusted and reaches the callback.
func TestCheckFileScopes(t *testing.T) {
	var heard []string
	g := &gate{adminUID: "0", untrusted: func(l loc, m fmeta, why string) { heard = append(heard, l.String()) }}
	g.acctOnce.Do(func() {})
	foreign := fmeta{owner: "1001", group: "1001", perm: 0o644, hasOwner: true, nlink: 1}
	home := loc{root: "/home/alice", rel: ".cursor/mcp.json", home: true, user: true, uid: "1000", inHome: true}
	if err := g.checkFile(home, foreign, "1000"); !errors.Is(err, errUntrusted) || !strings.Contains(err.Error(), "uid 1001") {
		t.Fatalf("foreign file in the home: %v", err)
	}
	if len(heard) != 1 || heard[0] != "/home/alice/.cursor/mcp.json" {
		t.Fatalf("callback: %v", heard)
	}
	if err := g.checkFile(systemLoc("/etc/codex/config.toml"), foreign, ""); err != nil {
		t.Errorf("system file: %v", err)
	}
	outside := loc{root: "/srv/repos/tool", rel: ".mcp.json", user: true, uid: "1000"}
	if err := g.checkFile(outside, foreign, "1000"); err != nil {
		t.Errorf("unprivileged, project outside the home: %v (the older rule applies)", err)
	}
	g.priv = true
	if err := g.checkFile(outside, foreign, "1000"); !errors.Is(err, errOwner) {
		t.Errorf("privileged, project outside the home: %v", err)
	}
	if err := g.checkFile(home, fmeta{owner: "1000", perm: 0o644, hasOwner: true, nlink: 1}, "1000"); err != nil {
		t.Errorf("the account's own file: %v", err)
	}
	// Windows: no owner known, nothing to check.
	if err := g.checkFile(home, fmeta{perm: 0o666}, "1000"); err != nil {
		t.Errorf("no owner: %v", err)
	}
}

// TestOwnerRuleScan plants, in alice's home, files the owner rule must
// refuse (another account's, world- or shared-group-writable, a hard link
// to a root file) next to files it must read (root-provisioned, a private
// group with umask 002), and checks that no refused file's content reaches
// any record, that each is reported as untrusted_owner posture (on the
// agent, or as a project_config asset in a project), and that the files it
// trusts are read.
func TestOwnerRuleScan(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create files owned by several accounts")
	}
	f := newFixture(t)
	h := "/home/alice"
	f.file("/etc/passwd", "root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\nbob:x:1001:50::/home/bob:/bin/sh\n", 0o644)
	f.file("/etc/group", "root:x:0:\nstaff:x:50:alice\nalice:x:1000:\n", 0o644)
	// Content of every refused file carries a canary name.
	f.file(h+"/.factory/mcp.json", `{"mcpServers":{"rootprovisioned":{"command":"x"}}}`, 0o644)
	f.file(h+"/.claude.json", `{"mcpServers":{"privategroup":{"command":"x"}}}`, 0o664)
	f.file(h+"/.cursor/mcp.json", `{"mcpServers":{"canary-bobs":{"command":"x"}}}`, 0o644)
	f.file(h+"/.gemini/settings.json", `{"mcpServers":{"canary-worldwritable":{"command":"x"}}}`, 0o644)
	f.file(h+"/.codex/config.toml", "[mcp_servers.canary-sharedgroup]\ncommand = \"x\"\n", 0o664)
	f.file("/etc/spoor-secret.json", `{"mcpServers":{"canary-hardlink":{"command":"x"}}}`, 0o600)
	f.dir(h + "/.copilot")
	if err := os.Link(f.real("/etc/spoor-secret.json"), f.real(h+"/.copilot/mcp-config.json")); err != nil {
		t.Fatal(err)
	}
	project := h + "/src/app"
	f.file(project+"/.mcp.json", `{"mcpServers":{"canary-project":{"command":"x"}}}`, 0o644)
	f.file(project+"/.cursor/mcp.json", `{"mcpServers":{"projectok":{"command":"x"}}}`, 0o644)
	f.file(h+"/.claude/projects/-home-alice-src-app/s.jsonl", `{"cwd":"`+project+`","type":"user"}`+"\n", 0o600)

	chown := func(p string, uid, gid int) {
		t.Helper()
		if err := os.Lchown(f.real(p), uid, gid); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{h, h + "/.factory", h + "/.claude.json", h + "/.cursor", h + "/.gemini", h + "/.gemini/settings.json",
		h + "/.codex", h + "/.copilot", h + "/src", project, project + "/.cursor", project + "/.cursor/mcp.json",
		h + "/.claude", h + "/.claude/projects", h + "/.claude/projects/-home-alice-src-app", h + "/.claude/projects/-home-alice-src-app/s.jsonl"} {
		chown(p, 1000, 1000)
	}
	chown(h+"/.factory/mcp.json", 0, 0)
	chown(h+"/.cursor/mcp.json", 1001, 50)
	chown(project+"/.mcp.json", 1001, 50)
	chown(h+"/.codex/config.toml", 1000, 50)
	// chmod after chown: chown clears nothing here, but be explicit.
	if err := os.Chmod(f.real(h+"/.gemini/settings.json"), 0o666); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(f.real(h+"/.codex/config.toml"), 0o664); err != nil {
		t.Fatal(err)
	}

	alice := f.user("alice")
	alice.UID = "1000"
	o := f.opts(alice)
	o.adminUID = "0"
	res, err := Scan(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(res)
	if strings.Contains(string(b), "canary-") {
		t.Fatalf("content of a refused file reached the result:\n%s", b)
	}
	x := fixtureIndex{events: res.Events}
	for _, name := range []string{"rootprovisioned", "privategroup", "projectok"} {
		if a := x.one(t, event.AssetMCPServer, name); a.Owner != "alice" {
			t.Errorf("%s owner %q", name, a.Owner)
		}
	}
	// One record per refused file, parented to the agent whose location
	// holds it (the agent asset itself need not exist: ~/.cursor alone is
	// shared by two products and identifies neither).
	for rel, parent := range map[string]string{".cursor/mcp.json": "cursor", ".gemini/settings.json": "gemini-cli", ".codex/config.toml": "codex", ".copilot/mcp-config.json": "copilot-cli"} {
		a := x.one(t, event.AssetProjectConfig, rel)
		if !has(a.RiskFlags, flagUntrustedOwner) || a.Scope != event.ScopeUser || a.Path != h+"/"+rel || a.Owner != "alice" || a.SHA256 != "" || a.Detail[flagUntrustedOwner] == "" {
			t.Errorf("%s: %+v", rel, a)
		}
		if a.Parent != parent && !(parent == "cursor" && strings.HasPrefix(a.Parent, "cursor")) {
			t.Errorf("%s: parent %q, want %q", rel, a.Parent, parent)
		}
	}
	for _, e := range res.Events {
		if a := e.Asset; a != nil && has(a.RiskFlags, flagUntrustedOwner) && (a.Name == ".claude.json" || a.Name == ".factory/mcp.json") {
			t.Errorf("a trusted file was reported: %+v", a)
		}
	}
	pc := x.one(t, event.AssetProjectConfig, ".mcp.json")
	if !has(pc.RiskFlags, flagUntrustedOwner) || pc.SHA256 != "" || pc.Scope != event.ScopeProject ||
		!strings.Contains(pc.Detail[flagUntrustedOwner], "uid 1001") || pc.Detail["project"] != project {
		t.Errorf("project file: %+v", pc)
	}
	// Each refused file is also a failing posture check on its asset: high
	// when someone else wrote it, medium when only its mode lets others.
	sev := map[string]string{h + "/.cursor/mcp.json": event.SevHigh, h + "/.copilot/mcp-config.json": event.SevHigh,
		project + "/.mcp.json": event.SevHigh, h + "/.gemini/settings.json": event.SevMedium, h + "/.codex/config.toml": event.SevMedium}
	ids := map[string]string{}
	for _, e := range res.Events {
		if a := e.Asset; a != nil && has(a.RiskFlags, flagUntrustedOwner) {
			ids[a.Path] = a.ID
		}
	}
	got := map[string]bool{}
	for _, e := range res.Events {
		c := e.Check
		if c == nil {
			continue
		}
		want, ok := sev[c.Subject]
		if e.Kind != event.KindPosture || e.Type != event.TypePostureCheck || !ok || c.ID != checkUntrustedOwner || c.Status != "fail" ||
			c.Severity != want || c.AssetID == "" || c.AssetID != ids[c.Subject] || c.Owner != "alice" || c.Actual == "" || c.Remedy == "" ||
			e.User == nil || e.User.Name != "alice" {
			t.Errorf("posture check %+v (event %s/%s)", c, e.Kind, e.Type)
		}
		got[c.Subject] = true
	}
	for p := range sev {
		if !got[p] {
			t.Errorf("no posture check for refused %s", p)
		}
	}
	notes := strings.Join(res.Ledger.Notes, "\n")
	for _, w := range []string{"owned by uid 1001", "writable by every account", "writable by group 50", "links"} {
		if !strings.Contains(notes, w) {
			t.Errorf("ledger notes lack %q:\n%s", w, notes)
		}
	}
	if res.Ledger.Denied < 5 {
		t.Errorf("refusals not counted as denied: %+v", res.Ledger)
	}
}

// ScanProject (a session started in a project of the home) reports the
// refused file the same way and reads the rest.
func TestOwnerRuleScanProject(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create files owned by several accounts")
	}
	f := newFixture(t)
	project := "/home/alice/work/site"
	f.file(project+"/.mcp.json", `{"mcpServers":{"canary-planted":{"command":"x"}}}`, 0o644)
	f.file(project+"/.vscode/tasks.json", `{"version":"2.0.0","tasks":[{"label":"x","command":"make","runOptions":{"runOn":"folderOpen"}}]}`, 0o644)
	for _, p := range []string{"/home/alice", "/home/alice/work", project, project + "/.vscode", project + "/.vscode/tasks.json"} {
		if err := os.Lchown(f.real(p), 1000, 1000); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Lchown(f.real(project+"/.mcp.json"), 1001, 1001); err != nil {
		t.Fatal(err)
	}
	alice := f.user("alice")
	alice.UID = "1000"
	o := f.opts()
	o.adminUID = "0"
	res, err := ScanProject(context.Background(), project, alice, o)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(res)
	if strings.Contains(string(b), "canary-planted") {
		t.Fatal("the refused file was read")
	}
	x := fixtureIndex{events: res.Events}
	if pc := x.one(t, event.AssetProjectConfig, ".mcp.json"); !has(pc.RiskFlags, flagUntrustedOwner) {
		t.Errorf("planted .mcp.json: %+v", pc)
	}
	if pc := x.one(t, event.AssetProjectConfig, ".vscode/tasks.json"); has(pc.RiskFlags, flagUntrustedOwner) {
		t.Errorf("the account's own tasks.json flagged: %+v", pc)
	}
}

// The refusals kept are bounded per directory and per account, not per
// scan: alice filling her own home with refused files (300 world-writable
// SKILL.md) hides nothing in bob's home, and inside her home a file another
// account wrote displaces one that is only world-writable. What is over the
// caps becomes one summary check.
func TestUntrustedCapPerHome(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create files owned by several accounts")
	}
	f := newFixture(t)
	f.file("/etc/passwd", "root:x:0:0:root:/root:/bin/sh\nalice:x:1000:1000::/home/alice:/bin/sh\nbob:x:1001:1001::/home/bob:/bin/sh\n", 0o644)
	f.file("/etc/group", "root:x:0:\nalice:x:1000:\nbob:x:1001:\n", 0o644)
	const n = 300
	for i := 0; i < n; i++ {
		f.file(fmt.Sprintf("/home/alice/.claude/skills/s%03d/SKILL.md", i), "---\nname: s\n---\n", 0o666)
	}
	// Read after the cap is full: bob's planted skill in alice's home.
	f.file("/home/alice/.claude/skills/zzz/SKILL.md", "---\nname: canary-planted\n---\n", 0o644)
	// bob: an MCP config planted by alice.
	f.file("/home/bob/.cursor/mcp.json", `{"mcpServers":{"canary-planted":{"command":"x"}}}`, 0o644)
	chownR := func(dir string, uid, gid int) {
		t.Helper()
		err := filepath.WalkDir(f.real(dir), func(p string, _ fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			return os.Lchown(p, uid, gid)
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	chownR("/home/alice", 1000, 1000)
	chownR("/home/bob", 1001, 1001)
	for p, uid := range map[string]int{"/home/bob/.cursor/mcp.json": 1000, "/home/alice/.claude/skills/zzz/SKILL.md": 1001} {
		if err := os.Lchown(f.real(p), uid, uid); err != nil {
			t.Fatal(err)
		}
	}
	alice := platform.UserHome{Name: "alice", UID: "1000", Home: "/home/alice"}
	bob := platform.UserHome{Name: "bob", UID: "1001", Home: "/home/bob"}
	o := f.opts(alice, bob)
	o.adminUID = "0"
	o.Projects = false
	res, err := Scan(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(res)
	if strings.Contains(string(b), "canary-") {
		t.Fatal("content of a refused file reached the result")
	}
	assets := map[string]int{}
	var planted []string
	for _, e := range res.Events {
		if a := e.Asset; a != nil && has(a.RiskFlags, flagUntrustedOwner) {
			assets[a.Owner]++
			if a.Path == "/home/bob/.cursor/mcp.json" || a.Path == "/home/alice/.claude/skills/zzz/SKILL.md" {
				planted = append(planted, a.Path)
			}
		}
	}
	if len(planted) != 2 {
		t.Errorf("planted files reported: %v (untrusted_owner assets per account %v)", planted, assets)
	}
	if assets["alice"] != maxUntrustedPerDir || assets["bob"] != 1 {
		t.Errorf("untrusted_owner assets per account %v, want alice %d, bob 1", assets, maxUntrustedPerDir)
	}
	var summary *event.Check
	for _, e := range res.Events {
		if c := e.Check; c != nil && c.AssetID == "" {
			if summary != nil {
				t.Fatalf("two summary checks: %+v, %+v", summary, c)
			}
			summary = c
		}
	}
	// 301 refused in alice's home, 64 listed: 237 more, all hers.
	want := fmt.Sprintf("%d more refused files are not listed (0 written by another account)", n+1-maxUntrustedPerDir)
	if summary == nil || summary.Subject != "/home/alice" || summary.Owner != "alice" || summary.Severity != event.SevMedium ||
		summary.ID != checkUntrustedOwner || !strings.HasPrefix(summary.Actual, want) {
		t.Errorf("summary check %+v, want subject /home/alice and %q", summary, want)
	}
	if res.Ledger.Denied < n+2 {
		t.Errorf("refusals over the cap not counted as denied: %+v", res.Ledger)
	}
}

// recordUntrusted directly: the per-account cap holds across directories,
// a foreign file displaces only a non-foreign one of its own directory, the
// same path counts once, and the summary says how many foreign files were
// dropped.
func TestRecordUntrustedCaps(t *testing.T) {
	s := &scanner{goos: "linux", adminUID: "0", untrusted: map[string]*untrustedSet{}, untrustedKept: map[string]int{},
		untrustedSeen: map[string]bool{}, led: newLedger()}
	own := fmeta{owner: "1000", perm: 0o666, nlink: 1}
	foreign := fmeta{owner: "1001", perm: 0o644, nlink: 1}
	at := func(root string, i int) loc {
		return loc{root: root, rel: fmt.Sprintf("f%04d", i), user: true, uid: "1000", inHome: true}
	}
	for i := 0; i < maxUntrustedPerDir+10; i++ {
		s.recordUntrusted(at("/home/alice", i), own, "w")
	}
	s.recordUntrusted(at("/home/alice", 0), own, "w") // again: not counted twice
	home := s.untrusted[s.untrustedKey("1000", "/home/alice")]
	if len(home.files) != maxUntrustedPerDir || home.dropped != 10 {
		t.Fatalf("home set: %d kept, %d dropped", len(home.files), home.dropped)
	}
	s.recordUntrusted(at("/home/alice", 9000), foreign, "planted")
	if home.dropped != 11 || home.droppedForeign != 0 || !home.files[len(home.files)-1].foreign {
		t.Fatalf("foreign file did not displace a world-writable one: dropped %d/%d", home.dropped, home.droppedForeign)
	}
	// Fill the account cap through projects.
	for p := 0; s.untrustedKept["1000"] < maxUntrustedPerAccount; p++ {
		s.recordUntrusted(at(fmt.Sprintf("/home/alice/p%d", p), 0), own, "w")
	}
	s.recordUntrusted(at("/home/alice/late", 0), foreign, "planted")
	late := s.untrusted[s.untrustedKey("1000", "/home/alice/late")]
	if late == nil || len(late.files) != 0 || late.dropped != 1 || late.droppedForeign != 1 {
		t.Fatalf("over the account cap: %+v", late)
	}
	// Another account is unaffected.
	s.recordUntrusted(loc{root: "/home/bob", rel: "x", user: true, uid: "1001", inHome: true}, fmeta{owner: "1000", perm: 0o644, nlink: 1}, "planted")
	if bob := s.untrusted[s.untrustedKey("1001", "/home/bob")]; bob == nil || len(bob.files) != 1 || !bob.files[0].foreign {
		t.Fatalf("bob's set: %+v", bob)
	}
	uc := &userCtx{u: platform.UserHome{Name: "alice", UID: "1000", Home: "/home/alice"}, home: "/home/alice"}
	s.reportUntrusted(uc, "/home/alice/late", true)
	if len(s.checks) != 1 || s.checks[0].c.Severity != event.SevHigh || s.checks[0].c.Scope != event.ScopeProject ||
		!strings.Contains(s.checks[0].c.Actual, "1 more refused files are not listed (1 written by another account)") {
		t.Fatalf("summary for a dropped foreign file: %+v", s.checks)
	}
}
