package discovery

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
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
	for _, e := range res.Events {
		if a := e.Asset; a != nil && a.Kind == event.AssetAgent {
			t.Logf("agent %s %s evidence %v flags %v", a.CatalogID, a.Owner, a.Evidence, a.RiskFlags)
		}
	}
	flagged := map[string]string{}
	for _, e := range res.Events {
		if a := e.Asset; a != nil && has(a.RiskFlags, flagUntrustedOwner) {
			flagged[firstNonEmptyStr(a.CatalogID, a.Name)] = a.Detail[flagUntrustedOwner]
		}
	}
	for id, path := range map[string]string{"cursor": "/.cursor/mcp.json", "gemini-cli": "/.gemini/settings.json", "codex": "/.codex/config.toml", "copilot-cli": "/.copilot/mcp-config.json"} {
		if d, ok := flagged[id]; !ok || !strings.Contains(d, h+path) {
			t.Errorf("%s: untrusted_owner not reported (detail %q); flagged: %v", id, d, flagged)
		}
	}
	if d := flagged["claude-code"]; d != "" {
		t.Errorf("claude-code flagged for a trusted file: %s", d)
	}
	pc := x.one(t, event.AssetProjectConfig, ".mcp.json")
	if !has(pc.RiskFlags, flagUntrustedOwner) || pc.SHA256 != "" || !strings.Contains(pc.Detail[flagUntrustedOwner], "uid 1001") || pc.Detail["project"] != project {
		t.Errorf("project file: %+v", pc)
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

func firstNonEmptyStr(v ...string) string {
	for _, s := range v {
		if s != "" {
			return s
		}
	}
	return ""
}
