//go:build linux || darwin

package discovery

import (
	"context"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// TestHostRootSymlinksStayInside plants links inside a container root that
// point at absolute paths of the node. Nothing outside the root may be read.
func TestHostRootSymlinksStayInside(t *testing.T) {
	outside := t.TempDir() // the "node"
	secretDir := filepath.Join(outside, "nodeetc")
	if err := os.MkdirAll(filepath.Join(secretDir, "windsurf"), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(p, body string) {
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	nodeSecret := filepath.Join(outside, "shadow")
	write(nodeSecret, `{"mcpServers":{"escaped-file":{"command":"x"}}}`)
	write(filepath.Join(secretDir, "windsurf", "mcp_config.json"), `{"mcpServers":{"escaped-dir":{"command":"x"}}}`)
	write(filepath.Join(secretDir, "managed-mcp.json"), `{"mcpServers":{"escaped-system":{"command":"x"}}}`)

	f := newFixture(t)
	f.dir("/home/alice")
	// final component: a config that is a link to a node file
	f.symlink("/home/alice/.cursor/mcp.json", nodeSecret)
	// intermediate component in a home: a directory link to a node directory
	f.symlink("/home/alice/.codeium", secretDir)
	// intermediate component in a system path, absolute target: re-rooted
	f.symlink("/etc/claude-code", secretDir)
	// relative link climbing out of the root
	f.symlink("/home/alice/.gemini", "../../../../../../../../.."+secretDir)

	res, err := Scan(context.Background(), f.opts(f.user("alice")))
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range res.Events {
		b, _ := e.MarshalLine()
		if strings.Contains(string(b), "escaped") {
			t.Errorf("a node file was read through a container link: %s", b)
		}
	}
	if res.Ledger.Denied+res.Ledger.Skipped == 0 {
		t.Errorf("refusals were not counted: %+v", res.Ledger)
	}
}

// TestOpenerConfinement exercises both resolution strategies directly:
// openat2 (where the kernel has it) and the O_NOFOLLOW component walk.
func TestOpenerConfinement(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret"), []byte("node"), 0o644); err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	mk := func(p string) {
		if err := os.MkdirAll(filepath.Join(root, p), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	mk("home/a/real")
	mk("etc")
	if err := os.WriteFile(filepath.Join(root, "home/a/real/f.json"), []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/secret"), []byte("inner"), 0o644); err != nil {
		t.Fatal(err)
	}
	links := map[string]string{
		"home/a/abs":      filepath.Join(outside, "secret"),
		"home/a/absdir":   outside,
		"home/a/inner":    "real",        // stays inside: allowed below a home with openat2
		"home/a/up":       "../../../..", // climbs out
		"home/a/etclink":  "/etc",
		"home/a/real/lnk": "f.json",
	}
	for l, target := range links {
		if err := os.Symlink(target, filepath.Join(root, l)); err != nil {
			t.Fatal(err)
		}
	}
	for _, mode := range []string{"openat2", "walk"} {
		t.Run(mode, func(t *testing.T) {
			op, err := newOpener(root)
			if err != nil {
				t.Fatal(err)
			}
			defer op.close()
			uo := op.(*unixOpener)
			if mode == "walk" {
				uo.useOpenat.Store(false)
			} else if !openat2Supported {
				t.Skip("no openat2 on this OS")
			}
			read := func(rootDir, rel string) (string, error) {
				f, err := op.openFile(rootDir, rel)
				if err != nil {
					return "", err
				}
				defer f.Close()
				b := make([]byte, 16)
				n, _ := f.Read(b)
				return string(b[:n]), nil
			}
			if s, err := read("/home/a", "real/f.json"); err != nil || s != "{}" {
				t.Fatalf("plain file: %q %v", s, err)
			}
			for _, rel := range []string{"abs", "absdir/secret", "up/secret", "real/lnk", "etclink/secret"} {
				if s, err := read("/home/a", rel); err == nil {
					t.Errorf("%s: read %q through a link", rel, s)
				}
			}
			// A link to a directory that stays inside the home: openat2
			// follows it, the walk refuses it; neither leaves the root.
			s, err := read("/home/a", "inner/f.json")
			if mode == "walk" && err == nil {
				t.Errorf("walk followed an intermediate link: %q", s)
			}
			if mode == "openat2" && uo.useOpenat.Load() && (err != nil || s != "{}") {
				t.Errorf("openat2 refused a link that stays inside the home: %q %v", s, err)
			}
			// A system directory reached through an absolute link inside the
			// root resolves inside the root (RESOLVE_IN_ROOT) or is refused.
			if s, err := read("/home/a/etclink", "secret"); err == nil && s != "inner" {
				t.Errorf("etclink resolved outside the root: %q", s)
			}
			if _, err := op.openFile("/home/a", "real"); !errors.Is(err, errNotReg) && err == nil {
				t.Error("a directory opened as a file")
			}
			m, err := op.lstat("/home/a", "abs")
			if err != nil || m.kind != kindSymlink {
				t.Errorf("lstat link: %+v %v", m, err)
			}
			if tgt, err := op.readlink("/home/a", "abs"); err != nil || tgt == "" {
				t.Errorf("readlink: %q %v", tgt, err)
			}
			if _, err := op.openDir("/home/a", "absdir"); err == nil {
				t.Error("listed a linked directory")
			}
			if _, err := op.openFile("/home/a", "missing"); !errors.Is(err, fs.ErrNotExist) {
				t.Errorf("missing file error = %v", err)
			}
			if mode == "openat2" && !uo.useOpenat.Load() {
				t.Log("openat2 unavailable here (ENOSYS/EPERM): the walk was used")
			}
		})
	}
}

// TestFIFONeverBlocks: a FIFO where a config is expected is skipped at once.
func TestFIFONeverBlocks(t *testing.T) {
	f := newFixture(t)
	f.fifo("/home/alice/.claude.json")
	f.fifo("/home/alice/.claude/settings.json")
	f.fifo("/home/alice/.claude/skills/x/SKILL.md")
	o := f.opts(f.user("alice"))
	res, err := Scan(context.Background(), o)
	if err != nil {
		t.Fatal(err)
	}
	if res.Ledger.Skipped == 0 {
		t.Errorf("FIFOs not counted as skipped: %+v", res.Ledger)
	}
}

// TestMultiUserOwnership needs root: files must belong to the home's owner.
func TestMultiUserOwnership(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to create files owned by several users")
	}
	f := newFixture(t)
	alice := f.user("alice")
	alice.UID = "1000"
	bob := f.user("bob")
	bob.UID = "1001"
	f.file("/home/alice/.cursor/mcp.json", `{"mcpServers":{"alice-srv":{"command":"x"}}}`, 0o644)
	f.file("/home/alice/.gemini/settings.json", `{"mcpServers":{"planted-by-bob":{"command":"x"}}}`, 0o644)
	f.file("/home/bob/.cursor/mcp.json", `{"mcpServers":{"bob-srv":{"command":"x"}}}`, 0o644)
	f.file("/home/bob/.claude/settings.json", `{}`, 0o644)
	chown := func(p string, uid int) {
		if err := os.Lchown(f.real(p), uid, uid); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{"/home/alice", "/home/alice/.cursor", "/home/alice/.cursor/mcp.json", "/home/alice/.gemini"} {
		chown(p, 1000)
	}
	chown("/home/alice/.gemini/settings.json", 1001)
	for _, p := range []string{"/home/bob", "/home/bob/.cursor", "/home/bob/.cursor/mcp.json", "/home/bob/.claude", "/home/bob/.claude/settings.json"} {
		chown(p, 1001)
	}
	res, err := Scan(context.Background(), f.opts(alice, bob))
	if err != nil {
		t.Fatal(err)
	}
	x := fixtureIndex{events: res.Events}
	if a := x.one(t, event.AssetMCPServer, "alice-srv"); a.Owner != "alice" {
		t.Errorf("alice-srv owner = %s", a.Owner)
	}
	if a := x.one(t, event.AssetMCPServer, "bob-srv"); a.Owner != "bob" {
		t.Errorf("bob-srv owner = %s", a.Owner)
	}
	if l := x.find(event.AssetMCPServer, "planted-by-bob"); len(l) != 0 {
		t.Errorf("a file bob owns in alice's home was attributed to alice: %+v", l[0])
	}
	if res.Ledger.Denied == 0 {
		t.Error("ownership refusal not counted")
	}
	checks := 0
	for _, e := range res.Events {
		owner := ""
		switch {
		case e.Asset != nil:
			owner = e.Asset.Owner
		case e.Check != nil:
			owner = e.Check.Owner
			checks++
			if e.Check.Subject != "/home/alice/.gemini/settings.json" || e.Check.Severity != event.SevHigh {
				t.Errorf("posture check for the planted file: %+v", e.Check)
			}
		default:
			t.Fatalf("event with neither asset nor check: %+v", e)
		}
		if e.User == nil || (e.User.Name != owner && owner != "") {
			t.Errorf("event user %+v does not match owner %q", e.User, owner)
		}
	}
	if checks != 1 {
		t.Errorf("%d posture checks, want 1 for bob's file in alice's home", checks)
	}
}

// TestGateScopeBudgets: each scope (the machine-wide pass, a home, a
// project) spends its own directory-entry budget; exhausting one leaves the
// next untouched, and the enclosing scope's remainder is restored.
func TestGateScopeBudgets(t *testing.T) {
	root := t.TempDir()
	for i := 0; i < 20; i++ {
		if err := os.WriteFile(filepath.Join(root, "f"+strings.Repeat("x", i)), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	g, err := newGate(context.Background(), newLedger(), "", false, "linux")
	if err != nil {
		t.Fatal(err)
	}
	defer g.close()
	l := loc{root: filepath.ToSlash(root)}
	restoreOuter := g.scope("home a", 30, 0)
	if _, err := g.readDir(l); err != nil {
		t.Fatal(err)
	}
	if _, err := g.readDir(l); !errors.Is(err, errBudget) {
		t.Fatalf("second listing within a 30-entry budget: %v", err)
	}
	restore := g.scope("project b", 30, 0)
	if _, err := g.readDir(l); err != nil {
		t.Errorf("a fresh scope inherited an exhausted budget: %v", err)
	}
	restore()
	if _, err := g.readDir(l); !errors.Is(err, errBudget) {
		t.Errorf("restored scope regained budget: %v", err)
	}
	restoreOuter()
	if _, err := g.readDir(l); err != nil {
		t.Errorf("the machine-wide budget was spent by a home: %v", err)
	}
}
