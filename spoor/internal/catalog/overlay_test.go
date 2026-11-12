package catalog

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeFile(t testing.TB, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestOverlayAddsAProduct(t *testing.T) {
	c := mustLoad(t)
	base := c.Len()
	dir := t.TempDir()
	writeFile(t, dir, "10-acme.yaml", `
ambiguous_names: [bob]
interpreters: {ruby: npm}
products:
  - id: acme-agent
    name: Acme Agent
    vendor: Acme
    kind: agent
    binaries: [acme-agent, bob]
    packages: [npm:@acme/agent]
    bundle_ids: [com.acme.agent]
    install_paths: {posix: ["~/.acme/bin"]}
    state_dirs: ["~/.acme"]
    env_markers: [ACME_AGENT]
    risky_flags: [--no-guardrails]
    ports: [45454]
    api_hosts: [api.acme.example]
`)
	// Files that are not YAML, and dotfiles, are ignored.
	writeFile(t, dir, "README.txt", "not yaml: [")
	writeFile(t, dir, ".hidden.yaml", "products: [{id: BAD}]")
	if err := c.LoadOverlay(dir); err != nil {
		t.Fatalf("LoadOverlay: %v", err)
	}
	if c.Len() != base+1 {
		t.Errorf("Len = %d, want %d", c.Len(), base+1)
	}
	p, ok := c.Get("acme-agent")
	if !ok || p.Name != "Acme Agent" {
		t.Fatalf("overlay product missing: %+v", p)
	}
	if got, ok := c.ByPackage("npm", "@acme/agent"); !ok || got.ID != "acme-agent" {
		t.Error("overlay package is not indexed")
	}
	if got, ok := c.ByBundleID("com.acme.agent"); !ok || got.ID != "acme-agent" {
		t.Error("overlay bundle id is not indexed")
	}
	if got, ok := c.MatchProcess("acme-agent", "", nil); !ok || got.ID != "acme-agent" {
		t.Error("overlay binary does not match")
	}
	// The overlay declared "bob" ambiguous: name alone fails, path helps.
	if _, ok := c.MatchProcess("bob", "/usr/bin/bob", nil); ok {
		t.Error("overlay ambiguous name matched alone")
	}
	if got, ok := c.MatchProcess("bob", "/home/dev/.acme/bin/bob", nil); !ok || got.ID != "acme-agent" {
		t.Error("overlay ambiguous name did not match with path evidence")
	}
	// The overlay added ruby as an interpreter for npm-style shims.
	if got, ok := c.MatchProcess("ruby", "/usr/bin/ruby", []string{"ruby", "/usr/local/bin/acme-agent"}); !ok || got.ID != "acme-agent" {
		t.Error("overlay interpreter is not honoured")
	}
	if len(c.ByPort(45454)) != 1 || len(c.ByEnvMarker("ACME_AGENT")) != 1 || len(c.ByAPIHost("api.acme.example")) != 1 {
		t.Error("overlay port, env marker or host is not indexed")
	}
	if !strings.Contains(c.Version(), "+overlay.") {
		t.Errorf("Version() = %q, want an overlay suffix", c.Version())
	}
	// Shipped products are untouched.
	if cc, ok := c.Get("claude-code"); !ok || cc.Hooks == nil {
		t.Error("shipped product damaged by overlay")
	}
	// Another catalog in the same process does not see the overlay.
	other := mustLoad(t)
	if _, ok := other.Get("acme-agent"); ok || strings.Contains(other.Version(), "overlay") {
		t.Error("overlay leaked into a second Load")
	}
}

func TestOverlayOverridesFieldByField(t *testing.T) {
	c := mustLoad(t)
	before, _ := c.Get("claude-code")
	dir := t.TempDir()
	writeFile(t, dir, "claude.yml", `
products:
  - id: claude-code
    binaries: [claude, claude-internal]
    state_dirs: ["~/.claude", "/opt/corp/claude-state"]
    risky_flags: []
`)
	if err := c.LoadOverlay(dir); err != nil {
		t.Fatalf("LoadOverlay: %v", err)
	}
	after, _ := c.Get("claude-code")
	wantEq(t, "binaries", after.Binaries, []string{"claude", "claude-internal"})
	wantEq(t, "state dirs", after.StateDirs.Linux, []string{"~/.claude", "/opt/corp/claude-state"})
	if len(after.RiskyFlags) != 0 {
		t.Errorf("an explicitly empty list must replace the shipped one, got %v", after.RiskyFlags)
	}
	// Everything the overlay did not mention survives.
	if after.Name != before.Name || after.Kind != before.Kind || after.Vendor != before.Vendor {
		t.Errorf("identity fields lost: %+v", after)
	}
	if after.Hooks == nil || after.Hooks.Dialect != DialectClaude || after.Transcript == nil || len(after.MCP) != len(before.MCP) || len(after.Settings) != len(before.Settings) {
		t.Error("hooks, transcript, MCP or settings were dropped by a partial override")
	}
	wantEq(t, "packages", after.Packages, before.Packages)
	if got, ok := c.MatchProcess("claude-internal", "", nil); !ok || got.ID != "claude-code" {
		t.Error("overridden binary does not match")
	}
	if c.Len() != mustLoad(t).Len() {
		t.Error("an override must not add a product")
	}
}

func TestOverlayReplace(t *testing.T) {
	c := mustLoad(t)
	dir := t.TempDir()
	writeFile(t, dir, "a.yaml", `
products:
  - id: aider
    replace: true
    name: Aider (corp build)
    vendor: Corp
    kind: agent
    binaries: [corp-aider]
`)
	if err := c.LoadOverlay(dir); err != nil {
		t.Fatalf("LoadOverlay: %v", err)
	}
	p, _ := c.Get("aider")
	if p.Name != "Aider (corp build)" || len(p.Packages) != 0 || len(p.RiskyFlags) != 0 || p.Transcript != nil {
		t.Errorf("replace kept shipped fields: %+v", p)
	}
	if _, ok := c.MatchProcess("aider", "", nil); ok {
		t.Error("the replaced binary still matches")
	}
	if _, ok := c.ByPackage("pip", "aider-chat"); ok {
		t.Error("the replaced package is still indexed")
	}
}

func TestOverlayLayersAndOrder(t *testing.T) {
	c := mustLoad(t)
	dir := t.TempDir()
	// Name order decides: 20 overrides 10.
	writeFile(t, dir, "20-b.yaml", "products:\n  - {id: acme, name: Second}\n")
	writeFile(t, dir, "10-a.yaml", "products:\n  - {id: acme, name: First, vendor: Acme, kind: agent, binaries: [acme]}\n")
	if err := c.LoadOverlay(dir); err != nil {
		t.Fatal(err)
	}
	if p, _ := c.Get("acme"); p.Name != "Second" || p.Vendor != "Acme" {
		t.Errorf("layering wrong: %+v", p)
	}
	v1 := c.Version()
	// A second directory layers on top of the first.
	dir2 := t.TempDir()
	writeFile(t, dir2, "x.yaml", "products:\n  - {id: acme, vendor: Acme Corp}\n  - {id: acme-two, name: Two, vendor: Acme, kind: app, bundle_ids: [com.acme.two]}\n")
	if err := c.LoadOverlay(dir2); err != nil {
		t.Fatal(err)
	}
	if p, _ := c.Get("acme"); p.Name != "Second" || p.Vendor != "Acme Corp" {
		t.Errorf("second layer wrong: %+v", p)
	}
	if _, ok := c.Get("acme-two"); !ok {
		t.Error("second layer product missing")
	}
	if c.Version() == v1 {
		t.Error("the version must change when overlay content changes")
	}
	// An empty directory is a no-op.
	v2 := c.Version()
	if err := c.LoadOverlay(t.TempDir()); err != nil || c.Version() != v2 {
		t.Errorf("empty overlay dir: err %v, version %q", err, c.Version())
	}
}

func TestOverlayRejectedLeavesCatalogUnchanged(t *testing.T) {
	bad := map[string]string{
		"claims a shipped binary":       "products:\n  - {id: evil, name: Evil, vendor: X, kind: agent, binaries: [claude]}\n",
		"claims a shipped bundle id":    "products:\n  - {id: evil, name: Evil, vendor: X, kind: app, bundle_ids: [com.anthropic.claudefordesktop]}\n",
		"claims a shipped package":      "products:\n  - {id: evil, name: Evil, vendor: X, kind: agent, packages: ['pipx:Aider_Chat']}\n",
		"one-sided alias is not enough": "products:\n  - {id: evil, name: Evil, vendor: X, kind: agent, binaries: [codex], aliases: [codex, chatgpt]}\n",
		"no fingerprint":                "products:\n  - {id: evil, name: Evil, vendor: X, kind: agent}\n",
		"new product without a name":    "products:\n  - {id: evil, kind: agent, binaries: [evil]}\n",
		"bad kind":                      "products:\n  - {id: evil, name: Evil, kind: mcp_server, binaries: [evil]}\n",
		"bad id":                        "products:\n  - {id: 'Evil Product', name: Evil, kind: agent, binaries: [evil]}\n",
		"id with path":                  "products:\n  - {id: '../../etc/passwd', name: Evil, kind: agent, binaries: [evil]}\n",
		"unknown key":                   "products:\n  - {id: evil, name: Evil, kind: agent, binarys: [evil]}\n",
		"unknown nested key":            "products:\n  - {id: evil, name: Evil, kind: agent, binaries: [evil], hooks: {dialekt: claude, user_paths: ['~/x']}}\n",
		"unknown OS key":                "products:\n  - {id: evil, name: Evil, kind: agent, state_dirs: {window: ['~/x']}}\n",
		"unknown top-level key":         "product:\n  - {id: evil}\n",
		"generic binary name":           "products:\n  - {id: evil, name: Evil, kind: agent, binaries: [node]}\n",
		"binary with a path":            "products:\n  - {id: evil, name: Evil, kind: agent, binaries: ['/usr/bin/evil']}\n",
		"invalid regexp":                "products:\n  - {id: evil, name: Evil, kind: agent, process_args: ['(unclosed']}\n",
		"regexp matching everything":    "products:\n  - {id: evil, name: Evil, kind: agent, process_args: ['.*']}\n",
		"unknown hook dialect":          "products:\n  - {id: evil, name: Evil, kind: agent, binaries: [evil], hooks: {dialect: qwen, user_paths: ['~/x']}}\n",
		"project path escapes the root": "products:\n  - {id: evil, name: Evil, kind: agent, binaries: [evil], mcp: [{project_paths: ['../../etc/passwd'], scope: project}]}\n",
		"absolute project path":         "products:\n  - {id: evil, name: Evil, kind: agent, binaries: [evil], hooks: {project_paths: ['/etc/shadow']}}\n",
		"dot-dot in a state dir":        "products:\n  - {id: evil, name: Evil, kind: agent, state_dirs: ['~/../../etc']}\n",
		"bad package manager":           "products:\n  - {id: evil, name: Evil, kind: agent, packages: ['gem:evil']}\n",
		"bad port":                      "products:\n  - {id: evil, name: Evil, kind: agent, binaries: [evil], ports: [70000]}\n",
		"bad chrome id":                 "products:\n  - {id: evil, name: Evil, kind: browser_extension, chrome_ids: [short]}\n",
		"bad setting op":                "products:\n  - {id: evil, name: Evil, kind: agent, binaries: [evil], settings: [{file: ['~/x'], format: json, key: a, op: regex, value: x, flag: f}]}\n",
		"bad risky flag":                "products:\n  - {id: evil, name: Evil, kind: agent, binaries: [evil], risky_flags: ['rm -rf /']}\n",
		"bad interpreter ecosystem":     "interpreters: {ruby: gems}\n",
		"malformed yaml":                "products:\n  - {id: evil, name: [unterminated\n",
		"products is not a list":        "products: {id: evil}\n",
		"top level is a list":           "- id: evil\n",
		"duplicate key":                 "products:\n  - {id: evil, id: evil2, name: Evil, kind: agent, binaries: [evil]}\n",
		"wrong type":                    "products:\n  - {id: evil, name: Evil, kind: agent, binaries: evil-not-a-list, ports: [a]}\n",
		"NUL in a name":                 "products:\n  - {id: evil, name: \"E\\0vil\", kind: agent, binaries: [evil]}\n",
		"oversized string":              "products:\n  - {id: evil, name: \"" + strings.Repeat("A", maxStringLen+1) + "\", kind: agent, binaries: [evil]}\n",
		"too many list entries":         "products:\n  - {id: evil, name: Evil, kind: agent, binaries: [" + strings.Repeat("b,", maxListLen+1) + "c]}\n",
	}
	for desc, content := range bad {
		t.Run(desc, func(t *testing.T) {
			c := mustLoad(t)
			version, n := c.Version(), c.Len()
			dir := t.TempDir()
			// A good file sorted before the bad one must not be applied
			// either: the overlay is all or nothing.
			writeFile(t, dir, "00-good.yaml", "products:\n  - {id: good-one, name: Good, vendor: G, kind: agent, binaries: [good-one]}\n")
			writeFile(t, dir, "50-bad.yaml", content)
			err := c.LoadOverlay(dir)
			if err == nil {
				t.Fatal("LoadOverlay accepted a bad file")
			}
			t.Logf("rejected with: %v", err)
			if !strings.HasPrefix(err.Error(), "catalog:") {
				t.Errorf("error lacks the package prefix: %v", err)
			}
			if c.Version() != version || c.Len() != n {
				t.Errorf("catalog changed after a rejected overlay: %q %d", c.Version(), c.Len())
			}
			if _, ok := c.Get("good-one"); ok {
				t.Error("a partial overlay was applied")
			}
			if _, ok := c.Get("evil"); ok {
				t.Error("the bad product is visible")
			}
			if p, ok := c.MatchProcess("claude", "", nil); !ok || p.ID != "claude-code" {
				t.Error("matching broke after a rejected overlay")
			}
		})
	}
}

func TestOverlaySharedFingerprintNeedsBothSides(t *testing.T) {
	c := mustLoad(t)
	dir := t.TempDir()
	// Both products acknowledge each other, so sharing "codex" is allowed.
	writeFile(t, dir, "a.yaml", `
products:
  - {id: corp-codex, name: Corp Codex, vendor: Corp, kind: agent, binaries: [codex], aliases: [codex, chatgpt]}
  - {id: codex, aliases: [codex-cli, chatgpt, corp-codex]}
  - {id: chatgpt, aliases: [chatgpt-desktop, codex-app, Codex desktop, codex, corp-codex]}
`)
	if err := c.LoadOverlay(dir); err != nil {
		t.Fatalf("mutual aliases should allow a shared binary: %v", err)
	}
	if got := len(c.ByBinary("codex")); got != 3 {
		t.Errorf("ByBinary(codex) returned %d products, want 3", got)
	}
}

func TestOverlayFileSafety(t *testing.T) {
	good := "products:\n  - {id: acme, name: Acme, vendor: A, kind: agent, binaries: [acme]}\n"

	t.Run("missing directory", func(t *testing.T) {
		c := mustLoad(t)
		if err := c.LoadOverlay(filepath.Join(t.TempDir(), "nope")); err == nil {
			t.Error("want an error")
		}
		if err := c.LoadOverlay(""); err == nil {
			t.Error("want an error for an empty path")
		}
	})
	t.Run("path is a file", func(t *testing.T) {
		c := mustLoad(t)
		if err := c.LoadOverlay(writeFile(t, t.TempDir(), "x.yaml", good)); err == nil {
			t.Error("want an error")
		}
	})
	t.Run("oversized file", func(t *testing.T) {
		c := mustLoad(t)
		dir := t.TempDir()
		writeFile(t, dir, "big.yaml", good+"# "+strings.Repeat("x", maxFileBytes))
		if err := c.LoadOverlay(dir); err == nil || !strings.Contains(err.Error(), "larger") {
			t.Errorf("want a size error, got %v", err)
		}
	})
	t.Run("too many files", func(t *testing.T) {
		c := mustLoad(t)
		dir := t.TempDir()
		for i := 0; i <= maxOverlayFile; i++ {
			writeFile(t, dir, "f"+strings.Repeat("0", 3-len(itoa(i)))+itoa(i)+".yaml", "")
		}
		if err := c.LoadOverlay(dir); err == nil {
			t.Error("want an error")
		}
	})
	t.Run("subdirectories are not descended", func(t *testing.T) {
		c := mustLoad(t)
		dir := t.TempDir()
		sub := filepath.Join(dir, "sub.yaml")
		if err := os.Mkdir(sub, 0o755); err != nil {
			t.Fatal(err)
		}
		writeFile(t, sub, "x.yaml", good)
		if err := c.LoadOverlay(dir); err == nil {
			t.Error("a directory named like a YAML file must be refused, not skipped silently")
		}
	})
	t.Run("BOM and CRLF", func(t *testing.T) {
		c := mustLoad(t)
		dir := t.TempDir()
		writeFile(t, dir, "x.yaml", "\xef\xbb\xbf"+strings.ReplaceAll(good, "\n", "\r\n"))
		if err := c.LoadOverlay(dir); err != nil {
			t.Fatalf("BOM/CRLF file rejected: %v", err)
		}
		if _, ok := c.Get("acme"); !ok {
			t.Error("product missing")
		}
	})
	t.Run("empty and comment-only files", func(t *testing.T) {
		c := mustLoad(t)
		dir := t.TempDir()
		writeFile(t, dir, "a.yaml", "")
		writeFile(t, dir, "b.yaml", "# nothing here\n")
		writeFile(t, dir, "c.yaml", "products: []\n")
		if err := c.LoadOverlay(dir); err != nil {
			t.Fatalf("empty files rejected: %v", err)
		}
	})

	if runtime.GOOS == "windows" {
		return
	}
	t.Run("symlinked file", func(t *testing.T) {
		c := mustLoad(t)
		outside := writeFile(t, t.TempDir(), "target.yaml", good)
		dir := t.TempDir()
		if err := os.Symlink(outside, filepath.Join(dir, "link.yaml")); err != nil {
			t.Skip(err)
		}
		if err := c.LoadOverlay(dir); err == nil || !strings.Contains(err.Error(), "symlink") {
			t.Errorf("want a symlink refusal, got %v", err)
		}
		if _, ok := c.Get("acme"); ok {
			t.Error("a symlinked overlay was applied")
		}
	})
	t.Run("symlinked directory", func(t *testing.T) {
		c := mustLoad(t)
		real := t.TempDir()
		writeFile(t, real, "x.yaml", good)
		link := filepath.Join(t.TempDir(), "link")
		if err := os.Symlink(real, link); err != nil {
			t.Skip(err)
		}
		if err := c.LoadOverlay(link); err == nil {
			t.Error("want a refusal for a symlinked directory")
		}
	})
	t.Run("world-writable file", func(t *testing.T) {
		c := mustLoad(t)
		dir := t.TempDir()
		p := writeFile(t, dir, "x.yaml", good)
		if err := os.Chmod(p, 0o666); err != nil {
			t.Fatal(err)
		}
		if err := c.LoadOverlay(dir); err == nil || !strings.Contains(err.Error(), "world-writable") {
			t.Errorf("want a world-writable refusal, got %v", err)
		}
	})
	t.Run("world-writable directory", func(t *testing.T) {
		c := mustLoad(t)
		dir := t.TempDir()
		writeFile(t, dir, "x.yaml", good)
		if err := os.Chmod(dir, 0o777); err != nil {
			t.Fatal(err)
		}
		defer os.Chmod(dir, 0o755)
		if err := c.LoadOverlay(dir); err == nil || !strings.Contains(err.Error(), "world-writable") {
			t.Errorf("want a world-writable refusal, got %v", err)
		}
	})
	t.Run("fifo is not read", func(t *testing.T) {
		// A FIFO would block a naive reader forever; os.MkdirAll-style
		// creation is not portable, so use a socket-like stand-in: a
		// directory entry that is not a regular file.
		c := mustLoad(t)
		dir := t.TempDir()
		if err := os.Mkdir(filepath.Join(dir, "pipe.yml"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := c.LoadOverlay(dir); err == nil || !strings.Contains(err.Error(), "regular") {
			t.Errorf("want a not-regular refusal, got %v", err)
		}
	})
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

func TestOverlayHostileYAML(t *testing.T) {
	// None of these may panic, hang or take the process down; each must
	// come back as an error with the catalog intact.
	billion := "a: &a [x,x,x,x,x,x,x,x,x]\n"
	prev := "a"
	for _, n := range []string{"b", "c", "d", "e", "f", "g", "h", "i"} {
		billion += n + ": &" + n + " [*" + prev + ",*" + prev + ",*" + prev + ",*" + prev + ",*" + prev + ",*" + prev + ",*" + prev + ",*" + prev + ",*" + prev + "]\n"
		prev = n
	}
	billion += "products: *" + prev + "\n"
	hostile := map[string]string{
		"deep flow nesting":        "products: " + strings.Repeat("[", 20000) + strings.Repeat("]", 20000) + "\n",
		"deep block nesting":       deepBlock(5000),
		"alias bomb at top level":  billion,
		"alias bomb in a list":     "ambiguous_names:\n" + aliasBomb("  - ") + "products: []\n",
		"alias bomb in a product":  "products:\n  - id: evil\n    name: x\n    kind: agent\n    binaries:\n" + aliasBomb("      - "),
		"alias bomb in paths":      "products:\n  - id: evil\n    name: x\n    kind: agent\n    state_dirs:\n" + aliasBomb("      - "),
		"alias bomb in settings":   "products:\n  - id: evil\n    name: x\n    kind: agent\n    binaries: [evil]\n    settings:\n" + aliasBomb("      - "),
		"self-referential anchor":  "products: &p\n  - *p\n",
		"invalid utf-8":            "products:\n  - {id: evil, name: \"\xff\xfe\xfd\", kind: agent, binaries: [evil]}\n",
		"invalid utf-8 in a key":   "products:\n  - {id: evil, \"\xff\": 1}\n",
		"binary garbage":           "\x00\x01\x02\x03\xff\xfe products: [",
		"huge scalar":              "products:\n  - {id: evil, name: " + strings.Repeat("A", 900000) + ", kind: agent, binaries: [evil]}\n",
		"many products":            "products:\n" + strings.Repeat("  - {id: x}\n", 60000),
		"tagged binary":            "products:\n  - {id: evil, name: !!binary AAAA, kind: agent, binaries: [evil]}\n",
		"custom tag":               "products:\n  - !!python/object/apply:os.system [\"id\"]\n",
		"merge of a non-mapping":   "products:\n  - {<<: [1, 2], id: evil}\n",
		"numeric id":               "products:\n  - {id: 12345678901234567890123456789012345678901234567890, name: x, kind: agent, binaries: [x]}\n",
		"null product":             "products:\n  - ~\n",
		"scalar product":           "products:\n  - evil\n",
		"paths as a number":        "products:\n  - {id: evil, name: x, kind: agent, state_dirs: 42}\n",
		"paths nested wrong":       "products:\n  - {id: evil, name: x, kind: agent, state_dirs: {linux: {a: b}}}\n",
		"settings as a string":     "products:\n  - {id: evil, name: x, kind: agent, binaries: [evil], settings: nope}\n",
		"hooks as a list":          "products:\n  - {id: evil, name: x, kind: agent, binaries: [evil], hooks: [a, b]}\n",
		"regexp with huge repeat":  "products:\n  - {id: evil, name: x, kind: agent, process_args: ['(a{1000}){1000}']}\n",
		"regexp longer than limit": "products:\n  - {id: evil, name: x, kind: agent, process_args: ['" + strings.Repeat("a", maxPatternLen+1) + "']}\n",
	}
	for desc, content := range hostile {
		t.Run(desc, func(t *testing.T) {
			if len(content) > maxFileBytes {
				t.Fatalf("test input is %d bytes; it would be rejected for size before the parser sees it", len(content))
			}
			c := mustLoad(t)
			version, n := c.Version(), c.Len()
			dir := t.TempDir()
			writeFile(t, dir, "x.yaml", content)
			err := c.LoadOverlay(dir)
			if err == nil {
				t.Error("hostile overlay was accepted")
			} else {
				t.Logf("rejected with: %.200v", err)
			}
			if c.Version() != version || c.Len() != n {
				t.Error("catalog changed")
			}
		})
	}
}

// aliasBomb returns list items in which each anchors a list of nine
// references to the previous one: nine levels, 9^9 leaves if expanded.
func aliasBomb(itemPrefix string) string {
	var b strings.Builder
	b.WriteString(itemPrefix + "&l0 [x,x,x,x,x,x,x,x,x]\n")
	for i := 1; i <= 9; i++ {
		ref := "*l" + itoa(i-1)
		b.WriteString(itemPrefix + "&l" + itoa(i) + " [" + strings.TrimSuffix(strings.Repeat(ref+",", 9), ",") + "]\n")
	}
	return b.String()
}

func deepBlock(n int) string {
	var b strings.Builder
	b.WriteString("products:\n")
	for i := 0; i < n; i++ {
		b.WriteString(strings.Repeat(" ", i%200+1))
		b.WriteString("- \n")
	}
	return b.String()
}
