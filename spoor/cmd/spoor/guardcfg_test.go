package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestSetGuardModeYAML(t *testing.T) {
	def, err := defaultConfigYAML("/var/lib/spoor")
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, in string
		want     string // substring of the result ("" with err)
		was      string
		err      string
	}{
		{"exported default", string(def), "  mode: advisory\n", "off", ""},
		{"already advisory", "guard:\n  mode: advisory\n", "guard:\n  mode: advisory\n", "advisory", ""},
		{"no guard key", "data_dir: /var/lib/spoor\n", "data_dir: /var/lib/spoor\nguard:\n  mode: advisory\n", "off", ""},
		{"no guard key, no final newline", "data_dir: /var/lib/spoor", "data_dir: /var/lib/spoor\nguard:\n  mode: advisory\n", "off", ""},
		{"guard without mode", "guard:\n    deadline: 200ms\nheartbeat: 5m\n", "guard:\n    mode: advisory\n    deadline: 200ms\nheartbeat: 5m\n", "off", ""},
		{"guard empty", "guard:\nheartbeat: 5m\n", "guard:\n  mode: advisory\nheartbeat: 5m\n", "off", ""},
		{"empty file", "", "guard:\n  mode: advisory\n", "off", ""},
		{"comments only", "# nothing here\n", "# nothing here\nguard:\n  mode: advisory\n", "off", ""},
		{"quoted value and comment", "guard:\n  mode: 'off'   # was off\n  max_response: ask\n", "  mode: advisory   # was off\n", "off", ""},
		{"double-quoted", "guard:\n  mode: \"off\"\n", "  mode: advisory\n", "off", ""},
		{"CRLF", "data_dir: /x\r\nguard:\r\n  mode: off\r\n", "guard:\r\n  mode: advisory\r\n", "off", ""},
		{"CRLF, no guard", "data_dir: /x\r\n", "data_dir: /x\r\nguard:\r\n  mode: advisory\r\n", "off", ""},
		{"document marker", "---\nguard:\n  mode: off\n", "---\nguard:\n  mode: advisory\n", "off", ""},
		{"flow mapping", "guard: {mode: off}\n", "", "", "not a block mapping"},
		{"flow top level", "{guard: {mode: off}}\n", "", "", "top level"},
		{"value on the next line", "guard:\n  mode:\n    off\n", "", "", "one line"},
		{"anchored guard", "guard: &g\n  mode: off\n", "", "", "block mapping"},
		{"unknown key", "gaurd:\n  mode: advisory\n", "", "", "does not load"},
		{"invalid value", "guard:\n  mode: enforce\n", "", "", "does not load"},
		{"not YAML", "guard: [\n", "", "", "does not load"},
		{"two documents", "guard:\n  mode: off\n---\nguard:\n  mode: off\n", "", "", ""},
		{"top level is a list", "- a\n", "", "", "does not load"},
		{"invalid UTF-8", "data_dir: \xff\n", "", "", "UTF-8"},
	} {
		out, was, err := setGuardModeYAML([]byte(tc.in))
		if tc.name == "two documents" {
			// Only the first document is the configuration; editing it is
			// fine, appending to the last would not be.
			if err == nil && !strings.HasPrefix(string(out), "guard:\n  mode: advisory\n---\n") {
				t.Errorf("%s: %q", tc.name, out)
			}
			continue
		}
		if tc.err != "" {
			if err == nil || !strings.Contains(err.Error(), tc.err) {
				t.Errorf("%s: err %v, want %q (out %q)", tc.name, err, tc.err, out)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: %v", tc.name, err)
			continue
		}
		if !strings.Contains(string(out), tc.want) || was != tc.was {
			t.Errorf("%s: was %q, out:\n%s", tc.name, was, out)
		}
		if err := loadsAsConfig(out); err != nil {
			t.Errorf("%s: result does not load: %v", tc.name, err)
		}
	}
	// The exported default keeps every comment and key.
	out, _, _ := setGuardModeYAML(def)
	if strings.Count(string(out), "#") != strings.Count(string(def), "#") || len(strings.Split(string(out), "\n")) != len(strings.Split(string(def), "\n")) {
		t.Error("comments or lines lost")
	}
	var m map[string]any
	if err := yaml.Unmarshal(out, &m); err != nil || m["guard"].(map[string]any)["mode"] != "advisory" {
		t.Fatalf("%v %v", err, m["guard"])
	}
}

// Hostile input never panics and never yields a file that does more than
// switch guard mode on.
func TestSetGuardModeYAMLHostile(t *testing.T) {
	for _, in := range []string{
		strings.Repeat("[", 10000), "guard:\n  mode: *x\n", "x: &x off\nguard:\n  mode: *x\n",
		"guard:\n  <<: {mode: off}\n", "guard:\n  mode: off\n  mode: off\n", "guard:\n\tmode: off\n",
		"guard: !!map\n  mode: off\n", "guard:\n  mode: !!str off\n", "guard:\n  \"mode\": off\n",
		"guard:\n  mode: off # \u202e\n", "guard:\n  mode: \"o\\\"ff\"\n", "guard:\n  mode: 'o''ff'\n",
		"\ufeffguard:\n  mode: off\n", "guard:\n  mode: |\n    off\n",
	} {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("%q: panic %v", in, r)
				}
			}()
			out, _, err := setGuardModeYAML([]byte(in))
			if err != nil {
				return
			}
			if err := sameExceptGuard([]byte(in), out); err != nil {
				t.Errorf("%q: accepted an edit that fails its own check: %v\n%s", in, err, out)
			}
		}()
	}
}

func TestHookConfigPath(t *testing.T) {
	p := hookConfigPath("")
	if !strings.HasSuffix(p, "spoor.yaml") || !filepath.IsAbs(p) {
		t.Fatalf("%s", p)
	}
	root := t.TempDir()
	if q := hookConfigPath(root); !strings.HasPrefix(q, root) || !strings.HasSuffix(q, "spoor.yaml") {
		t.Fatalf("%s", q)
	}
}

// hooks install --guard at the managed scope switches guard mode on in the
// configuration the hook reads, keeping the file's mode; it says so; a
// second run has nothing to do; a file it cannot edit stops everything.
func TestHooksInstallGuardManaged(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX paths")
	}
	if os.Geteuid() != 0 {
		t.Skip("managed hook files are root-owned")
	}
	prefix := t.TempDir()
	cfg := hookConfigPath(prefix)
	ta := newTestApp(t)
	args := []string{"hooks", "install", "--scope", "managed", "--root", prefix, "--binary", "/usr/bin/spoor", "--agents", "claude-code", "--guard"}

	// No configuration yet: written from the default, guard mode on.
	out := ta.mustRun(t, exitOK, append(args, "--dry-run")...)
	if !strings.Contains(out, "guard: would set guard.mode: advisory in "+cfg) {
		t.Fatalf("dry run:\n%s", out)
	}
	if _, err := os.Stat(cfg); !os.IsNotExist(err) {
		t.Fatal("dry run wrote the configuration")
	}
	out = ta.mustRun(t, exitOK, args...)
	if !strings.Contains(out, "guard: set guard.mode: advisory in "+cfg+" (file created from the default configuration)") {
		t.Fatalf("install:\n%s", out)
	}
	fi, err := os.Stat(cfg)
	if err != nil || fi.Mode().Perm() != 0o644 {
		t.Fatalf("created config: %v %v", fi, err)
	}
	b, _ := os.ReadFile(cfg)
	if loadsAsConfig(b) != nil || !strings.Contains(string(b), "  mode: advisory\n") {
		t.Fatalf("created config:\n%s", b)
	}
	out = ta.mustRun(t, exitOK, args...)
	if !strings.Contains(out, "guard: guard.mode is already advisory in "+cfg) {
		t.Fatalf("second run:\n%s", out)
	}

	// A file the developers' hooks cannot read: guard mode there would
	// apply to no hook, so nothing is written and the fix is printed.
	writeTestFile(t, cfg, "guard:\n  mode: off\n", 0o640)
	if err := os.Chmod(cfg, 0o640); err != nil {
		t.Fatal(err)
	}
	if code := ta.run(args...); code != exitError || !strings.Contains(ta.errb.String(), "other accounts cannot read it (mode 0640") ||
		!strings.Contains(ta.errb.String(), "chmod o+r") {
		t.Fatalf("unreadable config: exit %d\n%s", code, ta.errb.String())
	}
	if b, _ := os.ReadFile(cfg); string(b) != "guard:\n  mode: off\n" {
		t.Fatalf("unreadable config changed: %s", b)
	}

	// An existing file: only the value changes, mode kept.
	writeTestFile(t, cfg, "# site config\ndata_dir: /var/lib/spoor\nguard:\n  mode: off # pilot\n  max_response: ask\n", 0o604)
	if err := os.Chmod(cfg, 0o604); err != nil {
		t.Fatal(err)
	}
	var res planResult
	decodeJSON(t, ta.mustRun(t, exitOK, append(args, "--json")...), &res)
	if res.Guard == nil || res.Guard.Action != guardSet || res.Guard.Was != "off" || res.Guard.Path != cfg {
		t.Fatalf("json: %+v", res.Guard)
	}
	b, _ = os.ReadFile(cfg)
	if string(b) != "# site config\ndata_dir: /var/lib/spoor\nguard:\n  mode: advisory # pilot\n  max_response: ask\n" {
		t.Fatalf("edited config:\n%s", b)
	}
	if fi, _ := os.Stat(cfg); fi.Mode().Perm() != 0o604 {
		t.Fatalf("mode changed: %v", fi.Mode())
	}

	// A file spoor cannot edit with certainty: nothing at all is written,
	// and the exact change is printed.
	writeTestFile(t, cfg, "guard: {mode: off}\n", 0o644)
	prefix2 := t.TempDir()
	cfg2 := hookConfigPath(prefix2)
	writeTestFile(t, cfg2, "guard: {mode: off}\n", 0o644)
	code := ta.run("hooks", "install", "--scope", "managed", "--root", prefix2, "--binary", "/usr/bin/spoor", "--agents", "claude-code", "--guard")
	if code != exitError || !strings.Contains(ta.errb.String(), "nothing was written") || !strings.Contains(ta.errb.String(), "guard:\n    mode: advisory") || !strings.Contains(ta.errb.String(), cfg2) {
		t.Fatalf("exit %d\nstderr:\n%s", code, ta.errb.String())
	}
	if _, err := os.Stat(filepath.Join(prefix2, "etc", "claude-code")); !os.IsNotExist(err) {
		t.Fatal("hooks registered although guard mode could not be switched on")
	}
	if b, _ := os.ReadFile(cfg2); string(b) != "guard: {mode: off}\n" {
		t.Fatalf("config changed: %s", b)
	}
	// A symbolic link is not written through.
	prefix3 := t.TempDir()
	cfg3 := hookConfigPath(prefix3)
	target := filepath.Join(t.TempDir(), "elsewhere.yaml")
	writeTestFile(t, target, "guard:\n  mode: off\n", 0o644)
	if err := os.MkdirAll(filepath.Dir(cfg3), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, cfg3); err != nil {
		t.Fatal(err)
	}
	if code := ta.run("hooks", "install", "--scope", "managed", "--root", prefix3, "--binary", "/usr/bin/spoor", "--agents", "claude-code", "--guard"); code != exitError ||
		!strings.Contains(ta.errb.String(), "symbolic link") {
		t.Fatalf("symlink: exit %d %s", code, ta.errb.String())
	}
	if b, _ := os.ReadFile(target); string(b) != "guard:\n  mode: off\n" {
		t.Fatal("wrote through a link")
	}
}

// A user-scope --guard registers the hooks but cannot turn guard mode on
// (that is the machine's configuration): it prints the change and exits 5,
// so a script or CI job does not take the run for a guarded installation;
// with guard mode already on it exits 0. --root places the configuration.
func TestHooksInstallGuardUser(t *testing.T) {
	root := t.TempDir()
	home := t.TempDir()
	ta := newTestApp(t)
	args := []string{"hooks", "install", "--scope", "user", "--root", root, "--home", home, "--binary", "/usr/bin/spoor", "--agents", "claude-code", "--guard"}
	settings := filepath.Join(root, home, ".claude", "settings.json")
	cfg := hookConfigPath(root)
	// --dry-run predicts the same outcome and writes nothing.
	if code := ta.run(append(args, "--dry-run")...); code != exitGuardOff {
		t.Fatalf("dry run: exit %d, want %d: %s", code, exitGuardOff, ta.errb.String())
	}
	if _, err := os.Stat(settings); err == nil {
		t.Fatal("dry run registered hooks")
	}
	code := ta.run(args...)
	if code != exitGuardOff {
		t.Fatalf("exit %d, want %d: %s", code, exitGuardOff, ta.errb.String())
	}
	if e := ta.errb.String(); !strings.Contains(e, "guard mode is NOT on (exit 5)") || !strings.Contains(e, cfg) || !strings.Contains(e, "mode: advisory") {
		t.Fatalf("stdout:\n%s\nstderr:\n%s", ta.out.String(), e)
	}
	if _, err := os.Stat(settings); err != nil {
		t.Fatal("hooks not registered")
	}
	if _, err := os.Stat(cfg); err == nil {
		t.Fatal("a user-scope install wrote the machine's configuration")
	}
	var res planResult
	if code := ta.run(append(args, "--json")...); code != exitGuardOff {
		t.Fatalf("--json: exit %d", code)
	}
	decodeJSON(t, ta.out.String(), &res)
	if res.Guard == nil || res.Guard.Action != guardManual {
		t.Fatalf("--json guard: %+v", res.Guard)
	}
	// Guard mode already on: the guarded installation is what was asked.
	writeTestFile(t, cfg, "guard:\n  mode: advisory\n", 0o644)
	if code := ta.run(args...); code != exitOK || !strings.Contains(ta.out.String(), "guard: guard.mode is already advisory") {
		t.Fatalf("guard on: exit %d\n%s%s", code, ta.out.String(), ta.errb.String())
	}
	// The exit code is documented.
	if help := ta.mustRun(t, exitOK, "help"); !strings.Contains(help, "5  hooks install --guard") {
		t.Errorf("spoor help does not list exit code 5:\n%s", help)
	}
	// The help says where guard mode lives.
	help := ta.mustRun(t, exitOK, "hooks", "install", "--help")
	for _, w := range []string{"guard.mode", "--only-installed", "configuration every hook reads"} {
		if !strings.Contains(help, w) {
			t.Errorf("help lacks %q:\n%s", w, help)
		}
	}
}

func TestPlanGuardModeUserNeverWrites(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "spoor.yaml")
	g := planGuardMode(cfg, false)
	if g.Action != guardManual || !strings.Contains(g.Note, "does not exist") {
		t.Fatalf("%+v", g)
	}
	writeTestFile(t, cfg, "guard:\n  mode: off\n", 0o644)
	g = planGuardMode(cfg, false)
	if g.Action != guardManual || !strings.Contains(g.Note, "guard.mode is off there") {
		t.Fatalf("%+v", g)
	}
	if err := g.apply(); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(cfg); string(b) != "guard:\n  mode: off\n" {
		t.Fatal("a manual plan wrote")
	}
	writeTestFile(t, cfg, "guard:\n  mode: advisory\n", 0o644)
	if g = planGuardMode(cfg, false); g.Action != guardUnchanged {
		t.Fatalf("%+v", g)
	}
	// A file edited between plan and apply is not overwritten.
	writeTestFile(t, cfg, "guard:\n  mode: off\n", 0o644)
	g = planGuardMode(cfg, true)
	writeTestFile(t, cfg, "guard:\n  mode: off\nheartbeat: 1m\n", 0o644)
	if err := g.apply(); err == nil || !strings.Contains(err.Error(), "changed after it was read") {
		t.Fatalf("apply after a concurrent edit: %v", err)
	}
}
