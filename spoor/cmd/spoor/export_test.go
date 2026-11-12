package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/thomastysong/spoor/deploy"
	"github.com/thomastysong/spoor/internal/config"
	"github.com/thomastysong/spoor/internal/fleetgen"
)

func TestExportConfigRoundTrip(t *testing.T) {
	for _, dataDir := range []string{"/var/lib/spoor", `C:\ProgramData\spoor`, "/data dir/with: colon"} {
		b, err := defaultConfigYAML(dataDir)
		if err != nil {
			t.Fatal(err)
		}
		p := filepath.Join(t.TempDir(), "spoor.yaml")
		writeTestFile(t, p, string(b), 0o644)
		got, err := config.Load(p, "/elsewhere")
		if err != nil {
			t.Fatalf("written config does not load: %v\n%s", err, b)
		}
		// Compared through YAML: an empty list written as [] reads back as
		// an empty slice where the default holds nil, which is the same
		// configuration.
		want := config.Default(dataDir)
		gy, _ := yaml.Marshal(got)
		wy, _ := yaml.Marshal(want)
		if string(gy) != string(wy) || got.DataDir != dataDir {
			t.Fatalf("round trip differs for %q:\n got %s\nwant %s", dataDir, gy, wy)
		}
	}
}

func TestExportConfigComments(t *testing.T) {
	b, err := defaultConfigYAML("/var/lib/spoor")
	if err != nil {
		t.Fatal(err)
	}
	keys, err := configKeys(b)
	if err != nil {
		t.Fatal(err)
	}
	// Every top-level key and every section is explained.
	for _, k := range keys {
		if !strings.Contains(k, ".") && configComments[k] == "" {
			t.Errorf("top-level key %q has no comment", k)
		}
	}
	for k := range configComments {
		found := false
		for _, have := range keys {
			if have == k {
				found = true
			}
		}
		if !found {
			t.Errorf("comment for %q, which the configuration does not have", k)
		}
	}
	if !strings.Contains(string(b), "# spoor configuration") || !strings.Contains(string(b), "profile: minimal") {
		t.Fatalf("unexpected output:\n%s", b)
	}
}

func TestExportConfigCommand(t *testing.T) {
	ta := newTestApp(t)
	out := ta.mustRun(t, exitOK, "export", "config", "--data-dir", "/srv/spoor")
	if !strings.Contains(out, "data_dir: /srv/spoor") {
		t.Fatalf("stdout:\n%s", out)
	}
	p := filepath.Join(t.TempDir(), "etc", "spoor.yaml")
	ta.mustRun(t, exitOK, "export", "config", "--out", p)
	fi, err := os.Stat(p)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o644 {
		t.Fatalf("mode %v: hooks run as users and must read the config", fi.Mode().Perm())
	}
	ta.mustRun(t, exitError, "export", "config", "--out", p)
	ta.mustRun(t, exitOK, "export", "config", "--out", p, "--force")
	// --force never writes through a link.
	target := filepath.Join(t.TempDir(), "victim")
	writeTestFile(t, target, "keep", 0o600)
	link := filepath.Join(t.TempDir(), "link.yaml")
	if err := os.Symlink(target, link); err != nil {
		t.Skip(err)
	}
	ta.mustRun(t, exitError, "export", "config", "--out", link, "--force")
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Fatal("wrote through a symlink")
	}
}

func TestExportFluentBit(t *testing.T) {
	cfg, data := testConfig(t, "")
	out := filepath.Join(t.TempDir(), "fb")
	ta := newTestApp(t)
	ta.mustRun(t, exitOK, "export", "fluent-bit", "--config", cfg, "--out", out)
	b, err := os.ReadFile(filepath.Join(out, "spoor-inputs.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), filepath.Join(data, "outbox")) || strings.Contains(string(b), "/var/lib/spoor/outbox") {
		t.Fatalf("outbox path not substituted:\n%s", b)
	}
	if _, err := os.Stat(filepath.Join(out, "VERIFIED.md")); err == nil {
		t.Fatal("verification evidence exported as deployment content")
	}
	if _, err := os.Stat(filepath.Join(out, "outputs", "splunk.yaml")); err != nil {
		t.Fatal(err)
	}
	ta.mustRun(t, exitError, "export", "fluent-bit", "--config", cfg, "--out", out)
	list := ta.mustRun(t, exitOK, "export", "fluent-bit", "--config", cfg, "--list")
	if !strings.Contains(list, "spoor.yaml") {
		t.Fatalf("list:\n%s", list)
	}
	ta.mustRun(t, exitUsage, "export", "fluent-bit", "--config", cfg)
}

func TestExportFleet(t *testing.T) {
	cfg, data := testConfig(t, "")
	ta := newTestApp(t)
	out1 := filepath.Join(t.TempDir(), "fleet")
	ta.mustRun(t, exitOK, "export", "fleet", "--config", cfg, "--out", out1)
	atc, err := os.ReadFile(filepath.Join(out1, "lib", fleetgen.FileATC))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(atc), filepath.Join(data, "state.db")) {
		t.Fatalf("ATC does not point at this host's database:\n%s", clip(string(atc), 800))
	}
	for _, f := range []string{"scripts/install-spoor.sh", "gitops/default.yml", "README.md", "lib/CONTENT.md", "lib/stock/policies.yml"} {
		if _, err := os.Stat(filepath.Join(out1, f)); err != nil {
			t.Errorf("missing %s: %v", f, err)
		}
	}
	if fi, err := os.Stat(filepath.Join(out1, "scripts/install-spoor.sh")); err == nil && fi.Mode().Perm()&0o100 == 0 {
		t.Error("install script not executable")
	}
	if _, err := os.Stat(filepath.Join(out1, "verify.sh")); err == nil {
		t.Error("verify.sh exported")
	}
	// --min-bundle-version changes the bundle policy and nothing else.
	out2 := filepath.Join(t.TempDir(), "fleet")
	ta.mustRun(t, exitOK, "export", "fleet", "--config", cfg, "--out", out2, "--min-bundle-version", "42")
	p1, _ := os.ReadFile(filepath.Join(out1, "lib/stock/policies.yml"))
	p2, _ := os.ReadFile(filepath.Join(out2, "lib/stock/policies.yml"))
	if string(p1) == string(p2) || !strings.Contains(string(p2), "42") {
		t.Fatal("--min-bundle-version had no effect on the policies")
	}
	ta.mustRun(t, exitUsage, "export", "fleet", "--config", cfg, "--out", out2, "--min-bundle-version", "0")
	// The generated library equals Generate's output for these options.
	gen, err := fleetgen.Generate(fleetOptions(filepath.Join(data, "state.db"), "", 42))
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range gen {
		b, err := os.ReadFile(filepath.Join(out2, "lib", filepath.FromSlash(k)))
		if err != nil || string(b) != string(v) {
			t.Errorf("lib/%s differs from fleetgen.Generate (%v)", k, err)
		}
	}
}

func TestExportATC(t *testing.T) {
	cfg, data := testConfig(t, "")
	ta := newTestApp(t)
	out := ta.mustRun(t, exitOK, "export", "atc", "--config", cfg)
	if !strings.Contains(out, filepath.Join(data, "state.db")) || !strings.Contains(out, "spoor_") {
		t.Fatalf("atc:\n%s", clip(out, 1000))
	}
}

func TestExportKubernetes(t *testing.T) {
	ta := newTestApp(t)
	out := filepath.Join(t.TempDir(), "k8s")
	if _, ok := deploy.Sub("kubernetes"); !ok {
		ta.mustRun(t, exitError, "export", "kubernetes", "--out", out)
		if !strings.Contains(ta.errb.String(), "no Kubernetes content") {
			t.Fatalf("stderr: %s", ta.errb.String())
		}
		return
	}
	ta.mustRun(t, exitOK, "export", "kubernetes", "--out", out)
}

func TestDeploySets(t *testing.T) {
	sets := deploySets()
	for _, want := range []string{"fleet", "fluent-bit"} {
		found := false
		for _, s := range sets {
			found = found || s == want
		}
		if !found {
			t.Errorf("embedded content lacks %s (have %v)", want, sets)
		}
	}
	if _, ok := deploy.Sub("../cmd"); ok {
		t.Fatal("Sub accepted a path outside the tree")
	}
}
