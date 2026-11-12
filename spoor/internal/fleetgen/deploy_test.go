package fleetgen

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// Content tests for the hand-written files next to the generated ones in
// deploy/fleet: scripts, package examples and GitOps examples. Their
// behaviour is exercised in a container by test/e2e/fleet_test.go.

func deployDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("no caller information")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "deploy", "fleet")
}

func readDeploy(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(deployDir(t), filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// Fleet refuses ad hoc script contents of 10,000 characters or more
// (docs/API/rest-api.md, "Run script").
func TestScriptsUnderFleetLimit(t *testing.T) {
	ents, err := os.ReadDir(filepath.Join(deployDir(t), "scripts"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) < 6 {
		t.Fatalf("only %d scripts", len(ents))
	}
	for _, e := range ents {
		s := readDeploy(t, "scripts/"+e.Name())
		if n := len([]rune(s)); n >= 10000 {
			t.Errorf("%s: %d characters, Fleet's limit is 10,000", e.Name(), n)
		}
		if strings.Contains(s, "\r") {
			t.Errorf("%s: carriage returns", e.Name())
		}
		// fleetctl gitops expands $FLEET_SECRET_* anywhere in a script,
		// comments included, and fails when the variable is not set.
		if regexp.MustCompile(`\$\{?FLEET_SECRET_`).MatchString(s) {
			t.Errorf("%s: names a Fleet secret variable; gitops would require it", e.Name())
		}
	}
}

func TestScriptsRegisterInOsqueryDefaultAutoload(t *testing.T) {
	for _, tc := range []struct {
		file string
		want []string
	}{
		{"scripts/install-spoor.sh", []string{"/etc/osquery/extensions.load", "/var/osquery/extensions.load"}},
		{"scripts/uninstall-spoor.sh", []string{"/etc/osquery/extensions.load", "/var/osquery/extensions.load"}},
		{"scripts/register-extension.sh", []string{"/etc/osquery/extensions.load", "/var/osquery/extensions.load"}},
		{"scripts/install-spoor.ps1", []string{`'osquery\extensions.load'`}},
		{"scripts/uninstall-spoor.ps1", []string{`'osquery\extensions.load'`}},
		{"scripts/register-extension.ps1", []string{`'osquery\extensions.load'`}},
	} {
		s := readDeploy(t, tc.file)
		for _, w := range tc.want {
			if !strings.Contains(s, w) {
				t.Errorf("%s: does not use %s", tc.file, w)
			}
		}
		code := stripComments(s)
		if strings.Contains(code, "/opt/orbit") || strings.Contains(strings.ToLower(code), `orbit\extensions.load`) {
			t.Errorf("%s: touches orbit's extensions.load", tc.file)
		}
	}
}

func TestInstallScriptsVerifyHash(t *testing.T) {
	sh := stripComments(readDeploy(t, "scripts/install-spoor.sh"))
	for _, w := range []string{`grep -Eq '^[0-9a-f]{64}$'`, `[ "$got" = "$want" ] || die "SHA-256 mismatch`, "--proto '=https'"} {
		if !strings.Contains(sh, w) {
			t.Errorf("install-spoor.sh lacks %q", w)
		}
	}
	// The hash is checked before anything is installed.
	if strings.Index(sh, "SHA-256 mismatch") > strings.Index(sh, `put "$tmp/spoor" "$BIN"`) {
		t.Error("install-spoor.sh installs before verifying the hash")
	}
	ps := stripComments(readDeploy(t, "scripts/install-spoor.ps1"))
	if !strings.Contains(ps, "Get-FileHash -Algorithm SHA256 -Path $tmp") || !strings.Contains(ps, "SHA-256 mismatch") {
		t.Error("install-spoor.ps1 does not verify the download")
	}
	if strings.Index(ps, "SHA-256 mismatch") > strings.Index(ps, "Copy-Item -Force -Path $tmp -Destination $Exe") {
		t.Error("install-spoor.ps1 installs before verifying the hash")
	}
}

// TestEmbeddedServiceDefinitions holds the unit and plist the install
// script writes to the ones in packaging/, so a hardening change there is
// not lost for script installs.
func TestEmbeddedServiceDefinitions(t *testing.T) {
	sh := readDeploy(t, "scripts/install-spoor.sh")
	unit := heredoc(t, sh, `cat >"$tmp/unit" <<'EOF'`)
	plist := heredoc(t, sh, `cat >"$tmp/plist" <<'EOF'`)
	pkgUnit, err := os.ReadFile(filepath.Join(deployDir(t), "..", "..", "packaging", "systemd", "spoor.service"))
	if err != nil {
		t.Skipf("packaging/systemd/spoor.service: %v", err)
	}
	if got, want := directives(unit), directives(string(pkgUnit)); got != want {
		t.Errorf("embedded unit differs from packaging/systemd/spoor.service:\n got: %s\nwant: %s", got, want)
	}
	pkgPlist, err := os.ReadFile(filepath.Join(deployDir(t), "..", "..", "packaging", "launchd", "com.github.thomastysong.spoor.plist"))
	if err != nil {
		t.Skipf("packaging/launchd plist: %v", err)
	}
	if got, want := plistText(plist), plistText(string(pkgPlist)); got != want {
		t.Errorf("embedded plist differs from packaging/launchd:\n got: %s\nwant: %s", got, want)
	}
}

func heredoc(t *testing.T, s, start string) string {
	t.Helper()
	i := strings.Index(s, start)
	if i < 0 {
		t.Fatalf("no heredoc %q", start)
	}
	rest := s[i+len(start)+1:]
	j := strings.Index(rest, "\nEOF\n")
	if j < 0 {
		t.Fatalf("heredoc %q not terminated", start)
	}
	return rest[:j]
}

// directives returns a unit's non-comment lines, sorted within sections.
func directives(s string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "#") || strings.HasPrefix(l, ";") {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, " | ")
}

var xmlComment = regexp.MustCompile(`(?s)<!--.*?-->`)

func plistText(s string) string {
	s = xmlComment.ReplaceAllString(s, "")
	return strings.Join(strings.Fields(strings.ReplaceAll(s, "><", "> <")), " ")
}

// stripComments drops shell and PowerShell comment lines.
func stripComments(s string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(strings.TrimSpace(l), "#") {
			continue
		}
		out = append(out, l)
	}
	return strings.Join(out, "\n")
}

// TestGitOpsExamplePathsResolve checks every path an example GitOps or
// package file references exists.
func TestGitOpsExamplePathsResolve(t *testing.T) {
	root := deployDir(t)
	var files []string
	for _, g := range []string{"gitops/*.yml", "gitops/fleets/*.yml", "software/*.yml"} {
		m, err := filepath.Glob(filepath.Join(root, filepath.FromSlash(g)))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	sort.Strings(files)
	if len(files) < 6 {
		t.Fatalf("found %d example files", len(files))
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var doc any
		if err := yaml.Unmarshal(b, &doc); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		walkPaths(doc, func(key, p string) {
			if _, err := os.Stat(filepath.Join(filepath.Dir(f), filepath.FromSlash(p))); err != nil {
				t.Errorf("%s: %s %q does not resolve: %v", filepath.Base(f), key, p, err)
			}
		})
	}
}

func walkPaths(v any, fn func(key, path string)) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if s, ok := e.(string); ok && (k == "path" || k == "package_path") {
				fn(k, s)
				continue
			}
			walkPaths(e, fn)
		}
	case []any:
		for _, e := range x {
			walkPaths(e, fn)
		}
	}
}

// TestPremiumInstallPoliciesMatchLabel keeps the per-OS install policies of
// the Premium example on the same paths as the generated "spoor installed"
// label.
func TestPremiumInstallPoliciesMatchLabel(t *testing.T) {
	var doc struct {
		Policies []map[string]any `yaml:"policies"`
	}
	if err := yaml.Unmarshal([]byte(readDeploy(t, "gitops/fleets/workstations.yml")), &doc); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, p := range doc.Policies {
		if p["install_software"] == nil {
			continue
		}
		n++
		plat, _ := p["platform"].(string)
		q, _ := p["query"].(string)
		want := "SELECT 1 FROM file WHERE " + sqlIn("path", []string{DefaultBinPaths()[plat], DefaultDBPaths()[plat]}) + " LIMIT 1;"
		if q != want {
			t.Errorf("%v: query\n %s\nwant\n %s", p["name"], q, want)
		}
	}
	if n != 3 {
		t.Errorf("%d install policies, want 3 (deb, rpm, pkg)", n)
	}
}
