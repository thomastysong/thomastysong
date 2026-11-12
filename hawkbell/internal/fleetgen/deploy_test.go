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
		{"scripts/install-hawkbell.sh", []string{"/etc/osquery/extensions.load", "/var/osquery/extensions.load"}},
		{"scripts/uninstall-hawkbell.sh", []string{"/etc/osquery/extensions.load", "/var/osquery/extensions.load"}},
		{"scripts/register-extension.sh", []string{"/etc/osquery/extensions.load", "/var/osquery/extensions.load"}},
		{"scripts/install-hawkbell.ps1", []string{`'osquery\extensions.load'`}},
		{"scripts/uninstall-hawkbell.ps1", []string{`'osquery\extensions.load'`}},
		{"scripts/register-extension.ps1", []string{`'osquery\extensions.load'`}},
	} {
		s := readDeploy(t, tc.file)
		for _, w := range tc.want {
			if !strings.Contains(s, w) {
				t.Errorf("%s: does not use %s", tc.file, w)
			}
		}
		// orbit's own autoload file may be read (to refuse the extension
		// tier where orbit overrides osquery's), never written.
		for _, l := range strings.Split(stripComments(s), "\n") {
			if !strings.Contains(strings.ToLower(l), "orbit") {
				continue
			}
			w := strings.NewReplacer("2>/dev/null", "", ">/dev/null", "", "2>&1", "", ">&2", "").Replace(l)
			if strings.Contains(w, ">") || orbitWrite.MatchString(w) {
				t.Errorf("%s: writes near orbit's extensions.load: %s", tc.file, strings.TrimSpace(l))
			}
		}
	}
	// The extension tier must refuse hosts where orbit's file is in use.
	for _, f := range []string{"scripts/install-hawkbell.sh", "scripts/register-extension.sh"} {
		if s := stripComments(readDeploy(t, f)); !strings.Contains(s, `"$ROOT/opt/orbit/extensions.load"`) || !strings.Contains(s, `if [ -s "$f" ]; then`) {
			t.Errorf("%s: does not check orbit's extensions.load", f)
		}
	}
	for _, f := range []string{"scripts/install-hawkbell.ps1", "scripts/register-extension.ps1"} {
		if s := stripComments(readDeploy(t, f)); !strings.Contains(s, `'Orbit\extensions.load'`) || !strings.Contains(s, "(Get-Item -Force $OrbitLoad).Length -gt 0") {
			t.Errorf("%s: does not check orbit's extensions.load", f)
		}
	}
}

var orbitWrite = regexp.MustCompile(`(?i)\b(Set-Content|Add-Content|Out-File|Copy-Item|Move-Item|Remove-Item|New-Item|cp|mv|rm|tee|install)\b`)

func TestInstallScriptsVerifyHash(t *testing.T) {
	sh := stripComments(readDeploy(t, "scripts/install-hawkbell.sh"))
	for _, w := range []string{`grep -Eq '^[0-9a-f]{64}$'`, `[ "$got" = "$want" ] || die "SHA-256 mismatch`, "--proto '=https'"} {
		if !strings.Contains(sh, w) {
			t.Errorf("install-hawkbell.sh lacks %q", w)
		}
	}
	// The hash is checked before anything is installed.
	if strings.Index(sh, "SHA-256 mismatch") > strings.Index(sh, `put "$tmp/hawkbell" "$BIN"`) {
		t.Error("install-hawkbell.sh installs before verifying the hash")
	}
	ps := stripComments(readDeploy(t, "scripts/install-hawkbell.ps1"))
	if !strings.Contains(ps, "Get-FileHash -Algorithm SHA256 -Path $tmp") || !strings.Contains(ps, "SHA-256 mismatch") {
		t.Error("install-hawkbell.ps1 does not verify the download")
	}
	if strings.Index(ps, "SHA-256 mismatch") > strings.Index(ps, "Copy-Item -Force -Path $tmp -Destination $Exe") {
		t.Error("install-hawkbell.ps1 installs before verifying the hash")
	}
}

// TestEmbeddedServiceDefinitions holds the unit and plist the install
// script writes to the ones in packaging/, so a hardening change there is
// not lost for script installs.
func TestEmbeddedServiceDefinitions(t *testing.T) {
	sh := readDeploy(t, "scripts/install-hawkbell.sh")
	unit := heredoc(t, sh, `cat >"$tmp/unit" <<'EOF'`)
	plist := heredoc(t, sh, `cat >"$tmp/plist" <<'EOF'`)
	pkgUnit, err := os.ReadFile(filepath.Join(deployDir(t), "..", "..", "packaging", "systemd", "hawkbell.service"))
	if err != nil {
		t.Skipf("packaging/systemd/hawkbell.service: %v", err)
	}
	if got, want := directives(unit), directives(string(pkgUnit)); got != want {
		t.Errorf("embedded unit differs from packaging/systemd/hawkbell.service:\n got: %s\nwant: %s", got, want)
	}
	pkgPlist, err := os.ReadFile(filepath.Join(deployDir(t), "..", "..", "packaging", "launchd", "com.github.thomastysong.hawkbell.plist"))
	if err != nil {
		t.Skipf("packaging/launchd plist: %v", err)
	}
	if got, want := plistText(plist), plistText(string(pkgPlist)); got != want {
		t.Errorf("embedded plist differs from packaging/launchd:\n got: %s\nwant: %s", got, want)
	}
}

// TestInstallScriptKeepsOutboxGroup: the data directory is root:hawkbell 0711
// (traversable, so hooks reach their own spool directory and the bundle;
// the outbox inside is root:hawkbell 0750 for the log shipper), but
// the unit's StateDirectory= makes systemd re-own it, recursively, to the
// service's user and group at every start: root:root for a root service.
// The script therefore runs the service with Group=hawkbell through a drop-in
// (the unit itself stays identical to packaging/), and uninstall removes it.
func TestInstallScriptKeepsOutboxGroup(t *testing.T) {
	sh := stripComments(readDeploy(t, "scripts/install-hawkbell.sh"))
	for _, w := range []string{
		"getent group hawkbell >/dev/null 2>&1 || groupadd --system hawkbell",
		`install -d -m 0711 -o 0 -g hawkbell "$DATA"`,
		`printf '[Service]\nGroup=hawkbell\n' >"$tmp/group.conf"`,
		`put "$tmp/group.conf" "$UNIT.d/10-outbox-group.conf" 0644`,
	} {
		if !strings.Contains(sh, w) {
			t.Errorf("install-hawkbell.sh lacks %q", w)
		}
	}
	// The drop-in counts as a unit change: daemon-reload and restart follow.
	if strings.Index(sh, `put "$tmp/group.conf"`) > strings.Index(sh, "[ $changed = 1 ] && systemctl daemon-reload") {
		t.Error("install-hawkbell.sh reloads systemd before writing the group drop-in")
	}
	if un := stripComments(readDeploy(t, "scripts/uninstall-hawkbell.sh")); !strings.Contains(un, `"$UNIT.d/10-outbox-group.conf"`) {
		t.Error("uninstall-hawkbell.sh leaves the group drop-in behind")
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

// premiumExample is the part of the Premium example fleet file the tests
// read.
type premiumExample struct {
	Labels   []map[string]any `yaml:"labels"`
	Policies []map[string]any `yaml:"policies"`
}

func readPremiumExample(t *testing.T) premiumExample {
	t.Helper()
	var doc premiumExample
	if err := yaml.Unmarshal([]byte(readDeploy(t, "gitops/fleets/workstations.yml")), &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// TestPremiumInstallPoliciesCheckTheBinary: an install-on-failure policy
// must fail wherever the binary is missing. The state database outlives an
// uninstall (uninstall-hawkbell.sh keeps data unless HAWKBELL_PURGE=1), so a
// policy that also accepted it would never reinstall hawkbell there.
func TestPremiumInstallPoliciesCheckTheBinary(t *testing.T) {
	doc := readPremiumExample(t)
	n := 0
	for _, pol := range doc.Policies {
		if pol["install_software"] == nil {
			continue
		}
		n++
		plat, _ := pol["platform"].(string)
		q, _ := pol["query"].(string)
		bin := DefaultBinPaths()[plat]
		if want := "SELECT 1 FROM file WHERE path = " + sqlString(bin) + " LIMIT 1;"; q != want {
			t.Errorf("%v: query\n %s\nwant\n %s", pol["name"], q, want)
		}
		for _, tc := range []struct {
			files []string
			pass  bool
		}{
			{nil, false},
			{[]string{DefaultDBPaths()[plat]}, false}, // uninstalled without purge
			{[]string{bin}, true},
			{[]string{bin, DefaultDBPaths()[plat]}, true},
		} {
			e := newEmu(t, "", atcFlavour)
			for _, f := range tc.files {
				e.exec("INSERT INTO file (path) VALUES (?)", f)
			}
			if got := e.passes(q); got != tc.pass {
				t.Errorf("%v with files %v: passes = %v, want %v", pol["name"], tc.files, got, tc.pass)
			}
		}
	}
	if n != 3 {
		t.Errorf("%d install policies, want 3 (deb, rpm, pkg)", n)
	}
}

// TestPremiumFamilyLabels: the deb and rpm install policies are scoped by
// package family, which Fleet's built-in labels do not cover (its "Ubuntu
// Linux" misses Debian, "Red Hat Linux" misses Rocky and Alma). Every label
// a policy names must be built in or defined in the file, and the family
// labels must select the right distributions from os_version
// (/etc/os-release ID as platform, ID_LIKE as platform_like).
func TestPremiumFamilyLabels(t *testing.T) {
	doc := readPremiumExample(t)
	queries := map[string]string{}
	for _, l := range doc.Labels {
		name, _ := l["name"].(string)
		queries[name], _ = l["query"].(string)
	}
	builtin := map[string]bool{"macOS": true, "MS Windows": true, "All Linux": true, "Ubuntu Linux": true}
	scope := map[string]string{}
	for _, pol := range doc.Policies {
		raw, _ := pol["labels_include_any"].([]any)
		for _, l := range raw {
			name, _ := l.(string)
			if _, ok := queries[name]; !ok && !builtin[name] {
				t.Errorf("%v: label %q is neither built in nor defined in the file", pol["name"], name)
			}
			if pkg, ok := pol["install_software"].(map[string]any); ok {
				scope[name], _ = pkg["package_path"].(string)
			}
		}
	}
	family := func(pkg string) string {
		for name, p := range scope {
			if strings.HasSuffix(p, pkg) {
				return name
			}
		}
		t.Fatalf("no install policy for %s", pkg)
		return ""
	}
	deb, rpm := family("hawkbell-deb.package.yml"), family("hawkbell-rpm.package.yml")
	for _, tc := range []struct {
		platform, like, name string
		deb, rpm             bool
	}{
		{"debian", "", "Debian GNU/Linux", true, false},
		{"ubuntu", "debian", "Ubuntu", true, false},
		{"linuxmint", "ubuntu debian", "Linux Mint", true, false},
		{"rhel", "fedora", "Red Hat Enterprise Linux", false, true},
		{"rocky", "rhel centos fedora", "Rocky Linux", false, true},
		{"almalinux", "rhel centos fedora", "AlmaLinux", false, true},
		{"centos", "rhel fedora", "CentOS Stream", false, true},
		{"fedora", "", "Fedora Linux", false, true},
		{"amzn", "fedora", "Amazon Linux", false, true},
		{"arch", "", "Arch Linux", false, false},
		{"opensuse-leap", "suse opensuse", "openSUSE Leap", false, false},
	} {
		e := newEmu(t, "", atcFlavour)
		e.exec("INSERT INTO os_version (platform, platform_like, name) VALUES (?, ?, ?)", tc.platform, tc.like, tc.name)
		if got := e.passes(queries[deb]); got != tc.deb {
			t.Errorf("%s: member of %q = %v, want %v", tc.name, deb, got, tc.deb)
		}
		if got := e.passes(queries[rpm]); got != tc.rpm {
			t.Errorf("%s: member of %q = %v, want %v", tc.name, rpm, got, tc.rpm)
		}
	}
}

// scriptTier returns the tier an install script uses when Fleet runs it,
// i.e. with no environment: Fleet scripts get none.
func scriptTier(t *testing.T, rel string) string {
	t.Helper()
	s := readDeploy(t, rel)
	var re *regexp.Regexp
	if strings.HasSuffix(rel, ".ps1") {
		re = regexp.MustCompile(`(?m)^\$Tier = if \(\$env:HAWKBELL_TIER\) \{ \$env:HAWKBELL_TIER \} else \{ '(\w+)' \}`)
	} else {
		re = regexp.MustCompile(`(?m)^TIER=\$\{HAWKBELL_TIER:-(\w+)\}`)
	}
	m := re.FindStringSubmatch(s)
	if m == nil {
		t.Fatalf("%s: no default tier found", rel)
	}
	return m[1]
}

// TestGitOpsExamplesUseOneTier: ATC agent options and the hawkbell extension
// are alternatives (osquery refuses the extension when ATC provides the
// hawkbell_* tables, VERIFIED.md section 3), and agent options without ATC
// leave hosts that do not register the extension with no hawkbell tables. So
// in every example file, the agent options and what its scripts and
// packages register must be the same tier.
func TestGitOpsExamplesUseOneTier(t *testing.T) {
	root := deployDir(t)
	files, err := filepath.Glob(filepath.Join(root, "gitops", "*.yml"))
	if err != nil {
		t.Fatal(err)
	}
	more, _ := filepath.Glob(filepath.Join(root, "gitops", "fleets", "*.yml"))
	files = append(files, more...)
	if len(files) < 2 {
		t.Fatalf("found %d GitOps examples", len(files))
	}
	for _, f := range files {
		var doc struct {
			AgentOptions struct {
				Path string `yaml:"path"`
			} `yaml:"agent_options"`
			Controls struct {
				Scripts []struct {
					Path string `yaml:"path"`
				} `yaml:"scripts"`
			} `yaml:"controls"`
			Software struct {
				Packages []struct {
					Path string `yaml:"path"`
				} `yaml:"packages"`
			} `yaml:"software"`
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if err := yaml.Unmarshal(b, &doc); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		dir := filepath.Dir(f)
		name, _ := filepath.Rel(root, f)
		ao, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(doc.AgentOptions.Path)))
		if err != nil {
			t.Fatalf("%s: agent options: %v", name, err)
		}
		var opts map[string]any
		if err := yaml.Unmarshal(ao, &opts); err != nil {
			t.Fatalf("%s: agent options: %v", name, err)
		}
		tier := "extension"
		if hasHawkbellATC(opts) {
			tier = "atc"
		}
		for _, sc := range doc.Controls.Scripts {
			base := filepath.Base(sc.Path)
			if !strings.HasPrefix(base, "install-hawkbell.") {
				continue
			}
			if got := scriptTier(t, "scripts/"+base); got != tier {
				t.Errorf("%s: agent options %s are tier %s, but %s installs tier %s when Fleet runs it",
					name, doc.AgentOptions.Path, tier, base, got)
			}
		}
		for _, pk := range doc.Software.Packages {
			pb, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(pk.Path)))
			if err != nil {
				t.Fatal(err)
			}
			var pkgs []map[string]any
			if err := yaml.Unmarshal(pb, &pkgs); err != nil {
				t.Fatalf("%s: %v", pk.Path, err)
			}
			for _, p := range pkgs {
				post, _ := p["post_install_script"].(map[string]any)
				path, _ := post["path"].(string)
				if strings.Contains(path, "register-extension.") && tier != "extension" {
					t.Errorf("%s: agent options %s carry hawkbell's ATC tables, but %s registers the extension",
						name, doc.AgentOptions.Path, pk.Path)
				}
			}
		}
	}
}

// hasHawkbellATC reports whether agent options define any hawkbell_* ATC table,
// in config or in a platform override.
func hasHawkbellATC(opts map[string]any) bool {
	has := func(cfg any) bool {
		m, _ := cfg.(map[string]any)
		atc, _ := m[aoATC].(map[string]any)
		for k := range atc {
			if strings.HasPrefix(k, "hawkbell_") {
				return true
			}
		}
		return false
	}
	if has(opts[aoConfig]) {
		return true
	}
	ov, _ := opts[aoOverrides].(map[string]any)
	plats, _ := ov[aoPlatforms].(map[string]any)
	for _, p := range plats {
		if has(p) {
			return true
		}
	}
	return false
}

// TestHasHawkbellATCSeesTheExamples keeps the tier test honest: it must see
// the ATC tables in the ATC example and none in the base example.
func TestHasHawkbellATCSeesTheExamples(t *testing.T) {
	for file, want := range map[string]bool{"lib/" + FileATCExample: true, "lib/" + FileBaseExample: false} {
		var opts map[string]any
		if err := yaml.Unmarshal([]byte(readDeploy(t, file)), &opts); err != nil {
			t.Fatal(err)
		}
		if got := hasHawkbellATC(opts); got != want {
			t.Errorf("%s: hawkbell ATC tables found = %v, want %v", file, got, want)
		}
	}
}
