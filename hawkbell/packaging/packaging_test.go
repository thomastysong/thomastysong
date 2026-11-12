package packaging

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/thomastysong/thomastysong/hawkbell/internal/config"
)

// root is the module root (this file lives in packaging/).
func root(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Dir(wd)
}

// read returns a file with CRLF line endings turned into LF, so that the
// checks below mean the same on a Windows checkout that converted them;
// TestLineEndings checks the bytes on disk.
func read(t *testing.T, rel string) string {
	t.Helper()
	return strings.ReplaceAll(string(readRaw(t, rel)), "\r\n", "\n")
}

func readRaw(t *testing.T, rel string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root(t), filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func yamlDocs(t *testing.T, rel string) []map[string]any {
	t.Helper()
	dec := yaml.NewDecoder(strings.NewReader(read(t, rel)))
	var out []map[string]any
	for {
		var m map[string]any
		err := dec.Decode(&m)
		if errors.Is(err, io.EOF) {
			return out
		}
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		out = append(out, m)
	}
}

func get(v any, path ...string) any {
	for _, k := range path {
		m, ok := v.(map[string]any)
		if !ok {
			return nil
		}
		v = m[k]
	}
	return v
}

func strs(v any) []string {
	l, _ := v.([]any)
	out := make([]string, 0, len(l))
	for _, x := range l {
		s, _ := x.(string)
		out = append(out, s)
	}
	return out
}

type content struct {
	Src, Dst string
	Mode     int
}

func contents(v any) []content {
	var out []content
	for _, x := range v.([]any) {
		m := x.(map[string]any)
		c := content{Src: m["src"].(string), Dst: m["dst"].(string)}
		if mode, ok := get(m, "file_info", "mode").(int); ok {
			c.Mode = mode
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Dst < out[j].Dst })
	return out
}

// TestNFPMMatchesGoreleaser: `make package` (nfpm.yaml) and the release
// (.goreleaser.yaml) must produce the same packages.
func TestNFPMMatchesGoreleaser(t *testing.T) {
	nf := yamlDocs(t, "packaging/linux/nfpm.yaml")[0]
	gr := yamlDocs(t, ".goreleaser.yaml")[0]
	nfpms, _ := gr["nfpms"].([]any)
	if len(nfpms) != 1 {
		t.Fatalf("want one nfpms entry, got %d", len(nfpms))
	}
	g := nfpms[0].(map[string]any)

	for _, k := range []string{"maintainer", "description", "license", "section", "priority", "homepage", "vendor", "release"} {
		if a, b := nf[k], g[k]; a != b {
			t.Errorf("%s differs: nfpm.yaml %q, .goreleaser.yaml %q", k, a, b)
		}
	}
	for _, k := range []string{"preinstall", "postinstall", "preremove", "postremove"} {
		a, b := get(nf, "scripts", k), get(g, "scripts", k)
		if a == nil || a != b {
			t.Errorf("script %s: nfpm.yaml %v, .goreleaser.yaml %v", k, a, b)
		}
		if _, err := os.Stat(filepath.Join(root(t), a.(string))); err != nil {
			t.Errorf("script %s: %v", k, err)
		}
	}
	nc, gc := contents(nf["contents"]), contents(g["contents"])
	// nfpm.yaml lists the binary; goreleaser adds it from bindir.
	var rest []content
	for _, c := range nc {
		if c.Dst == "/usr/bin/hawkbell" {
			if c.Mode != 0o755 {
				t.Errorf("binary mode %o", c.Mode)
			}
			continue
		}
		rest = append(rest, c)
	}
	if g["bindir"] != "/usr/bin" {
		t.Errorf("goreleaser bindir %v, the unit runs /usr/bin/hawkbell", g["bindir"])
	}
	if a, b := jsonOf(rest), jsonOf(gc); a != b {
		t.Errorf("package contents differ:\n nfpm.yaml:       %s\n .goreleaser.yaml: %s", a, b)
	}
	for _, c := range gc {
		if _, err := os.Stat(filepath.Join(root(t), c.Src)); err != nil {
			t.Errorf("content %s: %v", c.Src, err)
		}
	}
	// deploy/fleet/software names the packages hawkbell_<version>_linux_<arch>.<fmt>.
	if g["file_name_template"] != "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}" {
		t.Errorf("file_name_template %v", g["file_name_template"])
	}
	for _, f := range []string{"deploy/fleet/software/hawkbell-deb.package.yml", "deploy/fleet/software/hawkbell-rpm.package.yml"} {
		if !regexp.MustCompile(`/hawkbell_[0-9][0-9.]*_linux_(amd64|arm64)\.(deb|rpm)\b`).MatchString(read(t, f)) {
			t.Errorf("%s does not name a package the release produces", f)
		}
	}
	// install-hawkbell.sh downloads raw binaries hawkbell_<os>_<arch>.
	var bin map[string]any
	for _, a := range gr["archives"].([]any) {
		if strs(get(a, "formats"))[0] == "binary" {
			bin = a.(map[string]any)
		}
	}
	if bin == nil || bin["name_template"] != "{{ .ProjectName }}_{{ .Os }}_{{ .Arch }}" {
		t.Errorf("binary archive: %v", bin)
	}
	if !strings.Contains(read(t, "deploy/fleet/scripts/install-hawkbell.sh"), "/hawkbell_linux_amd64") {
		t.Error("install-hawkbell.sh no longer downloads hawkbell_<os>_<arch>; update the binary archive name")
	}
	build := get(gr, "builds").([]any)[0]
	if !contains(strs(get(build, "flags")), "-trimpath") || !contains(strs(get(build, "env")), "CGO_ENABLED=0") {
		t.Errorf("build flags/env: %v %v", get(build, "flags"), get(build, "env"))
	}
	if g := strs(get(build, "goos")); strings.Join(g, ",") != "linux,darwin,windows" {
		t.Errorf("goos %v", g)
	}
	if g := strs(get(build, "goarch")); strings.Join(g, ",") != "amd64,arm64" {
		t.Errorf("goarch %v", g)
	}
}

// TestLicenseFilesShipped: every release format carries LICENSE, NOTICE
// (credits for reused data and designs) and THIRD_PARTY_LICENSES (the
// licenses of the statically linked modules), which their licenses require
// in any binary redistribution.
func TestLicenseFilesShipped(t *testing.T) {
	files := []string{"LICENSE", "NOTICE", "THIRD_PARTY_LICENSES"}
	for _, f := range files {
		if fi, err := os.Stat(filepath.Join(root(t), f)); err != nil || fi.Size() == 0 {
			t.Errorf("%s missing or empty: %v", f, err)
		}
	}
	gr := yamlDocs(t, ".goreleaser.yaml")[0]
	for _, a := range gr["archives"].([]any) {
		if strs(get(a, "formats"))[0] == "binary" {
			continue // a raw binary cannot carry files; the other archives do
		}
		got := strs(get(a, "files"))
		for _, f := range files {
			if !contains(got, f) {
				t.Errorf("archive %v lacks %s", get(a, "id"), f)
			}
		}
	}
	nf := yamlDocs(t, "packaging/linux/nfpm.yaml")[0]
	g := gr["nfpms"].([]any)[0].(map[string]any)
	for name, cs := range map[string][]content{"nfpm.yaml": contents(nf["contents"]), ".goreleaser.yaml nfpms": contents(g["contents"])} {
		for _, f := range files {
			ok := false
			for _, c := range cs {
				if c.Src == f && c.Dst == "/usr/share/doc/hawkbell/"+f && c.Mode == 0o644 {
					ok = true
				}
			}
			if !ok {
				t.Errorf("%s does not install %s as /usr/share/doc/hawkbell/%s mode 0644", name, f, f)
			}
		}
	}
	// Both final image stages (binary and sensor) copy them.
	df := read(t, "Dockerfile")
	line := "COPY " + strings.Join(files, " ") + " /usr/share/doc/hawkbell/"
	stages := regexp.MustCompile(`(?m)^FROM `).Split(df, -1)
	for _, st := range stages[1:] {
		name := regexp.MustCompile(`AS (\S+)`).FindStringSubmatch(st)
		if name == nil || name[1] == "build" {
			continue
		}
		if !strings.Contains(st, line) {
			t.Errorf("Dockerfile stage %s lacks %q", name[1], line)
		}
	}
	pkg := read(t, "packaging/macos/build-pkg.sh")
	if !strings.Contains(pkg, "for f in "+strings.Join(files, " ")+"; do") || !strings.Contains(pkg, "/usr/local/share/doc/hawkbell/$f") {
		t.Error("macOS pkg does not install the license files under /usr/local/share/doc/hawkbell")
	}
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}

func jsonOf(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

var shellScripts = []string{
	"packaging/linux/preinstall.sh",
	"packaging/linux/postinstall.sh",
	"packaging/linux/preremove.sh",
	"packaging/linux/postremove.sh",
	"packaging/macos/postinstall",
	"packaging/macos/build-pkg.sh",
	"deploy/kubernetes/in-image/hawkbell-entrypoint.sh",
	"deploy/kubernetes/in-image/devcontainer-feature/install.sh",
}

// TestLineEndings: shell scripts are LF on disk on every OS (a CRLF
// post-install script does not run), which the .gitattributes files of the
// trees that hold them enforce on a Windows checkout.
func TestLineEndings(t *testing.T) {
	for _, s := range shellScripts {
		if bytes.Contains(readRaw(t, s), []byte("\r")) {
			t.Errorf("%s has CR line endings", s)
		}
	}
	for _, f := range []string{"packaging/.gitattributes", "deploy/kubernetes/.gitattributes"} {
		if !regexp.MustCompile(`(?m)^\* text=auto eol=lf$`).MatchString(read(t, f)) {
			t.Errorf("%s does not keep LF line endings", f)
		}
	}
	ci := read(t, ".github/workflows/ci.yml")
	if i, j := strings.Index(ci, "git config --global core.autocrlf false"), strings.Index(ci, "actions/checkout"); i < 0 || i > j {
		t.Error("ci.yml: the Windows job must turn core.autocrlf off before the checkout")
	}
}

// TestShellScripts: every script parses under the POSIX shells present
// here and is executable.
func TestShellScripts(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no POSIX shell")
	}
	var shells []string
	for _, sh := range []string{"sh", "dash", "bash", "busybox"} {
		if _, err := exec.LookPath(sh); err == nil {
			shells = append(shells, sh)
		}
	}
	if len(shells) == 0 {
		t.Skip("no shell found")
	}
	for _, s := range shellScripts {
		p := filepath.Join(root(t), s)
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm()&0o111 == 0 {
			t.Errorf("%s is not executable", s)
		}
		if !strings.HasPrefix(read(t, s), "#!/bin/sh\n") {
			t.Errorf("%s: want #!/bin/sh (the scripts are POSIX sh)", s)
		}
		for _, sh := range shells {
			args := []string{"-n", p}
			if sh == "busybox" {
				args = append([]string{"sh"}, args...)
			}
			if out, err := exec.Command(sh, args...).CombinedOutput(); err != nil {
				t.Errorf("%s -n %s: %v\n%s", sh, s, err, out)
			}
		}
	}
}

// assign returns the value of the first `NAME=value` line in a script.
func assign(t *testing.T, script, name string) string {
	t.Helper()
	m := regexp.MustCompile(`(?m)^` + name + `=(.*)$`).FindStringSubmatch(script)
	if m == nil {
		t.Fatalf("no %s= line", name)
	}
	v := strings.Trim(m[1], `"`)
	return v
}

// TestScriptsMatchServiceDefinitions: the post-install scripts create what
// the service definitions use.
func TestScriptsMatchServiceDefinitions(t *testing.T) {
	unit := read(t, "packaging/systemd/hawkbell.service")
	post := read(t, "packaging/linux/postinstall.sh")
	pre := read(t, "packaging/linux/preinstall.sh")
	exec := regexp.MustCompile(`(?m)^ExecStart=(\S+) run --config (\S+)$`).FindStringSubmatch(unit)
	if exec == nil {
		t.Fatal("ExecStart not found")
	}
	if b := assign(t, post, "BIN"); b != exec[1] {
		t.Errorf("unit runs %s, postinstall uses %s", exec[1], b)
	}
	if c := strings.ReplaceAll(assign(t, post, "CONF"), "$CONF_DIR", assign(t, post, "CONF_DIR")); c != exec[2] {
		t.Errorf("unit reads %s, postinstall writes %s", exec[2], c)
	}
	if !strings.Contains(unit, "\nGroup=hawkbell\n") || !strings.Contains(pre, "groupadd --system hawkbell") || !strings.Contains(pre, "addgroup --system hawkbell") {
		t.Error("the unit's Group= and the group preinstall creates differ")
	}
	// systemd sets StateDirectoryMode at every start; the package creates the
	// directory the same way so hooks can reach their spool before that.
	mode := regexp.MustCompile(`(?m)^StateDirectoryMode=(0[0-7]{3})$`).FindStringSubmatch(unit)
	if mode == nil || !strings.Contains(unit, "\nStateDirectory=hawkbell\n") || assign(t, post, "DATA") != "/var/lib/hawkbell" ||
		!strings.Contains(post, `chmod `+mode[1]+` "$DATA"`) || !strings.Contains(post, `chown root:hawkbell "$DATA"`) {
		t.Errorf("data directory: unit StateDirectory/StateDirectoryMode %v and postinstall disagree", mode)
	}
	// The extension paths are register-extension.sh's.
	reg := read(t, "deploy/fleet/scripts/register-extension.sh")
	for _, s := range []string{post, read(t, "packaging/linux/preremove.sh")} {
		if !strings.Contains(s, "EXT_DIR=/usr/lib/hawkbell") || !strings.Contains(s, "LOAD=/etc/osquery/extensions.load") {
			t.Error("extension paths differ from the Linux packages' scripts")
		}
	}
	if !strings.Contains(reg, "EXTDIR=$ROOT/usr/lib/hawkbell LOAD=$ROOT/etc/osquery/extensions.load") {
		t.Error("register-extension.sh moved the extension; update packaging/linux scripts")
	}

	// macOS: the plist and the postinstall.
	plist := read(t, "packaging/launchd/com.github.thomastysong.hawkbell.plist")
	mac := read(t, "packaging/macos/postinstall")
	if !strings.Contains(plist, "<string>/usr/local/bin/hawkbell</string>") || assign(t, mac, "BIN") != "$ROOT/usr/local/bin/hawkbell" {
		t.Error("macOS binary path differs between plist and postinstall")
	}
	if !strings.Contains(plist, "<string>/Library/Application Support/hawkbell/hawkbell.yaml</string>") ||
		assign(t, mac, "CONF_DIR") != "$ROOT/Library/Application Support/hawkbell" {
		t.Error("macOS configuration path differs between plist and postinstall")
	}
	logPath := regexp.MustCompile(`<key>StandardErrorPath</key>\s*<string>([^<]+)</string>`).FindStringSubmatch(plist)
	if logPath == nil || filepath.Dir(logPath[1]) != strings.TrimPrefix(assign(t, mac, "LOGS"), "$ROOT") {
		t.Errorf("launchd does not create directories: postinstall must create %v", logPath)
	}
	label := regexp.MustCompile(`<key>Label</key>\s*<string>([^<]+)</string>`).FindStringSubmatch(plist)
	if label == nil || assign(t, mac, "LABEL") != label[1] {
		t.Error("launchd label differs")
	}

	// Windows: the service command line never goes through sc.exe binPath=
	// (PowerShell 5.1 mangles the embedded quotes), and the WiX sketch runs
	// the same command line.
	ps := read(t, "packaging/windows/install-service.ps1")
	if regexp.MustCompile(`(?m)^[^#]*binPath=`).MatchString(ps) {
		t.Error("install-service.ps1 sets the service command line through sc.exe binPath=")
	}
	if !strings.Contains(ps, "'\" run --config \"'") {
		t.Error("install-service.ps1 service command line changed")
	}
	wxs := read(t, "packaging/windows/hawkbell.wxs")
	if !strings.Contains(wxs, `Arguments="run --config &quot;[DATAFOLDER]hawkbell.yaml&quot;"`) || !strings.Contains(wxs, `Name="hawkbell.exe"`) {
		t.Error("hawkbell.wxs service command line differs from install-service.ps1")
	}
}

// hookStep returns step 6 of a post-install script: the call that rewrites
// the managed hook entries that already exist, and what it does with the
// answer.
func hookStep(t *testing.T, script string) string {
	t.Helper()
	m := regexp.MustCompile(`(?s)if out=\$\("\$BIN" hooks install --only-installed --scope managed[^\n]*\n.*?\nfi\n`).FindString(script)
	if m == "" {
		t.Fatal("hook step not found")
	}
	return m
}

// shBlock returns the lines of a script from the first one that starts
// with start up to and including the first line after it that equals end.
func shBlock(t *testing.T, script, start, end string) string {
	t.Helper()
	i := strings.Index(script, start)
	if i < 0 {
		t.Fatalf("block %q not found", start)
	}
	j := strings.Index(script[i:], "\n"+end+"\n")
	if j < 0 {
		t.Fatalf("block %q has no end %q", start, end)
	}
	return script[i : i+j+len(end)+2]
}

// TestScriptsRefreshHooksOnlyInstalled: every install or upgrade path
// (deb/rpm, macOS pkg, Windows service script, Fleet scripts) rewrites
// hawkbell's managed hooks with `hooks install --only-installed`, which
// selects the already-hooked agents and keeps their options itself, rather
// than parsing `hooks status` (the awk and regex selection it replaced
// could only keep entries written with install's default options). Every
// removal path takes the managed entries out while the binary still
// exists, before the binary goes.
func TestScriptsRefreshHooksOnlyInstalled(t *testing.T) {
	for _, f := range []string{"packaging/linux/postinstall.sh", "packaging/macos/postinstall", "packaging/windows/install-service.ps1",
		"deploy/fleet/scripts/install-hawkbell.sh", "deploy/fleet/scripts/install-hawkbell.ps1"} {
		s := read(t, f)
		if !strings.Contains(s, "hooks install --only-installed --scope managed") {
			t.Errorf("%s does not refresh the managed hooks with --only-installed", f)
		}
		// awk as a word: the binary's name contains the letters.
		for _, bad := range []string{`hooks status`, `\bawk\b`, `ConvertFrom-Json`, `earlier hawkbell release`} {
			if regexp.MustCompile(bad).MatchString(stripShComments(s)) {
				t.Errorf("%s still selects hooks itself (%q)", f, bad)
			}
		}
	}
	for f, binGone := range map[string]string{
		"packaging/linux/preremove.sh":                `rm -f "$EXT" "$EXT.new"`,
		"deploy/fleet/scripts/uninstall-hawkbell.sh":  `rm -f "$EXT" "$BIN"`,
		"deploy/fleet/scripts/uninstall-hawkbell.ps1": `Remove-Item -Force -Recurse -ErrorAction SilentlyContinue -Path $Dir`,
		"packaging/windows/install-service.ps1":       `Invoke-Native sc.exe @('delete', $Name)`,
	} {
		s := stripShComments(read(t, f))
		i, j := strings.Index(s, "hooks uninstall --scope managed"), strings.Index(s, binGone)
		if i < 0 || j < 0 {
			t.Errorf("%s: hooks uninstall at %d, binary removal at %d", f, i, j)
		} else if f != "packaging/linux/preremove.sh" && i > j {
			// preremove runs it last on purpose (an aborted removal keeps
			// the administrator's hook options); the binary is removed by
			// dpkg/rpm after the script.
			t.Errorf("%s removes the binary before the managed hook entries", f)
		}
	}
}

// stripShComments drops whole-line comments (shell and PowerShell).
func stripShComments(s string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "#") {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// TestUpgradeKeepsHookOptions runs the hook steps of the install scripts,
// as written, with the real binary on a file-system prefix where an
// administrator registered Claude Code's managed hooks in guard mode with
// --fail-closed and a 30 s timeout and Codex's with a 20 s timeout, an
// earlier release left Gemini CLI's and Codex's entries in their unguarded
// form, Cursor's are current and Copilot's were edited by hand. An upgrade
// must not turn the fail-closed guard into a fail-open one or reset a
// timeout (review finding PKG-1), must update the earlier release's
// entries with the options they carry, must leave the edited file alone
// and must hook no agent that was not hooked. Then the removal steps take
// every managed entry out.
func TestUpgradeKeepsHookOptions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell")
	}
	if testing.Short() {
		t.Skip("builds hawkbell")
	}
	if os.Geteuid() != 0 {
		t.Skip("managed hook files are root-owned")
	}
	sh, err := exec.LookPath("sh")
	if err != nil {
		t.Skip("no sh")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "hawkbell")
	build := exec.Command("go", "build", "-o", bin, "./cmd/hawkbell")
	build.Dir = root(t)
	build.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("go build: %v\n%s", err, out)
	}
	prefix := filepath.Join(dir, "host")
	if err := os.MkdirAll(prefix, 0o755); err != nil {
		t.Fatal(err)
	}
	run := func(args ...string) []byte {
		t.Helper()
		out, err := exec.Command(bin, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("hawkbell %s: %v\n%s", strings.Join(args, " "), err, out)
		}
		return out
	}
	install := func(extra ...string) {
		t.Helper()
		run(append([]string{"hooks", "install", "--scope", "managed", "--root", prefix, "--binary", "/usr/bin/hawkbell"}, extra...)...)
	}
	file := func(rel string) string { return filepath.Join(prefix, filepath.FromSlash(rel)) }
	claude, gemini, cursor := file("etc/claude-code/managed-settings.d/50-hawkbell.json"), file("etc/gemini-cli/settings.json"), file("etc/cursor/hooks.json")
	codex, copilot := file("etc/codex/requirements.toml"), file("etc/github-copilot/policy.d/hawkbell.json")
	// The command lines of the releases before the missing-binary check.
	unguard := func(path, agent string) {
		t.Helper()
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		cur := `[ -x '/usr/bin/hawkbell' ] || exit 0; exec '/usr/bin/hawkbell' hook --agent ` + agent
		if !bytes.Contains(b, []byte(cur)) {
			t.Fatalf("setup: no current %s command line in\n%s", agent, b)
		}
		if err := os.WriteFile(path, bytes.ReplaceAll(b, []byte(cur), []byte(`'/usr/bin/hawkbell' hook --agent `+agent)), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	setup := func() map[string][]byte {
		t.Helper()
		if err := os.RemoveAll(prefix); err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(prefix, 0o755); err != nil {
			t.Fatal(err)
		}
		install("--agents", "claude-code", "--guard", "--fail-closed", "--timeout", "30")
		install("--agents", "codex", "--timeout", "20")
		install("--agents", "gemini-cli,cursor,copilot-cli")
		unguard(gemini, "gemini-cli")
		unguard(codex, "codex")
		b, _ := os.ReadFile(copilot)
		if err := os.WriteFile(copilot, bytes.Replace(b, []byte(`"timeoutSec": 10`), []byte(`"timeoutSec": 12`), 1), 0o644); err != nil {
			t.Fatal(err)
		}
		before := map[string][]byte{}
		for _, f := range []string{claude, cursor, copilot} {
			if before[f], err = os.ReadFile(f); err != nil {
				t.Fatal(err)
			}
		}
		if !bytes.Contains(before[claude], []byte(`"onFailure": "block"`)) || !bytes.Contains(before[claude], []byte(`"timeout": 30`)) {
			t.Fatalf("setup: no fail-closed entry with a 30 s timeout:\n%s", before[claude])
		}
		return before
	}

	// $BIN for the step: hawkbell on the prefix, installing the packaged path
	// (the macOS step passes --root and --binary itself).
	wrapper := filepath.Join(dir, "hawkbell-on-prefix")
	ws := "#!/bin/sh\nsub=$1 verb=$2\nshift 2\n" +
		"case \"$*\" in *--root*) exec '" + bin + "' \"$sub\" \"$verb\" \"$@\" ;; esac\n" +
		"if [ \"$verb\" = install ]; then set -- --binary /usr/bin/hawkbell \"$@\"; fi\n" +
		"exec '" + bin + "' \"$sub\" \"$verb\" --root '" + prefix + "' \"$@\"\n"
	if err := os.WriteFile(wrapper, []byte(ws), 0o755); err != nil {
		t.Fatal(err)
	}
	fleet := read(t, "deploy/fleet/scripts/install-hawkbell.sh")
	steps := map[string]string{
		"packaging/linux/postinstall.sh": "BIN='" + wrapper + "'\n" + hookStep(t, read(t, "packaging/linux/postinstall.sh")),
		// On another volume: $ROOT is the prefix, the binary is found there.
		"packaging/macos/postinstall": "ROOT='" + prefix + "'\nBIN='" + bin + "'\n" + strings.ReplaceAll(hookStep(t, read(t, "packaging/macos/postinstall")), "--binary /usr/local/bin/hawkbell", "--binary /usr/bin/hawkbell"),
		// The Fleet script with its test prefix: BIN is $ROOT/usr/bin/hawkbell.
		"deploy/fleet/scripts/install-hawkbell.sh": "ROOT='" + prefix + "'\nBIN='" + prefix + "/usr/bin/hawkbell'\nmkdir -p '" + prefix + "/usr/bin' && cp '" + bin + "' \"$BIN\"\n" +
			shBlock(t, fleet, `"$BIN" hooks install --only-installed`, `	echo "hawkbell install: warning: managed hooks not refreshed" >&2`),
	}
	for _, rel := range []string{"packaging/linux/postinstall.sh", "packaging/macos/postinstall", "deploy/fleet/scripts/install-hawkbell.sh"} {
		before := setup()
		script := "set -eu\nwarn() { echo \"hawkbell: warning: $*\" >&2; }\n" + steps[rel]
		out, err := exec.Command(sh, "-c", script).CombinedOutput()
		t.Logf("%s hook step:\n%s", rel, out)
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		o := string(out)
		if rel != "deploy/fleet/scripts/install-hawkbell.sh" {
			for _, w := range []string{
				"hawkbell: managed hooks rewritten for gemini-cli\n",
				"hawkbell: managed hooks rewritten for codex with --timeout 20\n",
				"hawkbell: managed hooks of claude-code left as they are: already what install writes (--guard --fail-closed --timeout 30)",
				"hawkbell: managed hooks of copilot-cli left as they are: the hawkbell entries differ",
			} {
				if !strings.Contains(o, w) {
					t.Errorf("%s: output lacks %q", rel, w)
				}
			}
		} else if !strings.Contains(o, "managed hooks rewritten for gemini-cli\n") {
			t.Errorf("%s: the earlier release's gemini-cli entries were not rewritten", rel)
		}
		for f, b := range before {
			after, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(after, b) {
				t.Errorf("%s: %s changed:\n%s", rel, f, after)
			}
		}
		var st []struct{ Agent, Status, Detail, Hash string }
		if err := json.Unmarshal(run("hooks", "status", "--scope", "managed", "--root", prefix, "--json"), &st); err != nil {
			t.Fatal(err)
		}
		for _, s := range st {
			switch s.Agent {
			case "gemini-cli":
				if s.Status != "managed" {
					t.Errorf("%s: gemini-cli after the upgrade: %s (%s)", rel, s.Status, s.Detail)
				}
			case "claude-code", "codex", "cursor", "copilot-cli":
				if strings.Contains(s.Detail, "earlier hawkbell release") {
					t.Errorf("%s: %s still in the earlier form: %s", rel, s.Agent, s.Detail)
				}
			default:
				if s.Hash != "" {
					t.Errorf("%s: %s was hooked by the upgrade", rel, s.Agent)
				}
			}
		}
		if b, _ := os.ReadFile(codex); !bytes.Contains(b, []byte("timeout = 20")) {
			t.Errorf("%s: codex lost its 20 s timeout:\n%s", rel, b)
		}
	}

	// Removal: the Fleet uninstall script's hook step, with the binary in
	// place, takes every managed entry out.
	setup()
	un := read(t, "deploy/fleet/scripts/uninstall-hawkbell.sh")
	script := "set -eu\nROOT='" + prefix + "'\nBIN='" + prefix + "/usr/bin/hawkbell'\nmkdir -p '" + prefix + "/usr/bin' && cp '" + bin + "' \"$BIN\"\n" +
		shBlock(t, un, `if [ -x "$BIN" ]; then`, "fi")
	if out, err := exec.Command(sh, "-c", script).CombinedOutput(); err != nil {
		t.Fatalf("uninstall hook step: %v\n%s", err, out)
	}
	var st []struct{ Agent, Hash string }
	if err := json.Unmarshal(run("hooks", "status", "--scope", "managed", "--root", prefix, "--json"), &st); err != nil {
		t.Fatal(err)
	}
	for _, s := range st {
		if s.Hash != "" {
			t.Errorf("uninstall-hawkbell.sh left %s's managed entries", s.Agent)
		}
	}
}

// TestWindowsInstallScript: install-service.ps1 refreshes hooks the way the
// POSIX scripts do, lets hooks read the configuration without opening the
// rest of the data directory, and handles the osquery extension copy the way
// the Fleet scripts register it.
func TestWindowsInstallScript(t *testing.T) {
	ps := read(t, "packaging/windows/install-service.ps1")
	if !strings.Contains(ps, "& $Exe hooks install --only-installed --scope managed\nif ($LASTEXITCODE -ne 0)") {
		t.Error("install-service.ps1 does not refresh the managed hooks with --only-installed, checking its exit code")
	}
	if strings.Contains(ps, "'modified', 'shadowed'") {
		t.Error("install-service.ps1 still rewrites every modified entry with default options")
	}
	// Users: list and read on the data directory itself (no inheritance
	// flags: state.db and the daemon's files must not inherit it) and read on
	// hawkbell.yaml (review finding PKG-3).
	if !strings.Contains(ps, `icacls.exe @($Data, '/grant:r', '*S-1-5-32-545:RX')`) ||
		!strings.Contains(ps, `icacls.exe @($Config, '/grant:r', '*S-1-5-32-545:R')`) {
		t.Error("install-service.ps1: hooks cannot read hawkbell.yaml")
	}
	if regexp.MustCompile(`\$Data[^\n]*545:\((OI|CI)\)`).MatchString(ps) {
		t.Error("install-service.ps1 grants Users an inherited ACE on the data directory")
	}
	fleet := read(t, "deploy/fleet/scripts/install-hawkbell.ps1")
	for _, re := range []string{`\$Ext\s*= Join-Path \$Dir 'hawkbell\.ext\.exe'`, `\$Load\s*= Join-Path \$env:ProgramFiles 'osquery\\extensions\.load'`} {
		r := regexp.MustCompile(re)
		if !r.MatchString(ps) || !r.MatchString(fleet) {
			t.Errorf("osquery extension path %s differs from deploy/fleet/scripts/install-hawkbell.ps1", re)
		}
	}
	if !strings.Contains(ps, "Copy-Item -Force -Path $Exe -Destination $Ext") || !strings.Contains(ps, "Where-Object { $_ -ne $Ext }") {
		t.Error("install-service.ps1 neither refreshes nor unregisters the osquery extension copy")
	}

	// The WiX sketch: well-formed XML (no "--" in comments), the same ACL.
	dec := xml.NewDecoder(strings.NewReader(read(t, "packaging/windows/hawkbell.wxs")))
	var usersOnData, grant bool
	var inData bool
	for {
		tok, err := dec.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("hawkbell.wxs: %v", err)
		}
		el, ok := tok.(xml.StartElement)
		if !ok {
			continue
		}
		attr := map[string]string{}
		for _, a := range el.Attr {
			attr[a.Name.Local] = a.Value
		}
		switch el.Name.Local {
		case "Component":
			inData = attr["Directory"] == "DATAFOLDER"
		case "PermissionEx":
			if inData && attr["User"] == "Users" {
				usersOnData = attr["Inheritable"] == "no" && attr["GenericWrite"] == "" && attr["GenericAll"] == ""
			}
		case "CustomAction":
			grant = grant || (attr["Id"] == "GrantConfigRead" && strings.Contains(attr["ExeCommand"], "hawkbell.yaml&quot; /grant:r *S-1-5-32-545:R") ||
				attr["Id"] == "GrantConfigRead" && strings.Contains(attr["ExeCommand"], `hawkbell.yaml" /grant:r *S-1-5-32-545:R`))
		}
	}
	if !usersOnData || !grant {
		t.Errorf("hawkbell.wxs: Users read on the data folder only %v, read grant on hawkbell.yaml %v", usersOnData, grant)
	}
}

// TestDockerfile: pinned bases, no Docker Hub frontend, the capabilities
// the DaemonSet grants, non-root user.
func TestDockerfile(t *testing.T) {
	df := read(t, "Dockerfile")
	if regexp.MustCompile(`(?m)^#\s*syntax=`).MatchString(df) {
		t.Error("a # syntax= line pulls the frontend from Docker Hub")
	}
	for _, arg := range []string{"GO_IMAGE", "BASE_IMAGE"} {
		m := regexp.MustCompile(`(?m)^ARG ` + arg + `=(\S+)$`).FindStringSubmatch(df)
		if m == nil || !regexp.MustCompile(`@sha256:[0-9a-f]{64}$`).MatchString(m[1]) {
			t.Errorf("%s not pinned by digest: %v", arg, m)
		}
		if m != nil && (strings.HasPrefix(m[1], "docker.io/") || !strings.Contains(strings.SplitN(m[1], "/", 2)[0], ".")) {
			t.Errorf("%s comes from Docker Hub: %s", arg, m[1])
		}
	}
	for _, want := range []string{"CGO_ENABLED=0", "-trimpath", "-buildvcs=false", "-buildid=", "USER 65532:65532",
		"go run ./packaging/container/filecap set cap_dac_read_search,cap_sys_ptrace=ep",
		"go run ./packaging/container/filecap verify cap_dac_read_search,cap_sys_ptrace=ep",
		`ENTRYPOINT ["/usr/bin/hawkbell"]`} {
		if !strings.Contains(df, want) {
			t.Errorf("Dockerfile lacks %q", want)
		}
	}
	// The file capabilities are exactly what the DaemonSet adds.
	add := daemonSetContainer(t)["securityContext"].(map[string]any)["capabilities"].(map[string]any)["add"]
	var caps []string
	for _, c := range strs(add) {
		caps = append(caps, "cap_"+strings.ToLower(c))
	}
	sort.Strings(caps)
	if got := strings.Join(caps, ","); got != "cap_dac_read_search,cap_sys_ptrace" {
		t.Errorf("DaemonSet adds %s, the image's file capabilities are cap_dac_read_search,cap_sys_ptrace", got)
	}
	di := read(t, ".dockerignore")
	for _, want := range []string{".git", "dist", "**/*.test"} {
		if !strings.Contains(di, want) {
			t.Errorf(".dockerignore lacks %s", want)
		}
	}
}

func daemonSet(t *testing.T) map[string]any {
	t.Helper()
	for _, d := range yamlDocs(t, "deploy/kubernetes/daemonset.yaml") {
		if d["kind"] == "DaemonSet" {
			return d
		}
	}
	t.Fatal("no DaemonSet")
	return nil
}

func daemonSetContainer(t *testing.T) map[string]any {
	t.Helper()
	cs := get(daemonSet(t), "spec", "template", "spec", "containers").([]any)
	if len(cs) != 1 {
		t.Fatalf("want one container, got %d", len(cs))
	}
	return cs[0].(map[string]any)
}

// TestDaemonSet holds the manifest to the red team's minimal container
// story (redteam/containers-k8s.md, "Minimal honest container story for
// v1", from findings E1 and E2) and checks the shipped configuration with
// the configuration loader the daemon uses.
func TestDaemonSet(t *testing.T) {
	ds := daemonSet(t)
	pod := get(ds, "spec", "template", "spec").(map[string]any)
	want := map[string]any{"hostPID": true, "hostNetwork": false, "hostIPC": false, "automountServiceAccountToken": false}
	for k, v := range want {
		if pod[k] != v {
			t.Errorf("pod %s = %v, want %v", k, pod[k], v)
		}
	}
	if get(pod, "securityContext", "runAsNonRoot") != true || get(pod, "securityContext", "runAsUser") != 65532 ||
		get(pod, "securityContext", "runAsGroup") != 65532 {
		t.Errorf("pod securityContext: %v", pod["securityContext"])
	}
	for _, v := range pod["volumes"].([]any) {
		m := v.(map[string]any)
		if _, ok := m["hostPath"]; ok {
			t.Errorf("hostPath volume %v", m["name"])
		}
		if m["configMap"] == nil && m["emptyDir"] == nil {
			t.Errorf("volume %v is neither a ConfigMap nor an emptyDir", m["name"])
		}
	}
	c := daemonSetContainer(t)
	sc := c["securityContext"].(map[string]any)
	if sc["allowPrivilegeEscalation"] != true {
		t.Error("allowPrivilegeEscalation must be true: no_new_privs disables file capabilities")
	}
	if sc["readOnlyRootFilesystem"] != true || sc["privileged"] != false {
		t.Errorf("container securityContext: %v", sc)
	}
	if d := strs(get(sc, "capabilities", "drop")); strings.Join(d, ",") != "ALL" {
		t.Errorf("drop %v", d)
	}
	if strings.Join(strs(c["args"]), " ") != "run --config /etc/hawkbell/hawkbell.yaml --log-format json" {
		t.Errorf("args %v", c["args"])
	}
	mounts := map[string]bool{}
	for _, m := range c["volumeMounts"].([]any) {
		mounts[get(m, "mountPath").(string)] = true
	}
	if !mounts["/etc/hawkbell"] || !mounts["/var/lib/hawkbell"] {
		t.Errorf("mounts %v", mounts)
	}
	ns := yamlDocs(t, "deploy/kubernetes/namespace.yaml")[0]
	if get(ns, "metadata", "labels", "pod-security.kubernetes.io/enforce") != "privileged" {
		t.Error("namespace must admit privileged pods (hostPID, SYS_PTRACE, DAC_READ_SEARCH are outside baseline)")
	}
	for _, r := range strs(yamlDocs(t, "deploy/kubernetes/kustomization.yaml")[0]["resources"]) {
		if _, err := os.Stat(filepath.Join(root(t), "deploy", "kubernetes", r)); err != nil {
			t.Errorf("kustomization resource %s: %v", r, err)
		}
	}

	// The ConfigMap's hawkbell.yaml loads with the daemon's own loader (unknown
	// keys are errors there).
	cm := yamlDocs(t, "deploy/kubernetes/configmap.yaml")[0]
	body, _ := get(cm, "data").(map[string]any)["hawkbell.yaml"].(string)
	f := filepath.Join(t.TempDir(), "hawkbell.yaml")
	if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(f, "/var/lib/hawkbell")
	if err != nil {
		t.Fatalf("ConfigMap hawkbell.yaml: %v", err)
	}
	if cfg.DataDir != "/var/lib/hawkbell" || !cfg.Output.Stdout || cfg.Privacy.Profile != "minimal" {
		t.Errorf("ConfigMap config: data_dir %q stdout %v profile %q", cfg.DataDir, cfg.Output.Stdout, cfg.Privacy.Profile)
	}
	if config.On(cfg.Sources.Transcripts.Enabled, true) || config.On(cfg.Sources.Scan.Enabled, true) || !config.On(cfg.Sources.Processes.Enabled, true) {
		t.Error("node sensor collectors: want processes on, transcripts and scan off (they would read the sensor's own file system)")
	}
	// The in-image configuration the examples write.
	for _, rel := range []string{"deploy/kubernetes/in-image/Dockerfile.example", "deploy/kubernetes/in-image/devcontainer-feature/install.sh"} {
		if !strings.Contains(read(t, rel), `printf 'data_dir: /var/lib/hawkbell\noutput:\n  stdout: true\n'`) {
			t.Errorf("%s: in-image configuration changed; check it with config.Load", rel)
		}
	}
	f2 := filepath.Join(t.TempDir(), "in-image.yaml")
	if err := os.WriteFile(f2, []byte("data_dir: /var/lib/hawkbell\noutput:\n  stdout: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(f2, "/var/lib/hawkbell"); err != nil {
		t.Errorf("in-image configuration: %v", err)
	}
}

// seccompProfile is the OCI runtime-spec form of a seccomp profile, the
// only fields a Localhost profile may use: moby's includes/excludes/archMap
// are not part of it, and a runtime that decodes only these fields would
// drop the conditions they carry.
type seccompProfile struct {
	DefaultAction   string   `json:"defaultAction"`
	DefaultErrnoRet *uint    `json:"defaultErrnoRet"`
	Architectures   []string `json:"architectures"`
	Syscalls        []struct {
		Names    []string `json:"names"`
		Action   string   `json:"action"`
		ErrnoRet *uint    `json:"errnoRet"`
		Args     []struct {
			Index    uint   `json:"index"`
			Value    uint64 `json:"value"`
			ValueTwo uint64 `json:"valueTwo"`
			Op       string `json:"op"`
		} `json:"args"`
	} `json:"syscalls"`
}

// TestSeccompProfile: the DaemonSet runs under seccomp/node-sensor.json,
// which takes away every call through which CAP_SYS_PTRACE with hostPID
// would let a compromised sensor control or write into other processes
// (review finding PKG-2), and keeps what the sensor needs.
func TestSeccompProfile(t *testing.T) {
	sp := get(daemonSet(t), "spec", "template", "spec", "securityContext", "seccompProfile")
	if get(sp, "type") != "Localhost" || get(sp, "localhostProfile") != "hawkbell/node-sensor.json" {
		t.Fatalf("DaemonSet seccompProfile %v, want Localhost hawkbell/node-sensor.json", sp)
	}
	if c := daemonSetContainer(t); get(c, "securityContext", "seccompProfile") != nil {
		t.Error("the container overrides the pod's seccomp profile")
	}
	dec := json.NewDecoder(bytes.NewReader(readRaw(t, "deploy/kubernetes/seccomp/node-sensor.json")))
	dec.DisallowUnknownFields()
	var p seccompProfile
	if err := dec.Decode(&p); err != nil {
		t.Fatalf("node-sensor.json is not a plain OCI seccomp profile: %v", err)
	}
	if p.DefaultAction != "SCMP_ACT_ERRNO" || p.DefaultErrnoRet == nil || *p.DefaultErrnoRet != 1 {
		t.Errorf("default action %s %v, want SCMP_ACT_ERRNO with EPERM", p.DefaultAction, p.DefaultErrnoRet)
	}
	for _, a := range []string{"SCMP_ARCH_X86_64", "SCMP_ARCH_AARCH64"} {
		if !contains(p.Architectures, a) {
			t.Errorf("architectures %v lack %s", p.Architectures, a)
		}
	}
	allowed := map[string]bool{}
	for _, r := range p.Syscalls {
		switch r.Action {
		case "SCMP_ACT_ALLOW":
			for _, n := range r.Names {
				allowed[n] = true
			}
		case "SCMP_ACT_ERRNO":
		default:
			t.Errorf("rule %v: action %s", r.Names, r.Action)
		}
	}
	// Control of other processes, then what the runtime default denies to a
	// container without CAP_SYS_ADMIN and friends.
	for _, n := range []string{"ptrace", "process_vm_readv", "process_vm_writev", "pidfd_getfd", "kcmp", "process_madvise",
		"open_by_handle_at", "mount", "umount2", "unshare", "setns", "bpf", "perf_event_open", "init_module", "finit_module",
		"kexec_load", "keyctl", "add_key", "request_key", "userfaultfd", "chroot", "reboot", "swapon", "pivot_root", "acct"} {
		if allowed[n] {
			t.Errorf("node-sensor.json allows %s", n)
		}
	}
	// What a Go binary reading /proc needs (the e2e test runs the sensor
	// under the profile).
	for _, n := range []string{"openat", "openat2", "read", "readlinkat", "getdents64", "newfstatat", "statx", "futex",
		"epoll_pwait", "rt_sigaction", "mmap", "capget", "prctl", "pidfd_open", "clone"} {
		if !allowed[n] {
			t.Errorf("node-sensor.json does not allow %s", n)
		}
	}
	// clone only without namespace flags; clone3 fails with ENOSYS so the
	// runtime falls back to clone.
	for _, r := range p.Syscalls {
		if len(r.Names) != 1 {
			continue
		}
		switch r.Names[0] {
		case "clone":
			if len(r.Args) != 1 || r.Args[0].Op != "SCMP_CMP_MASKED_EQ" || r.Args[0].Value != 0x7E020000 {
				t.Errorf("clone rule %+v", r.Args)
			}
		case "clone3":
			if r.Action != "SCMP_ACT_ERRNO" || r.ErrnoRet == nil || *r.ErrnoRet != 38 {
				t.Errorf("clone3 rule %s %v", r.Action, r.ErrnoRet)
			}
		}
	}
}

// credentialPattern is the check from the integration notes: no literal in
// a provider credential format may be committed (push protection).
// The Anthropic prefix is split so this file does not match itself.
var credentialPattern = regexp.MustCompile(`AKIA[0-9A-Z]{16}|aws_secret_access_key *[=:] *[A-Za-z0-9/+]{40}|` +
	"sk-ant-" + "api03-" + `|ghp_[A-Za-z0-9]{36}|-----BEGIN [A-Z ]*PRIVATE KEY`)

func TestNoCredentialLiterals(t *testing.T) {
	var files []string
	for _, dir := range []string{"packaging", "deploy/kubernetes"} {
		err := filepath.WalkDir(filepath.Join(root(t), dir), func(p string, d os.DirEntry, err error) error {
			if err == nil && d.Type().IsRegular() {
				files = append(files, p)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, f := range []string{"Dockerfile", ".dockerignore", ".goreleaser.yaml", "Makefile", ".github/workflows/ci.yml", "test/e2e/container_test.go"} {
		files = append(files, filepath.Join(root(t), f))
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Errorf("%v", err)
			continue
		}
		if m := credentialPattern.Find(b); m != nil {
			t.Errorf("%s contains a credential-format literal", f)
		}
	}
}
