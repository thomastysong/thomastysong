package packaging

import (
	"bytes"
	"encoding/json"
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

	"github.com/thomastysong/spoor/internal/config"
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

func read(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(root(t), filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
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
		if c.Dst == "/usr/bin/spoor" {
			if c.Mode != 0o755 {
				t.Errorf("binary mode %o", c.Mode)
			}
			continue
		}
		rest = append(rest, c)
	}
	if g["bindir"] != "/usr/bin" {
		t.Errorf("goreleaser bindir %v, the unit runs /usr/bin/spoor", g["bindir"])
	}
	if a, b := jsonOf(rest), jsonOf(gc); a != b {
		t.Errorf("package contents differ:\n nfpm.yaml:       %s\n .goreleaser.yaml: %s", a, b)
	}
	for _, c := range gc {
		if _, err := os.Stat(filepath.Join(root(t), c.Src)); err != nil {
			t.Errorf("content %s: %v", c.Src, err)
		}
	}
	// deploy/fleet/software names the packages spoor_<version>_linux_<arch>.<fmt>.
	if g["file_name_template"] != "{{ .ProjectName }}_{{ .Version }}_{{ .Os }}_{{ .Arch }}" {
		t.Errorf("file_name_template %v", g["file_name_template"])
	}
	for _, f := range []string{"deploy/fleet/software/spoor-deb.package.yml", "deploy/fleet/software/spoor-rpm.package.yml"} {
		if !regexp.MustCompile(`/spoor_[0-9][0-9.]*_linux_(amd64|arm64)\.(deb|rpm)\b`).MatchString(read(t, f)) {
			t.Errorf("%s does not name a package the release produces", f)
		}
	}
	// install-spoor.sh downloads raw binaries spoor_<os>_<arch>.
	var bin map[string]any
	for _, a := range gr["archives"].([]any) {
		if strs(get(a, "formats"))[0] == "binary" {
			bin = a.(map[string]any)
		}
	}
	if bin == nil || bin["name_template"] != "{{ .ProjectName }}_{{ .Os }}_{{ .Arch }}" {
		t.Errorf("binary archive: %v", bin)
	}
	if !strings.Contains(read(t, "deploy/fleet/scripts/install-spoor.sh"), "/spoor_linux_amd64") {
		t.Error("install-spoor.sh no longer downloads spoor_<os>_<arch>; update the binary archive name")
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
	"deploy/kubernetes/in-image/spoor-entrypoint.sh",
	"deploy/kubernetes/in-image/devcontainer-feature/install.sh",
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
	unit := read(t, "packaging/systemd/spoor.service")
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
	if !strings.Contains(unit, "\nGroup=spoor\n") || !strings.Contains(pre, "groupadd --system spoor") || !strings.Contains(pre, "addgroup --system spoor") {
		t.Error("the unit's Group= and the group preinstall creates differ")
	}
	// systemd sets StateDirectoryMode at every start; the package creates the
	// directory the same way so hooks can reach their spool before that.
	mode := regexp.MustCompile(`(?m)^StateDirectoryMode=(0[0-7]{3})$`).FindStringSubmatch(unit)
	if mode == nil || !strings.Contains(unit, "\nStateDirectory=spoor\n") || assign(t, post, "DATA") != "/var/lib/spoor" ||
		!strings.Contains(post, `chmod `+mode[1]+` "$DATA"`) || !strings.Contains(post, `chown root:spoor "$DATA"`) {
		t.Errorf("data directory: unit StateDirectory/StateDirectoryMode %v and postinstall disagree", mode)
	}
	// The extension paths are register-extension.sh's.
	reg := read(t, "deploy/fleet/scripts/register-extension.sh")
	for _, s := range []string{post, read(t, "packaging/linux/preremove.sh")} {
		if !strings.Contains(s, "EXT_DIR=/usr/lib/spoor") || !strings.Contains(s, "LOAD=/etc/osquery/extensions.load") {
			t.Error("extension paths differ from the Linux packages' scripts")
		}
	}
	if !strings.Contains(reg, "EXTDIR=$ROOT/usr/lib/spoor LOAD=$ROOT/etc/osquery/extensions.load") {
		t.Error("register-extension.sh moved the extension; update packaging/linux scripts")
	}

	// macOS: the plist and the postinstall.
	plist := read(t, "packaging/launchd/com.github.thomastysong.spoor.plist")
	mac := read(t, "packaging/macos/postinstall")
	if !strings.Contains(plist, "<string>/usr/local/bin/spoor</string>") || assign(t, mac, "BIN") != "$ROOT/usr/local/bin/spoor" {
		t.Error("macOS binary path differs between plist and postinstall")
	}
	if !strings.Contains(plist, "<string>/Library/Application Support/spoor/spoor.yaml</string>") ||
		assign(t, mac, "CONF_DIR") != "$ROOT/Library/Application Support/spoor" {
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
	wxs := read(t, "packaging/windows/spoor.wxs")
	if !strings.Contains(wxs, `Arguments="run --config &quot;[DATAFOLDER]spoor.yaml&quot;"`) || !strings.Contains(wxs, `Name="spoor.exe"`) {
		t.Error("spoor.wxs service command line differs from install-service.ps1")
	}
}

// hookAwk returns the awk program a post-install script uses to pick the
// agents whose managed hooks it rewrites.
func hookAwk(t *testing.T, script string) string {
	t.Helper()
	m := regexp.MustCompile(`(?s)awk -F'"' '(.*?)'\) \|\| hooked=""`).FindStringSubmatch(script)
	if m == nil {
		t.Fatal("hook selection awk program not found")
	}
	return m[1]
}

// TestHookSelection: only agents that already have spoor's managed entries
// get them rewritten; the Linux and macOS scripts select alike.
func TestHookSelection(t *testing.T) {
	if _, err := exec.LookPath("awk"); err != nil {
		t.Skip("no awk")
	}
	linux := hookAwk(t, read(t, "packaging/linux/postinstall.sh"))
	if mac := hookAwk(t, read(t, "packaging/macos/postinstall")); mac != linux {
		t.Error("macOS and Linux postinstall select hooked agents differently")
	}
	// The shape `spoor hooks status --scope managed --json` prints (JSON
	// array, two-space indent, one key per line).
	type row struct {
		Agent  string `json:"agent"`
		Scope  string `json:"scope"`
		Path   string `json:"path"`
		Status string `json:"status"`
		Detail string `json:"detail,omitempty"`
	}
	rows := []row{
		{"claude-code", "managed", "/etc/claude-code/managed-settings.d/50-spoor.json", "managed", `checked: "quoted" detail`},
		{"codex", "managed", "/etc/codex/requirements.toml", "missing", "no hook file"},
		{"copilot-cli", "managed", "/etc/github-copilot/policy.d/spoor.json", "foreign_only", ""},
		{"gemini-cli", "managed", "/etc/gemini-cli/settings.json", "modified", "AfterAgent differs"},
		{"cursor", "managed", "/etc/cursor/hooks.json", "insecure_permissions", ""},
		{"claude-code", "user", "/root/.claude/settings.json", "shadowed", ""},
		{"kiro-cli", "managed", "/etc/kiro/x.json", "unsupported", ""},
	}
	b, _ := json.MarshalIndent(rows, "", "  ")
	cmd := exec.Command("awk", "-F", `"`, linux)
	cmd.Stdin = bytes.NewReader(b)
	out, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if got, want := strings.TrimSpace(string(out)), "claude-code,gemini-cli,cursor"; got != want {
		t.Errorf("selected %q, want %q", got, want)
	}
	cmd = exec.Command("awk", "-F", `"`, linux)
	cmd.Stdin = strings.NewReader("[]\n")
	if out, _ := cmd.Output(); strings.TrimSpace(string(out)) != "" {
		t.Errorf("empty status selected %q", out)
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
		`ENTRYPOINT ["/usr/bin/spoor"]`} {
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
// story (redteam/containers-k8s.md) and checks the shipped configuration
// with the configuration loader the daemon uses.
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
	if strings.Join(strs(c["args"]), " ") != "run --config /etc/spoor/spoor.yaml --log-format json" {
		t.Errorf("args %v", c["args"])
	}
	mounts := map[string]bool{}
	for _, m := range c["volumeMounts"].([]any) {
		mounts[get(m, "mountPath").(string)] = true
	}
	if !mounts["/etc/spoor"] || !mounts["/var/lib/spoor"] {
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

	// The ConfigMap's spoor.yaml loads with the daemon's own loader (unknown
	// keys are errors there).
	cm := yamlDocs(t, "deploy/kubernetes/configmap.yaml")[0]
	body, _ := get(cm, "data").(map[string]any)["spoor.yaml"].(string)
	f := filepath.Join(t.TempDir(), "spoor.yaml")
	if err := os.WriteFile(f, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(f, "/var/lib/spoor")
	if err != nil {
		t.Fatalf("ConfigMap spoor.yaml: %v", err)
	}
	if cfg.DataDir != "/var/lib/spoor" || !cfg.Output.Stdout || cfg.Privacy.Profile != "minimal" {
		t.Errorf("ConfigMap config: data_dir %q stdout %v profile %q", cfg.DataDir, cfg.Output.Stdout, cfg.Privacy.Profile)
	}
	if config.On(cfg.Sources.Transcripts.Enabled, true) || config.On(cfg.Sources.Scan.Enabled, true) || !config.On(cfg.Sources.Processes.Enabled, true) {
		t.Error("node sensor collectors: want processes on, transcripts and scan off (they would read the sensor's own file system)")
	}
	// The in-image configuration the examples write.
	for _, rel := range []string{"deploy/kubernetes/in-image/Dockerfile.example", "deploy/kubernetes/in-image/devcontainer-feature/install.sh"} {
		if !strings.Contains(read(t, rel), `printf 'data_dir: /var/lib/spoor\noutput:\n  stdout: true\n'`) {
			t.Errorf("%s: in-image configuration changed; check it with config.Load", rel)
		}
	}
	f2 := filepath.Join(t.TempDir(), "in-image.yaml")
	if err := os.WriteFile(f2, []byte("data_dir: /var/lib/spoor\noutput:\n  stdout: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := config.Load(f2, "/var/lib/spoor"); err != nil {
		t.Errorf("in-image configuration: %v", err)
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
