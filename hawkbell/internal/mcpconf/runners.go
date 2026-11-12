package mcpconf

import (
	"strings"
)

// The tables below list, per launcher, the options that consume the next
// word. They are the whole difference between reading a launch line and
// pattern-matching it: without them "npx -p pkg cmd" names the wrong package
// and "docker run -e K=V --rm image" names the wrong image. Options not
// listed are switches. "--opt=value" never needs the table.

func buildRunnerFlags(t *tables) {
	// npx, npm exec, pnpm dlx, yarn dlx, bunx. --package/-p and --call/-c
	// are handled in code because they carry meaning.
	t.nodePkgValueFlags = set("--node-options", "--registry", "--cache", "--userconfig", "--prefix",
		"--workspace", "-w", "--loglevel", "--node-arg", "-n", "--shell", "--script-shell",
		"--allow-build", "--cwd", "--config")

	t.nodeValueFlags = set("-r", "--require", "--import", "--loader", "--experimental-loader",
		"--env-file", "--env-file-if-exists", "--inspect-port", "-C", "--conditions",
		"--input-type", "--title", "--watch-path", "--project", "-P", "--tsconfig")

	t.bunValueFlags = set("--cwd", "--env-file", "--preload", "-r", "--config", "-c", "--define",
		"-d", "--loader", "-l", "--port", "--tsconfig-override")

	// uv / uvx. --from, --with and friends are handled in code.
	t.uvValueFlags = set("--python", "-p", "--index-url", "-i", "--extra-index-url", "--index",
		"--default-index", "--find-links", "-f", "--constraints", "-c", "--overrides",
		"--build-constraints", "-b", "--env-file", "--cache-dir", "--config-file", "--color",
		"--refresh-package", "--upgrade-package", "-P", "--reinstall-package", "--index-strategy",
		"--keyring-provider", "--allow-insecure-host", "--resolution", "--prerelease",
		"--exclude-newer", "--link-mode", "--config-setting", "-C", "--no-binary-package",
		"--no-build-package", "--python-preference", "--python-platform", "--extra", "--group",
		"--only-group", "--no-group", "--package", "--with-requirements", "--with-editable",
		"--directory", "--project", "--from", "--with", "--script-name")

	t.pipxValueFlags = set("--python", "--index-url", "-i", "--pip-args", "--spec", "--backend")

	t.pipValueFlags = set("--index-url", "-i", "--extra-index-url", "--find-links", "-f", "--target",
		"-t", "--requirement", "-r", "--constraint", "-c", "--prefix", "--root", "--python",
		"--trusted-host", "--cert", "--client-cert", "--proxy", "--platform", "--python-version",
		"--implementation", "--abi", "--only-binary", "--no-binary", "--upgrade-strategy",
		"--editable", "-e", "--src", "--cache-dir", "--config-settings", "-C")

	t.denoValueFlags = set("--config", "-c", "--import-map", "--lock", "--cert", "--location",
		"--seed", "--log-level", "-L", "--ext", "--preload")

	t.goValueFlags = set("-C", "-exec", "-mod", "-modfile", "-tags", "-ldflags", "-gcflags",
		"-asmflags", "-overlay", "-pkgdir", "-p", "-toolexec", "-buildmode", "-compiler",
		"-coverpkg", "-covermode")

	t.dockerGlobalValueFlags = set("--context", "-c", "--host", "-H", "--config", "--log-level", "-l",
		"--tlscacert", "--tlscert", "--tlskey", "--connection", "--url", "--identity", "--root",
		"--runroot", "--storage-driver", "--storage-opt", "--tmpdir", "--cgroup-manager")

	t.dockerRunValueFlags = set("--add-host", "--annotation", "--attach", "--blkio-weight",
		"--blkio-weight-device", "--cap-add", "--cap-drop", "--cgroup-parent", "--cgroupns",
		"--cidfile", "--cpu-period", "--cpu-quota", "--cpu-rt-period", "--cpu-rt-runtime",
		"--cpu-shares", "--cpus", "--cpuset-cpus", "--cpuset-mems", "--detach-keys", "--device",
		"--device-cgroup-rule", "--device-read-bps", "--device-read-iops", "--device-write-bps",
		"--device-write-iops", "--dns", "--dns-option", "--dns-search", "--domainname",
		"--entrypoint", "--env", "--env-file", "--expose", "--gpus", "--group-add", "--health-cmd",
		"--health-interval", "--health-retries", "--health-start-interval", "--health-start-period",
		"--health-timeout", "--hostname", "--io-maxbandwidth", "--io-maxiops", "--ip", "--ip6",
		"--ipc", "--isolation", "--kernel-memory", "--label", "--label-file", "--link",
		"--link-local-ip", "--log-driver", "--log-opt", "--mac-address", "--memory",
		"--memory-reservation", "--memory-swap", "--memory-swappiness", "--mount", "--name",
		"--network", "--net", "--network-alias", "--oom-score-adj", "--pid", "--pids-limit",
		"--platform", "--publish", "--pull", "--restart", "--runtime", "--security-opt",
		"--shm-size", "--stop-signal", "--stop-timeout", "--storage-opt", "--sysctl", "--tmpfs",
		"--ulimit", "--user", "--userns", "--uts", "--volume", "--volume-driver", "--volumes-from",
		"--workdir", "--secret", "--arch", "--os", "--variant", "--authfile", "--pod", "--systemd",
		"--timeout", "--tz", "--umask", "--uidmap", "--gidmap", "--subuidname", "--subgidname")

	// scriptRunnerPackages are npm packages whose first operand is the file
	// to run, so "npx tsx src/index.ts" executes a local script.
	t.scriptRunnerPackages = set("tsx", "ts-node", "esno", "jiti", "vite-node", "nodemon", "babel-node", "zx")
}

// dockerShortValue are the one-letter docker run options that take a
// value, for clusters ("-itv /a:/b") and attached values ("-eK=V").
const dockerShortValue = "acehlmpuvw"

// cutFlag splits "--name=value".
func cutFlag(a string) (name, value string, hasValue bool) {
	return strings.Cut(a, "=")
}

// flagValue returns the value of the flag at args[i] and the index of the
// last word it occupies.
func flagValue(args []string, i int) (string, int) {
	if _, v, ok := cutFlag(args[i]); ok {
		return v, i
	}
	if i+1 < len(args) {
		return args[i+1], i + 1
	}
	return "", i
}

// setSpecs records what a package runner resolves. The first spec is the one
// reported; every spec decides pinning, because an unpinned --with
// dependency floats just like an unpinned main package.
func (l *launch) setSpecs(specs []string, parse func(string) pkgSpec, online bool) {
	for i, raw := range specs {
		sp := parse(raw)
		if i == 0 {
			l.spec, l.has = sp, true
		}
		if sp.local {
			if i == 0 {
				l.script = joinPath(l.dir, strings.TrimPrefix(raw, "file:"))
			}
			continue
		}
		if online {
			l.fetch = true
		}
		if !sp.pinned {
			l.unpinned = true
		}
	}
}

// nodePackage reads npx-style launchers: npx, npm exec, pnpm dlx, yarn dlx
// (all reported as npx) and bunx / bun x (reported as bunx).
func (l *launch) nodePackage(runner string, args []string) {
	l.runner, l.eco = runner, "npm"
	var pkgs []string
	online := true
	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			i++
			break
		}
		if !isFlag(a) {
			break
		}
		name, _, hasEq := cutFlag(a)
		switch {
		case name == "--package" || name == "-p":
			var v string
			v, i = flagValue(args, i)
			if v != "" {
				pkgs = append(pkgs, v)
			}
		case name == "--call" || name == "-c":
			var v string
			v, i = flagValue(args, i)
			l.inline = append(l.inline, v)
		case name == "--no-install" || name == "--offline" || name == "--no":
			online = false
		case tab().nodePkgValueFlags[name] && !hasEq:
			i++
		}
	}
	operand := ""
	if i < len(args) {
		operand = args[i]
		l.rest = args[i+1:]
	}
	specs := pkgs
	if len(specs) == 0 && operand != "" {
		specs = []string{operand}
	}
	if len(specs) == 0 {
		return
	}
	l.setSpecs(specs, parseNpmSpec, online)
	if tab().scriptRunnerPackages[strings.ToLower(l.spec.name)] {
		// With -p the operand is the runner's own bin and the file follows it.
		for _, r := range l.rest {
			if !isFlag(r) {
				l.script = joinPath(l.dir, r)
				break
			}
		}
	}
}

// nodeScript reads "node [options] file" (also bun, tsx, ts-node).
func (l *launch) nodeScript(args []string, valueFlags map[string]bool) {
	l.runner = "node"
	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			i++
			break
		}
		if !isFlag(a) {
			break
		}
		name, _, hasEq := cutFlag(a)
		if name == "-e" || name == "--eval" || name == "-p" || name == "--print" {
			l.rest = args[i:]
			return // inline code, no file
		}
		if valueFlags[name] && !hasEq {
			i++
		}
	}
	if i >= len(args) {
		return
	}
	file, rest := args[i], args[i+1:]
	if strings.EqualFold(baseName(file), "npx-cli.js") {
		// "node .../npx-cli.js -y pkg" is npx spelled out for hosts that
		// cannot spawn the npx.cmd shim.
		l.nodePackage("npx", rest)
		return
	}
	l.script, l.rest = joinPath(l.dir, file), rest
}

// uvTool reads "uvx [options] pkg" and "uv tool run".
func (l *launch) uvTool(args []string) {
	l.runner, l.eco = "uvx", "pypi"
	var from string
	var with []string
	online := true
	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			i++
			break
		}
		if !isFlag(a) {
			break
		}
		name, _, hasEq := cutFlag(a)
		switch {
		case name == "--from":
			from, i = flagValue(args, i)
		case name == "--with":
			var v string
			v, i = flagValue(args, i)
			with = append(with, splitList(v)...)
		case name == "--offline":
			online = false
		case tab().uvValueFlags[name] && !hasEq:
			i++
		}
	}
	operand := ""
	if i < len(args) {
		operand = args[i]
		l.rest = args[i+1:]
	}
	primary := from
	if primary == "" {
		primary = operand
	}
	if primary == "" {
		return
	}
	l.setSpecs(append([]string{primary}, with...), parsePySpec, online)
}

func splitList(v string) []string {
	var out []string
	for _, p := range strings.Split(v, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// uv dispatches "uv [global options] <tool run|run|pip install>".
func (l *launch) uv(args []string, depth int) {
	i := 0
	for ; i < len(args) && isFlag(args[i]); i++ {
		name, _, hasEq := cutFlag(args[i])
		if name == "--directory" || name == "--project" {
			var v string
			v, i = flagValue(args, i)
			l.dir = joinPath(l.dir, v)
		} else if tab().uvValueFlags[name] && !hasEq {
			i++
		}
	}
	switch {
	case i+1 < len(args) && args[i] == "tool" && (args[i+1] == "run" || args[i+1] == "uvx"):
		l.uvTool(args[i+2:])
	case i < len(args) && args[i] == "run":
		l.uvRun(args[i+1:], depth)
	case i+1 < len(args) && args[i] == "pip" && args[i+1] == "install":
		l.pip(args[i+1:])
	default:
		l.binary(l.cmd, args)
	}
}

// uvRun reads "uv run [options] <script|command> [args]". It runs local
// code; --with adds requirements that are resolved at launch.
func (l *launch) uvRun(args []string, depth int) {
	l.runner = "python"
	var with []string
	online, module := true, false
	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			i++
			break
		}
		if !isFlag(a) {
			break
		}
		name, _, hasEq := cutFlag(a)
		switch {
		case name == "--with":
			var v string
			v, i = flagValue(args, i)
			with = append(with, splitList(v)...)
		case name == "--directory" || name == "--project":
			var v string
			v, i = flagValue(args, i)
			l.dir = joinPath(l.dir, v)
		case name == "--module" || name == "-m":
			module = true
		case name == "--offline":
			online = false
		case tab().uvValueFlags[name] && !hasEq:
			i++
		}
	}
	if len(with) > 0 {
		l.eco = "pypi"
		l.setSpecs(with, parsePySpec, online)
	}
	if i >= len(args) {
		return
	}
	operand, rest := args[i], args[i+1:]
	l.rest = rest
	base := cmdBase(operand)
	switch {
	case module:
	case isPython(base):
		sub := launch{dir: l.dir}
		sub.python(rest)
		l.script, l.rest = sub.script, sub.rest
	case base == "mcp" || base == "fastmcp":
		// "mcp run server.py" is the install line the Python SDK writes into
		// client configs; the file may carry an ":object" suffix.
		for _, r := range rest {
			file := r
			if j := strings.LastIndex(r, ".py:"); j >= 0 {
				file = r[:j+3]
			}
			if strings.HasSuffix(strings.ToLower(file), ".py") {
				l.script = joinPath(l.dir, file)
				break
			}
		}
	case isPathLike(operand) || strings.HasSuffix(strings.ToLower(operand), ".py"):
		l.script = joinPath(l.dir, operand)
	case l.dir != "":
		// An entry point of the project in that directory: its code runs.
		l.script = l.dir
	}
}

// pipx reads "pipx run [options] spec".
func (l *launch) pipx(args []string) {
	i := 0
	for i < len(args) && isFlag(args[i]) {
		i++
	}
	if i >= len(args) || args[i] != "run" {
		l.binary(l.cmd, args)
		return
	}
	l.runner, l.eco = "pipx", "pypi"
	spec := ""
	for i++; i < len(args); i++ {
		a := args[i]
		if a == "--" {
			i++
			break
		}
		if !isFlag(a) {
			break
		}
		name, _, hasEq := cutFlag(a)
		if name == "--spec" {
			spec, i = flagValue(args, i)
		} else if tab().pipxValueFlags[name] && !hasEq {
			i++
		}
	}
	if i < len(args) {
		if spec == "" {
			spec = args[i]
		}
		l.rest = args[i+1:]
	}
	if spec != "" {
		l.setSpecs([]string{spec}, parsePySpec, true)
	}
}

// pip reads "pip install specs...", which only occurs inside launch scripts
// ("pip install x && python -m x").
func (l *launch) pip(args []string) {
	if len(args) == 0 || args[0] != "install" {
		l.binary(l.cmd, args)
		return
	}
	l.runner, l.eco = "pip", "pypi"
	var specs []string
	for i := 1; i < len(args); i++ {
		a := args[i]
		if isFlag(a) {
			name, _, hasEq := cutFlag(a)
			if tab().pipValueFlags[name] && !hasEq {
				i++
			}
			continue
		}
		specs = append(specs, a)
	}
	if len(specs) > 0 {
		l.setSpecs(specs, parsePySpec, true)
	}
}

// python reads "python [options] file", "python -m module", "python -c code".
func (l *launch) python(args []string) {
	l.runner = "python"
	i := 0
	for ; i < len(args); i++ {
		a := args[i]
		if a == "-m" {
			if i+1 < len(args) {
				l.rest = args[i+2:]
				if args[i+1] == "pip" {
					l.pip(l.rest)
				}
			}
			return
		}
		if a == "-c" || a == "-" {
			l.rest = args[i:]
			return
		}
		if !isFlag(a) {
			break
		}
		if a == "-W" || a == "-X" || a == "--check-hash-based-pycs" {
			i++
		}
	}
	if i < len(args) {
		l.script, l.rest = joinPath(l.dir, args[i]), args[i+1:]
	}
}

// deno reads "deno run [options] <npm:pkg|jsr:pkg|url|file>".
func (l *launch) deno(args []string) {
	l.runner = "deno"
	if len(args) == 0 {
		return
	}
	i := 0
	if args[0] == "run" || args[0] == "serve" {
		i = 1
	}
	for ; i < len(args); i++ {
		a := args[i]
		if !isFlag(a) {
			break
		}
		name, _, hasEq := cutFlag(a)
		if tab().denoValueFlags[name] && !hasEq {
			i++
		}
	}
	if i >= len(args) {
		return
	}
	spec := args[i]
	l.rest = args[i+1:]
	switch {
	case strings.HasPrefix(spec, "npm:"):
		l.eco = "npm"
		l.setSpecs([]string{spec[4:]}, parseNpmSpec, true)
	case strings.HasPrefix(spec, "jsr:"):
		sp := parseNpmSpec(spec[4:])
		sp.name = "jsr:" + sp.name
		l.spec, l.has, l.fetch, l.unpinned = sp, true, true, !sp.pinned
	case isURLLike(spec):
		// A remote module is whatever the URL serves today.
		l.spec, l.has, l.fetch, l.unpinned = pkgSpec{name: spec, remote: true}, true, true, true
	default:
		l.script = joinPath(l.dir, spec)
	}
}

// goRun reads "go run [build flags] module@version|package".
func (l *launch) goRun(args []string) {
	l.runner = "binary"
	if len(args) == 0 || args[0] != "run" {
		l.rest = args
		return
	}
	i := 1
	for ; i < len(args); i++ {
		a := args[i]
		if !isFlag(a) {
			break
		}
		name, _, hasEq := cutFlag(a)
		if tab().goValueFlags[name] && !hasEq {
			i++
		}
	}
	if i >= len(args) {
		return
	}
	l.rest = args[i+1:]
	sp := parseGoSpec(args[i])
	if sp.local {
		l.script = joinPath(l.dir, args[i])
		return
	}
	l.spec, l.has, l.fetch, l.unpinned = sp, true, true, !sp.pinned
}

// interpreter reads "<ruby|perl|php|java|dotnet ...> [options] file".
func (l *launch) interpreter(args []string) {
	l.runner = "binary"
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "-jar":
			if i+1 < len(args) {
				l.script, l.rest = joinPath(l.dir, args[i+1]), args[i+2:]
			}
			return
		case a == "-e" || a == "-r":
			l.rest = args[i:]
			return // inline code
		case a == "-cp" || a == "-classpath" || a == "-I":
			i++
		case isFlag(a):
		default:
			l.script, l.rest = joinPath(l.dir, a), args[i+1:]
			return
		}
	}
}

// ---- containers ----

// containerRun reads "docker|podman [global options] run [options] image [cmd]".
func (l *launch) containerRun(runner string, args []string) {
	l.runner, l.container = runner, true
	i := 0
	for ; i < len(args) && isFlag(args[i]); i++ {
		name, _, hasEq := cutFlag(args[i])
		if tab().dockerGlobalValueFlags[name] && !hasEq {
			i++
		}
	}
	if i < len(args) && args[i] == "container" {
		i++
	}
	if i >= len(args) {
		return
	}
	sub := args[i]
	i++
	if sub != "run" && sub != "create" {
		// exec, compose, "docker mcp gateway run": no image is named on
		// this line, so there is nothing to pin.
		l.rest = args[i:]
		return
	}
	l.eco = "oci"
	pullAlways := false
	for i < len(args) {
		a := args[i]
		if !isFlag(a) {
			break
		}
		name, val, hasVal, used := dockerFlag(args, i)
		i += used
		switch name {
		case "--privileged":
			if !hasVal || !strings.EqualFold(val, "false") {
				l.privileged = true
			}
		case "--cap-add":
			if dangerousCap(val) {
				l.privileged = true
			}
		case "--pid", "--userns":
			if strings.EqualFold(val, "host") {
				l.privileged = true
			}
		case "--security-opt":
			lv := strings.ToLower(val)
			if strings.Contains(lv, "unconfined") || strings.Contains(lv, "label=disable") || strings.Contains(lv, "label:disable") {
				l.privileged = true
			}
		case "-v", "--volume":
			l.addVolume(val)
		case "--mount":
			l.addMount(val)
		case "-e", "--env":
			if val != "" {
				l.ctrEnv = append(l.ctrEnv, val)
			}
		case "--pull":
			pullAlways = strings.EqualFold(val, "always")
		}
	}
	if i >= len(args) {
		return
	}
	sp := parseImageRef(args[i])
	l.rest = args[i+1:]
	l.spec, l.has = sp, true
	l.unpinned = !sp.pinned
	if !sp.pinned && (pullAlways || sp.version == "" || strings.EqualFold(sp.version, "latest")) {
		l.latest = true
	}
}

// dockerFlag reads the option at args[i]: its canonical name, its value and
// how many words it occupies. Short clusters ("-it", "-itv /a:/b") and
// attached values ("-eK=V", "-v/a:/b") are understood.
func dockerFlag(args []string, i int) (name, val string, hasVal bool, used int) {
	a := args[i]
	if strings.HasPrefix(a, "--") {
		name, val, hasVal = cutFlag(a)
		if hasVal {
			return name, val, true, 1
		}
		if tab().dockerRunValueFlags[name] && i+1 < len(args) {
			return name, args[i+1], true, 2
		}
		return name, "", false, 1
	}
	for j := 1; j < len(a); j++ {
		if strings.IndexByte(dockerShortValue, a[j]) < 0 {
			continue
		}
		name = "-" + string(a[j])
		if rem := a[j+1:]; rem != "" {
			return name, strings.TrimPrefix(rem, "="), true, 1
		}
		if i+1 < len(args) {
			return name, args[i+1], true, 2
		}
		return name, "", false, 1
	}
	return a, "", false, 1
}

func dangerousCap(v string) bool {
	for _, c := range splitList(v) {
		switch strings.TrimPrefix(strings.ToUpper(c), "CAP_") {
		case "ALL", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "SYS_RAWIO", "DAC_READ_SEARCH":
			return true
		}
	}
	return false
}

// addVolume records the host side of "-v src:dst[:opts]". A source without a
// path separator is a named volume, not host filesystem.
func (l *launch) addVolume(v string) {
	src := v
	start := 0
	if isDriveAbs(v) {
		start = 2 // skip the drive colon
	}
	if i := strings.IndexByte(v[start:], ':'); i >= 0 {
		src = v[:start+i]
	}
	l.addHostPath(src)
}

// addMount records the host side of "--mount type=bind,source=...,target=...".
func (l *launch) addMount(v string) {
	typ, src := "", ""
	for _, kv := range strings.Split(v, ",") {
		k, val, _ := strings.Cut(kv, "=")
		switch strings.ToLower(strings.TrimSpace(k)) {
		case "type":
			typ = strings.ToLower(val)
		case "source", "src":
			src = val
		}
	}
	if typ == "bind" || (typ == "" && isPathLike(src)) {
		l.addHostPath(src)
	}
}

var containerSockets = []string{"docker.sock", "podman.sock", "containerd.sock", "crio.sock", "docker_engine"}

func (l *launch) addHostPath(src string) {
	src = strings.Trim(strings.TrimSpace(src), `"'`)
	if src == "" {
		return
	}
	if !isPathLike(src) && !homeRelative(src) && !isDriveAbs(src) && !strings.HasPrefix(src, "$") && !strings.HasPrefix(src, "%") {
		return
	}
	ls := strings.ToLower(src)
	for _, sock := range containerSockets {
		if strings.Contains(ls, sock) {
			l.socket = true
		}
	}
	if len(l.mounts) < 256 {
		l.mounts = append(l.mounts, src)
	}
}
