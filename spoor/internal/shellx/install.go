package shellx

import "strings"

// Package-manager grammar. For each manager: which subcommands install,
// which fetch and run, which options take a value (so a value is not read as
// a package name), and which options name a registry or index.

type pkgDef struct {
	manager string
	install []string // subcommands that install packages
	exec    []string // subcommands that fetch and run a package
	remove  []string // subcommands that uninstall
	bare    bool     // the command itself is fetch-and-run (npx, uvx, bunx)
	global  bool     // installs are machine- or user-wide by nature
	spec    *optSpec
	// noSub: the manager installs when given no subcommand at all (yarn).
	noSub bool
}

var npmSpec = &optSpec{short: "wCp", long: longSet("--registry", "--prefix", "--workspace", "--tag", "--cache", "--userconfig",
	"--loglevel", "--otp", "--scope", "--omit", "--include", "--install-strategy", "--package", "--call", "--cwd", "--filter", "--dir", "--store-dir")}

var pipSpec = &optSpec{short: "ricetfCp", long: longSet("--index-url", "--extra-index-url", "--requirement", "--constraint", "--editable",
	"--target", "--find-links", "--trusted-host", "--prefix", "--root", "--python", "--platform", "--python-version",
	"--implementation", "--abi", "--cert", "--client-cert", "--proxy", "--cache-dir", "--src", "--upgrade-strategy",
	"--config-settings", "--global-option", "--no-binary", "--only-binary", "--progress-bar", "--report", "--index",
	"--default-index", "--with", "--from", "--with-requirements", "--group", "--extra", "--index-strategy", "--keyring-provider", "--resolution")}

var pkgDefs = map[string]*pkgDef{
	"npm":  {manager: "npm", install: []string{"install", "i", "add", "ci", "install-test", "it", "update", "up", "upgrade"}, exec: []string{"exec", "x"}, remove: []string{"uninstall", "remove", "rm", "un", "r"}, spec: npmSpec},
	"pnpm": {manager: "pnpm", install: []string{"install", "i", "add", "update", "up"}, exec: []string{"dlx"}, remove: []string{"remove", "rm", "uninstall", "un"}, spec: npmSpec},
	"yarn": {manager: "yarn", install: []string{"install", "add", "up", "upgrade"}, exec: []string{"dlx"}, remove: []string{"remove"}, spec: npmSpec, noSub: true},
	"bun":  {manager: "bun", install: []string{"install", "i", "add", "update"}, exec: []string{"x"}, remove: []string{"remove", "rm"}, spec: npmSpec},
	"npx":  {manager: "npx", bare: true, spec: npmSpec},
	"bunx": {manager: "bunx", bare: true, spec: npmSpec},
	"pnpx": {manager: "pnpm", bare: true, spec: npmSpec},

	"pip": {manager: "pip", install: []string{"install", "download"}, remove: []string{"uninstall"}, spec: pipSpec}, "pip3": {manager: "pip", install: []string{"install", "download"}, remove: []string{"uninstall"}, spec: pipSpec},
	"uvx":  {manager: "uvx", bare: true, spec: pipSpec},
	"pipx": {manager: "pipx", install: []string{"install", "inject", "upgrade"}, exec: []string{"run"}, remove: []string{"uninstall"}, global: true, spec: &optSpec{long: longSet("--index-url", "--pip-args", "--python", "--spec", "--suffix", "--with")}},

	"cargo": {manager: "cargo", install: []string{"install", "add", "binstall"}, remove: []string{"uninstall", "remove", "rm"}, spec: &optSpec{short: "jF", long: longSet("--version", "--git", "--branch", "--tag", "--rev", "--path", "--registry", "--index", "--root", "--features", "--target", "--profile", "--jobs", "--bin", "--example")}},
	"gem":   {manager: "gem", install: []string{"install", "i"}, remove: []string{"uninstall"}, global: true, spec: &optSpec{short: "vsiNnpP", long: longSet("--version", "--source", "--install-dir", "--bindir", "--http-proxy", "--platform", "--trust-policy")}},
	"brew":  {manager: "brew", install: []string{"install", "reinstall", "upgrade"}, remove: []string{"uninstall", "remove", "rm"}, global: true, spec: &optSpec{long: longSet("--appdir", "--cc", "--env")}},

	"apt": aptDef, "apt-get": aptDef, "aptitude": aptDef,
	"dnf": dnfDef, "yum": dnfDef, "microdnf": dnfDef,
	"apk":     {manager: "apk", install: []string{"add"}, remove: []string{"del"}, global: true, spec: &optSpec{short: "Xpt", long: longSet("--repository", "--root", "--virtual", "--repositories-file", "--keys-dir")}},
	"pacman":  {manager: "pacman", global: true},
	"zypper":  {manager: "zypper", install: []string{"install", "in"}, remove: []string{"remove", "rm"}, global: true, spec: &optSpec{short: "rtR", long: longSet("--repo", "--from", "--type", "--root")}},
	"snap":    {manager: "snap", install: []string{"install"}, remove: []string{"remove"}, global: true, spec: &optSpec{long: longSet("--channel", "--revision", "--cohort")}},
	"flatpak": {manager: "flatpak", install: []string{"install"}, remove: []string{"uninstall", "remove"}, global: true, spec: &optSpec{long: longSet("--arch", "--installation")}},

	"winget": {manager: "winget", install: []string{"install", "add", "upgrade", "update", "import"}, remove: []string{"uninstall", "remove", "rm"}, global: true, spec: &optSpec{short: "smvlo", long: longSet("--id", "--name", "--moniker", "--version", "--source", "--scope", "--architecture", "--locale", "--location", "--override", "--custom", "--header", "--log", "--manifest", "--query", "--installer-type")}},
	"choco":  {manager: "choco", install: []string{"install", "upgrade"}, remove: []string{"uninstall"}, global: true, spec: chocoSpec}, "cinst": {manager: "choco", bare: true, global: true, spec: chocoSpec},
	"scoop": {manager: "scoop", install: []string{"install", "update"}, remove: []string{"uninstall"}, global: true, spec: &optSpec{short: "a", long: longSet("--arch")}},

	"conda": condaDef, "mamba": condaDef, "micromamba": condaDef,
	"poetry":   {manager: "poetry", install: []string{"add", "install", "update"}, remove: []string{"remove"}, spec: &optSpec{short: "GEP", long: longSet("--group", "--extras", "--source", "--python", "--platform", "--directory", "--with", "--without", "--only")}},
	"composer": {manager: "composer", install: []string{"require", "install", "update", "global"}, remove: []string{"remove"}, spec: &optSpec{short: "d", long: longSet("--working-dir", "--prefer-install")}},
}

var chocoSpec = &optSpec{short: "svpu", long: longSet("--source", "--version", "--params", "--package-parameters", "--install-arguments", "--user", "--password", "--cert", "--proxy")}

var aptDef = &pkgDef{manager: "apt", install: []string{"install", "reinstall", "build-dep", "upgrade", "full-upgrade", "dist-upgrade"}, remove: []string{"remove", "purge", "autoremove"}, global: true,
	spec: &optSpec{short: "otc", long: longSet("--option", "--target-release", "--default-release", "--config-file")}}

var dnfDef = &pkgDef{manager: "dnf", install: []string{"install", "reinstall", "localinstall", "groupinstall", "upgrade", "update"}, remove: []string{"remove", "erase", "autoremove"}, global: true,
	spec: &optSpec{short: "cRdex", long: longSet("--enablerepo", "--disablerepo", "--repo", "--repofrompath", "--releasever", "--installroot", "--setopt", "--exclude", "--config")}}

var condaDef = &pkgDef{manager: "conda", install: []string{"install", "create", "update"}, remove: []string{"remove", "uninstall"},
	spec: &optSpec{short: "ncpf", long: longSet("--name", "--channel", "--prefix", "--file", "--override-channels", "--solver", "--clone")}}

// registryFlags are options whose value is a package source. They are kept
// with their value in PkgInstall.Flags because an install from an unexpected
// index is the dependency-confusion signal.
var registryFlags = map[string]bool{
	"--index-url": true, "-i": true, "--extra-index-url": true, "--registry": true, "--find-links": true, "-f": true,
	"--trusted-host": true, "--source": true, "-s": true, "--index": true, "--default-index": true, "--git": true,
	"--repository": true, "-X": true, "--channel": true, "-c": true, "--from": true, "--with": true, "--spec": true,
	"--package": true, "-p": true, "--tap": true, "--repofrompath": true, "--enablerepo": true, "--requirement": true,
	"-r": true, "--editable": true, "-e": true, "--constraint": true, "--pip-args": true, "--tag": true, "--branch": true, "--rev": true,
	"--version": true, "--id": true, "--manifest": true,
}

// registryEnv are environment variables that redirect a package manager.
var registryEnv = []string{"PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "UV_INDEX_URL", "UV_EXTRA_INDEX_URL", "UV_DEFAULT_INDEX", "UV_INDEX",
	"NPM_CONFIG_REGISTRY", "npm_config_registry", "YARN_REGISTRY", "YARN_NPM_REGISTRY_SERVER", "GOPROXY", "GOFLAGS", "GONOSUMDB", "GONOSUMCHECK",
	"GOPRIVATE", "GOINSECURE", "GOSUMDB", "CARGO_REGISTRIES_CRATES_IO_INDEX", "BUNDLE_MIRROR__RUBYGEMS__ORG", "HOMEBREW_BOTTLE_DOMAIN", "PIP_TRUSTED_HOST", "PIP_CONFIG_FILE"}

func init() {
	for name := range pkgDefs {
		registerWrap(wrapPkg, name)
	}
	registerWrap(wrapUv, "uv")
	registerWrap(wrapGo, "go")
	registerWrap(wrapCode, "code", "code-insiders", "cursor", "codium", "windsurf")
	register(hPacman, "pacman", "yay", "paru")
}

func inList(s string, list []string) bool {
	for _, l := range list {
		if s == l {
			return true
		}
	}
	return false
}

// pkgBase returns the name a package spec would run as: scope, version,
// extras and URL decoration removed.
func pkgBase(spec string) string {
	s := spec
	if i := strings.Index(s, "://"); i >= 0 {
		s = strings.TrimSuffix(baseName(s), ".git")
		if i := strings.IndexAny(s, "#?@"); i > 0 {
			s = s[:i]
		}
		return s
	}
	if strings.HasPrefix(s, "@") {
		// @scope/name@version
		if i := strings.IndexByte(s, '/'); i >= 0 {
			s = s[i+1:]
		}
	}
	if i := strings.IndexAny(s, "@=<>~![ "); i > 0 {
		s = s[:i]
	}
	return s
}

// addInstall appends a PkgInstall, bounded.
func (a *analyzer) addInstall(p PkgInstall) {
	if len(a.f.Installs) >= maxList {
		a.f.Truncated = true
		return
	}
	a.f.Installs = append(a.f.Installs, p)
}

// collect builds the PkgInstall from parsed options: every flag as written,
// registry-style flags with their value, positionals as packages.
func (a *analyzer) collect(c *simple, manager string, o *opts, exec, global bool) PkgInstall {
	p := PkgInstall{Manager: manager, Exec: exec, Global: global}
	for i := range o.flags {
		f := &o.flags[i]
		switch {
		case f.hasVal && registryFlags[f.name]:
			p.Flags = append(p.Flags, f.name+"="+f.val.s)
			if strings.Contains(f.val.s, "://") {
				a.url(f.val.s)
			} else if f.name == "--trusted-host" {
				a.host(f.val.s)
			}
		default:
			p.Flags = append(p.Flags, f.name)
		}
		switch f.name {
		case "-g", "--global", "--user", "--system", "--break-system-packages", "--location=global":
			p.Global = true
		}
		if f.name == "--location" && f.hasVal && f.val.s == "global" {
			p.Global = true
		}
	}
	for i := range c.env {
		for _, n := range registryEnv {
			if c.env[i].name == n {
				p.Flags = append(p.Flags, "env:"+n+"="+redactUserinfo(c.env[i].val.s))
				if strings.Contains(c.env[i].val.s, "://") {
					a.url(c.env[i].val.s)
				}
			}
		}
	}
	return p
}

func wrapPkg(a *analyzer, c *simple, in flow) (flow, int) {
	d := pkgDefs[c.name]
	if d == nil {
		return noFlow(), wrapNone
	}
	rest := c.rest()
	if d.bare {
		if d.manager == "choco" {
			o := parseOpts(rest, d.spec)
			p := a.collect(c, d.manager, &o, false, true)
			p.Packages = o.posStrs()
			a.addInstall(p)
			return noFlow(), wrapNone
		}
		return a.pkgExec(c, d.manager, rest, d.spec, in)
	}
	sub, after := subcommand(rest, d.spec)
	if c.name == "yarn" && sub == "global" {
		s2, a2 := subcommand(after, d.spec)
		if s2 == "add" {
			o := parseOpts(a2, d.spec)
			p := a.collect(c, d.manager, &o, false, true)
			p.Packages = o.posStrs()
			a.addInstall(p)
		}
		return noFlow(), wrapNone
	}
	if c.name == "composer" && sub == "global" {
		s2, a2 := subcommand(after, d.spec)
		if s2 == "require" {
			o := parseOpts(a2, d.spec)
			p := a.collect(c, d.manager, &o, false, true)
			p.Packages = o.posStrs()
			a.addInstall(p)
		}
		return noFlow(), wrapNone
	}
	switch {
	case inList(sub, d.exec):
		return a.pkgExec(c, d.manager, after, d.spec, in)
	case inList(sub, d.install):
		o := parseOpts(after, d.spec)
		p := a.collect(c, d.manager, &o, false, d.global)
		p.Packages = o.posStrs()
		if id, ok := o.get("--id"); ok {
			p.Packages = append(p.Packages, id.s) // winget install --id Vendor.App
		}
		a.addInstall(p)
		for _, pk := range o.pos {
			if strings.Contains(pk.s, "://") {
				a.url(pk.s)
			}
		}
	case inList(sub, d.remove):
		o := parseOpts(after, d.spec)
		for _, pk := range o.pos {
			a.uninstalled(pk.s)
		}
	case sub == "" && d.noSub:
		o := parseOpts(rest, d.spec)
		a.addInstall(a.collect(c, d.manager, &o, false, false))
	case sub == "run" && (d.manager == "poetry" || d.manager == "conda"):
		// poetry run CMD / conda run CMD execute CMD in the environment.
		return wrapRunner(a, c, in)
	case sub == "run" || sub == "run-script" || sub == "test" || sub == "start":
		// npm run <script>: the script body lives in package.json, unseen.
	case c.name == "npm" && sub == "token":
		a.cred("token_print")
	case c.name == "npm" && sub == "config":
		s2, a2 := subcommand(after, nil)
		if (s2 == "get" || s2 == "list" || s2 == "ls") && (containsArgFold(a2, "_authtoken") || containsArgFold(a2, "_auth") || s2 != "get" && containsArgFold(a2, "--json")) {
			a.cred("token_print")
		}
		if s2 == "set" && containsArgFold(a2, "registry") {
			for _, r := range a2 {
				a.scanURLs(r.s)
			}
		}
	case c.name == "npm" && sub == "whoami":
		a.recon("cloud_identity")
	case c.name == "npm" && sub == "publish", c.name == "pnpm" && sub == "publish", c.name == "yarn" && sub == "publish", c.name == "cargo" && sub == "publish":
		// Publishing sends the working tree to a registry.
	case c.name == "cargo" && sub == "run", c.name == "bun" && sub == "run":
	}
	return noFlow(), wrapNone
}

// pkgExec handles fetch-and-run: the package is installed into a cache and
// its binary run with the remaining arguments.
func (a *analyzer) pkgExec(c *simple, manager string, rest []arg, sp *optSpec, in flow) (flow, int) {
	cp := optSpec{}
	if sp != nil {
		cp = *sp
	}
	cp.posStop = true
	o := parseOpts(rest, &cp)
	p := a.collect(c, manager, &o, true, false)
	var run []arg
	// npx -p pkg cmd / uvx --from pkg cmd / pipx run --spec pkg cmd: the
	// package comes from the option and the first positional is the binary.
	explicit := o.all("-p", "--package", "--from", "--spec")
	for _, e := range explicit {
		p.Packages = append(p.Packages, e.s)
	}
	if call, ok := o.get("-c", "--call"); ok && manager != "uvx" {
		// npx -c 'cmd': a shell string run with the packages on PATH.
		a.addInstall(p)
		return a.sub(call.s, Posix, OriginWrapper, c.depth+1, in), wrapReparsed
	}
	if len(o.pos) == 0 {
		if len(p.Packages) > 0 {
			a.addInstall(p)
		}
		return noFlow(), wrapNone
	}
	if len(explicit) == 0 {
		p.Packages = append(p.Packages, o.pos[0].s)
		if strings.Contains(o.pos[0].s, "://") {
			a.url(o.pos[0].s)
		}
		name := pkgBase(o.pos[0].s)
		if name == "" {
			name = o.pos[0].s
		}
		run = append([]arg{{s: name, dyn: o.pos[0].dyn, t: o.pos[0].t}}, o.pos[1:]...)
	} else {
		run = o.pos
	}
	a.addInstall(p)
	res := a.runInner(c, run, in, true, false)
	// Path keeps the package spec as written.
	if res.rep >= 0 && res.rep < len(a.f.Commands) && len(explicit) == 0 {
		a.f.Commands[res.rep].Path = o.pos[0].s
	}
	return res, wrapDelegated
}

// wrapUv handles uv's subcommand tree: uv pip install, uv add, uv tool
// install|run, uv run --with.
func wrapUv(a *analyzer, c *simple, in flow) (flow, int) {
	sub, after := subcommand(c.rest(), pipSpec)
	switch sub {
	case "pip":
		s2, a2 := subcommand(after, pipSpec)
		if s2 == "install" || s2 == "sync" || s2 == "download" {
			o := parseOpts(a2, pipSpec)
			p := a.collect(c, "uv", &o, false, false)
			p.Packages = o.posStrs()
			a.addInstall(p)
		}
		if s2 == "uninstall" {
			for _, pk := range positionalsOf(a2) {
				a.uninstalled(pk.s)
			}
		}
	case "add", "sync", "lock":
		if sub != "add" {
			return noFlow(), wrapNone
		}
		o := parseOpts(after, pipSpec)
		p := a.collect(c, "uv", &o, false, false)
		p.Packages = o.posStrs()
		a.addInstall(p)
	case "tool":
		s2, a2 := subcommand(after, pipSpec)
		switch s2 {
		case "install", "upgrade":
			o := parseOpts(a2, pipSpec)
			p := a.collect(c, "uv", &o, false, true)
			p.Packages = o.posStrs()
			a.addInstall(p)
		case "run":
			return a.pkgExec(c, "uv", a2, pipSpec, in)
		}
	case "x":
		return a.pkgExec(c, "uv", after, pipSpec, in)
	case "run":
		cp := *pipSpec
		cp.posStop = true
		o := parseOpts(after, &cp)
		if with := o.all("--with", "--with-requirements"); len(with) > 0 {
			p := a.collect(c, "uv", &o, true, false)
			for _, w := range with {
				p.Packages = append(p.Packages, w.s)
			}
			a.addInstall(p)
		}
		if len(o.pos) > 0 {
			return a.runInner(c, o.pos, in, true, false), wrapDelegated
		}
	}
	return noFlow(), wrapNone
}

// wrapGo handles go install / go get / go run pkg@version.
func wrapGo(a *analyzer, c *simple, in flow) (flow, int) {
	sub, after := subcommand(c.rest(), &optSpec{oneDash: true, long: longSet("-C")})
	sp := &optSpec{oneDash: true, long: longSet("-o", "-p", "-tags", "-ldflags", "-gcflags", "-mod", "-modfile", "-overlay", "-pkgdir", "-exec", "-asmflags", "-buildmode", "-compiler", "-installsuffix", "-toolexec", "-coverpkg", "-covermode")}
	switch sub {
	case "install", "get":
		o := parseOpts(after, sp)
		p := a.collect(c, "go", &o, false, sub == "install")
		for _, pk := range o.pos {
			if pk.s != "./..." && pk.s != "." && !strings.HasPrefix(pk.s, "./") {
				p.Packages = append(p.Packages, pk.s)
			}
		}
		a.addInstall(p)
	case "run":
		cp := *sp
		cp.posStop = true
		o := parseOpts(after, &cp)
		if len(o.pos) > 0 && strings.Contains(o.pos[0].s, "@") && strings.Contains(o.pos[0].s, ".") {
			// go run example.com/cmd@version fetches and runs it.
			p := a.collect(c, "go", &o, true, false)
			p.Packages = []string{o.pos[0].s}
			a.addInstall(p)
		}
		if v, ok := o.get("-exec"); ok {
			a.sub(v.s, Posix, OriginWrapper, c.depth+1, noFlow())
		}
	case "build", "test", "vet":
		o := parseOpts(after, sp)
		for _, v := range o.all("-exec", "-toolexec") {
			a.sub(v.s, Posix, OriginWrapper, c.depth+1, noFlow())
		}
	}
	return noFlow(), wrapNone
}

// wrapCode handles editor CLIs installing extensions.
func wrapCode(a *analyzer, c *simple, in flow) (flow, int) {
	rest := c.rest()
	var p PkgInstall
	for i := 0; i < len(rest); i++ {
		s := rest[i].s
		if s == "--install-extension" && i+1 < len(rest) {
			p.Manager = "vscode"
			p.Global = true
			p.Packages = append(p.Packages, rest[i+1].s)
			if strings.Contains(rest[i+1].s, "://") {
				a.url(rest[i+1].s)
			}
			i++
			continue
		}
		if strings.HasPrefix(s, "--") && p.Manager != "" {
			p.Flags = append(p.Flags, s)
		}
	}
	if p.Manager != "" {
		a.addInstall(p)
	}
	return noFlow(), wrapNone
}

// hPacman handles pacman's operation letters: -S installs, -R removes.
func hPacman(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	if len(rest) == 0 {
		return
	}
	op := rest[0].s
	if len(op) < 2 || op[0] != '-' {
		return
	}
	var pkgs []string
	var flags []string
	for _, r := range rest {
		if strings.HasPrefix(r.s, "-") {
			flags = append(flags, r.s)
			continue
		}
		pkgs = append(pkgs, r.s)
	}
	switch {
	case strings.HasPrefix(op, "-S") && !strings.ContainsAny(op[2:], "sih"), strings.HasPrefix(op, "-U"), op == "--sync", op == "--upgrade":
		a.addInstall(PkgInstall{Manager: "pacman", Packages: pkgs, Global: true, Flags: flags})
		for _, p := range pkgs {
			if strings.Contains(p, "://") {
				a.url(p)
			}
		}
	case strings.HasPrefix(op, "-R"), op == "--remove":
		for _, p := range pkgs {
			a.uninstalled(p)
		}
	}
}
