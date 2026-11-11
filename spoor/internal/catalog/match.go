package catalog

import (
	"strings"
)

// Evidence classes reported by MatchProcessDetail.
const (
	EvidenceProcessName = "process_name" // the process or executable basename is the product's
	EvidenceScriptName  = "script_name"  // an interpreter is running a script named like the product's binary
	EvidencePath        = "path"         // the executable lives under one of the product's install paths
	EvidencePackagePath = "package_path" // the executable or script lives inside one of the product's packages
	EvidenceArgs        = "args"         // the command line matches a ProcessArgs pattern or launches the product's package
)

// Bounds on attacker-controlled process data. A command line is whatever the
// agent (or the code it runs) chose to exec, so it can be megabytes long.
const (
	maxCmdline = 16 << 10
	maxArgs    = 256
)

// ProcessMatch is the result of identifying a process.
type ProcessMatch struct {
	Product Product
	// Evidence lists the classes that matched.
	Evidence []string
	// Classes is the number of independent evidence classes (name, path,
	// args). Two or more is what Asset.Confidence "high" asks for.
	Classes int
}

// MatchProcess identifies a process from its name, executable path and
// arguments. Any of the three may be empty.
//
// A match needs the process (or interpreter script) name to be one of the
// product's binaries or process names, or the command line to show the
// product being launched (a ProcessArgs pattern, a script inside the
// product's package, or a package runner such as npx naming the package).
// A name on the ambiguous list (goose, amp, q, agent, gemini ...) is not
// enough alone: it needs a second class of evidence from the path or the
// arguments. A process named goose in /usr/games does not match.
//
// When several products qualify, the one with the most evidence classes
// wins; ties go to the innermost package directory, then to an exact-case
// name match, then to agents over apps, then to catalog order.
func (c *Catalog) MatchProcess(name, exe string, args []string) (Product, bool) {
	m, ok := c.MatchProcessDetail(name, exe, args)
	return m.Product, ok
}

// MatchProcessDetail is MatchProcess with the evidence that decided it.
func (c *Catalog) MatchProcessDetail(name, exe string, args []string) (m ProcessMatch, ok bool) {
	// Process data is hostile and this runs inside the process monitor loop;
	// a bug here must cost one unidentified process, not the sensor.
	defer func() {
		if r := recover(); r != nil {
			m, ok = ProcessMatch{}, false
		}
	}()
	s := c.snap.Load()
	in := newProcInput(name, exe, args)

	cands := map[int]*candidate{}
	get := func(i int) *candidate {
		cd := cands[i]
		if cd == nil {
			cd = &candidate{idx: i, pkgPos: -1}
			cands[i] = cd
		}
		return cd
	}

	// 1. Name evidence from the executable basename and the process name.
	for _, n := range in.names() {
		for _, i := range s.byExe[n.key] {
			cd := get(i)
			cd.name = true
			if !s.isAmbiguous(n.key) {
				cd.nameStrong = true
			}
			if n.raw != "" && listsExact(&s.products[i], n.raw) {
				cd.exactCase = true
			}
		}
	}
	// Linux truncates comm to 15 bytes; without an executable path that is
	// all we have, so accept it as a prefix of a longer catalogued name.
	if in.exeKey == "" && len(in.nameKey) == 15 {
		for _, i := range s.byExe15[in.nameKey] {
			cd := get(i)
			cd.name, cd.nameStrong = true, true
		}
	}

	eco, isInterp := interpreterEco(in.hostKey(), s.interpreters)
	var script scriptRef
	if isInterp {
		script = in.scriptArg()
	}

	// 2. An interpreter running a script named like a product's binary
	// ("node /usr/local/bin/gemini", "python -m aider"). The interpreter has
	// to be the one the product's package would use, which is itself
	// corroboration: a Go binary called goose is never "node .../goose".
	// File extensions are not stripped: package shims are extensionless, and
	// "node gemini.js" in somebody's project is not Gemini CLI.
	if script.value != "" {
		key := script.key()
		for _, i := range s.byExe[key] {
			cd := get(i)
			cd.script = true
			if _, same := s.matchers[i].pkgByEco[eco]; same {
				cd.args = true
			} else if !s.isAmbiguous(key) {
				cd.nameStrong = true
			}
		}
	}

	// 3. Package runners: "npx -y @openai/codex", "uvx aider-chat",
	// "docker run ghcr.io/openhands/agent-canvas".
	isLauncher := false
	for _, spec := range in.launcherSpecs(script, &isLauncher) {
		if spec.eco == "oci" {
			ref := strings.ToLower(spec.name)
			for i := range s.matchers {
				for _, want := range s.matchers[i].ociRefs {
					if ref == want || strings.HasPrefix(ref, want+":") || strings.HasPrefix(ref, want+"@") {
						get(i).args = true
					}
				}
			}
			continue
		}
		for _, i := range s.byPackage[packageKeyParts(spec.eco, spec.name)] {
			get(i).args = true
		}
	}

	// 4. Package directories. The executable path is always checked; the
	// script path only for interpreters, so that "vim .../claude-code/cli.js"
	// is an editor and not an agent.
	exeLower := strings.ToLower(in.exePath)
	scriptLower := ""
	if !script.module {
		scriptLower = strings.ToLower(slashed(script.value))
	}
	for i := range s.matchers {
		for _, frag := range s.matchers[i].pkgPaths {
			if exeLower != "" {
				if pos := strings.LastIndex(exeLower, frag); pos >= 0 {
					cd := get(i)
					cd.pkgExe = true
					cd.pkgPos = max(cd.pkgPos, pos)
				}
			}
			if scriptLower != "" {
				if pos := strings.LastIndex(scriptLower, frag); pos >= 0 {
					cd := get(i)
					cd.pkgScript = true
					cd.pkgPos = max(cd.pkgPos, pos)
				}
			}
		}
	}

	// 5. ProcessArgs patterns. They are written for interpreter-launched
	// agents, so they count when the host process is an interpreter or a
	// package runner, or when the product already matched by name.
	if in.cmdline != "" {
		for i := range s.matchers {
			mt := &s.matchers[i]
			if len(mt.args) == 0 {
				continue
			}
			if !isInterp && !isLauncher {
				if cd := cands[i]; cd == nil || !cd.hasName() {
					continue
				}
			}
			for _, re := range mt.args {
				if re.MatchString(in.cmdline) {
					get(i).argsRe = true
					break
				}
			}
		}
	}

	// 6. Install paths, for products that are already candidates.
	if in.exePath != "" {
		for i, cd := range cands {
			for _, re := range s.matchers[i].paths {
				if re.MatchString(in.exePath) {
					cd.path = true
					break
				}
			}
		}
	}

	best := (*candidate)(nil)
	for _, cd := range cands {
		if !cd.qualifies() {
			continue
		}
		if best == nil || cd.better(best, s) {
			best = cd
		}
	}
	if best == nil {
		return ProcessMatch{}, false
	}
	return ProcessMatch{
		Product:  s.products[best.idx].clone(),
		Evidence: best.evidence(),
		Classes:  best.classes(),
	}, true
}

// candidate accumulates evidence for one product.
type candidate struct {
	idx        int
	name       bool // process or executable basename matched
	nameStrong bool // ... and that name is not ambiguous
	exactCase  bool
	script     bool // interpreter script basename matched
	path       bool // install path
	pkgExe     bool // executable inside the product's package directory
	pkgScript  bool // interpreter script inside the product's package directory
	pkgPos     int  // deepest offset of a package directory in the path
	args       bool // runner package spec, or ecosystem-corroborated script name
	argsRe     bool // ProcessArgs pattern
}

func (c *candidate) hasName() bool { return c.name || c.script }
func (c *candidate) hasPath() bool { return c.path || c.pkgExe }
func (c *candidate) hasArgs() bool { return c.args || c.argsRe || c.pkgScript }

func (c *candidate) classes() int {
	n := 0
	for _, b := range []bool{c.hasName(), c.hasPath(), c.hasArgs()} {
		if b {
			n++
		}
	}
	return n
}

// qualifies applies the rule from MatchProcess.
func (c *candidate) qualifies() bool {
	if c.hasArgs() {
		return true
	}
	if !c.hasName() {
		return false // a path alone never identifies a process
	}
	return c.nameStrong || c.hasPath()
}

func (c *candidate) better(o *candidate, s *snapshot) bool {
	if a, b := c.classes(), o.classes(); a != b {
		return a > b
	}
	// A package vendored inside another package's node_modules is the
	// program that is actually running.
	if c.pkgPos != o.pkgPos {
		return c.pkgPos > o.pkgPos
	}
	if c.exactCase != o.exactCase {
		return c.exactCase
	}
	if a, b := kindRank[s.products[c.idx].Kind], kindRank[s.products[o.idx].Kind]; a != b {
		return a < b
	}
	return c.idx < o.idx
}

func (c *candidate) evidence() []string {
	var out []string
	if c.name {
		out = append(out, EvidenceProcessName)
	}
	if c.script {
		out = append(out, EvidenceScriptName)
	}
	if c.path {
		out = append(out, EvidencePath)
	}
	if c.pkgExe || c.pkgScript {
		out = append(out, EvidencePackagePath)
	}
	if c.args || c.argsRe {
		out = append(out, EvidenceArgs)
	}
	return out
}

// listsExact reports whether the product lists the name with exactly this
// spelling, which separates "Claude" (the desktop app) from "claude" (the CLI).
func listsExact(p *Product, raw string) bool {
	for _, list := range [][]string{p.Binaries, p.ProcessNames} {
		for _, n := range list {
			if n == raw {
				return true
			}
		}
	}
	return false
}

// procInput is the bounded, normalized view of one process.
type procInput struct {
	nameRaw, nameKey string
	exeRaw, exeKey   string
	exePath          string // slash-separated, original case
	args             []string
	cmdline          string
}

type nameCand struct{ key, raw string }

func newProcInput(name, exe string, args []string) *procInput {
	in := &procInput{}
	if len(exe) > maxCmdline {
		exe = ""
	}
	if len(name) > maxStringLen {
		name = name[:maxStringLen]
	}
	in.nameRaw = baseName(name)
	in.nameKey = exeKey(name)
	if exe != "" {
		in.exePath = slashed(exe)
		in.exeRaw = baseName(exe)
		in.exeKey = exeKey(exe)
	}
	// A process that rewrote its title (npm does: "npm exec <pkg>") shows up
	// as one argument with spaces in it.
	if len(args) == 1 && strings.ContainsRune(args[0], ' ') && len(args[0]) <= maxCmdline {
		args = strings.Fields(args[0])
	}
	if len(args) > maxArgs {
		args = args[:maxArgs]
	}
	in.args = args
	var b strings.Builder
	for i, a := range args {
		if i > 0 {
			b.WriteByte(' ')
		}
		if room := maxCmdline - b.Len(); len(a) > room {
			// Keep the head: the interpreter and script come first, and the
			// tail is where an attacker would pad.
			b.WriteString(a[:room])
			break
		}
		b.WriteString(a)
	}
	in.cmdline = b.String()
	return in
}

func baseName(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		p = p[i+1:]
	}
	p = strings.TrimSpace(p)
	if len(p) > 4 && strings.EqualFold(p[len(p)-4:], ".exe") {
		p = p[:len(p)-4]
	}
	return p
}

func (in *procInput) names() []nameCand {
	var out []nameCand
	if in.exeKey != "" {
		out = append(out, nameCand{in.exeKey, in.exeRaw})
	}
	if in.nameKey != "" && in.nameKey != in.exeKey {
		out = append(out, nameCand{in.nameKey, in.nameRaw})
	}
	return out
}

// hostKey is the name that decides whether the process is an interpreter:
// the executable basename when known (comm can be rewritten by the process),
// otherwise the process name.
func (in *procInput) hostKey() string {
	if in.exeKey != "" {
		return in.exeKey
	}
	return in.nameKey
}

// scriptRef is what an interpreter was asked to run.
type scriptRef struct {
	value  string
	index  int  // position in args
	module bool // given with -m: a module name, not a path
}

// key is the lookup key for a script: the basename of a path, or the
// top-level package of a module ("mlx_lm.server" is "mlx_lm").
func (r scriptRef) key() string {
	k := exeKey(r.value)
	if r.module {
		if i := strings.IndexByte(k, '.'); i > 0 {
			return k[:i]
		}
	}
	return k
}

// scriptArg returns the first argument after argv[0] that is not an option,
// or the module after "-m".
func (in *procInput) scriptArg() scriptRef {
	for i := 1; i < len(in.args); i++ {
		a := in.args[i]
		switch {
		case a == "":
			continue
		case a == "-m" || a == "--":
			if i+1 < len(in.args) {
				return scriptRef{value: in.args[i+1], index: i + 1, module: a == "-m"}
			}
			return scriptRef{}
		case strings.HasPrefix(a, "-"):
			continue
		}
		return scriptRef{value: a, index: i}
	}
	return scriptRef{}
}

type launchSpec struct{ eco, name string }

// launcherSpecs extracts the package a runner was asked to execute. The
// runner can be the process itself (uvx, docker) or a script run by an
// interpreter ("node /usr/bin/npx ..."); bunx is bun under another name, so
// both the executable and the process name are tried.
func (in *procInput) launcherSpecs(script scriptRef, isLauncher *bool) []launchSpec {
	type host struct {
		name string
		rest []string
	}
	var hosts []host
	if len(in.args) > 1 {
		// argv[0] is included for processes that rewrote their title: the
		// executable is node but argv reads "npm exec <pkg>".
		hosts = append(hosts, host{in.exeKey, in.args[1:]}, host{in.nameKey, in.args[1:]},
			host{exeKey(in.args[0]), in.args[1:]})
	}
	if script.value != "" && !script.module && script.index+1 <= len(in.args) {
		hosts = append(hosts, host{exeKey(script.value), in.args[script.index+1:]})
	}
	var out []launchSpec
	seen := map[string]bool{}
	for _, h := range hosts {
		forms, ok := launchers[h.name]
		if !ok || seen[h.name] {
			continue
		}
		seen[h.name] = true
		*isLauncher = true
		for _, f := range forms {
			rest, ok := skipSubcommand(h.rest, f.sub)
			if !ok {
				continue
			}
			for _, a := range firstOperands(rest, f.eco) {
				out = append(out, launchSpec{f.eco, specName(a, f.eco)})
			}
		}
	}
	return out
}

// skipSubcommand consumes the subcommand words of a runner form. Global
// options may precede each word ("docker --context x run" is not handled,
// "docker -D run" is): value-taking global options are rare enough that
// guessing which ones take a value would cost more than it finds.
func skipSubcommand(rest []string, sub []string) ([]string, bool) {
	for _, word := range sub {
		j := 0
		for j < len(rest) && j < 8 && strings.HasPrefix(rest[j], "-") {
			j++
		}
		if j >= len(rest) || rest[j] != word {
			return nil, false
		}
		rest = rest[j+1:]
	}
	return rest, true
}

// valueFlags are runner options that consume the next argument. Without the
// table, "docker run -e K=V image" would read K=V as the image.
var valueFlags = map[string]bool{
	"-p": true, "--package": true, "-c": true, "--call": true, // npx
	"--from": true, "--with": true, "--python": true, "--spec": true, // uvx, pipx
	"--index-url": true, "--extra-index-url": true,
	"-e": true, "--env": true, "-v": true, "--volume": true, "--name": true, // docker
	"-w": true, "--workdir": true, "-u": true, "--user": true, "--network": true,
	"--mount": true, "--entrypoint": true, "-l": true, "--label": true,
	"--env-file": true, "--platform": true, "--add-host": true, "-h": true,
	"--hostname": true, "--cpus": true, "-m": true, "--memory": true,
	"--publish": true, "--restart": true, "--runtime": true, "--gpus": true,
	"--cap-add": true, "--cap-drop": true, "--security-opt": true, "--pull": true,
}

// firstOperands returns the package spec operands: the values of -p/--package
// and --from (which name the package explicitly) and the first positional.
func firstOperands(args []string, eco string) []string {
	var out []string
	for i := 0; i < len(args) && i < 64; i++ {
		a := args[i]
		if a == "--" {
			if i+1 < len(args) {
				out = append(out, args[i+1])
			}
			break
		}
		if strings.HasPrefix(a, "-") {
			flag, val, hasVal := strings.Cut(a, "=")
			explicit := eco != "oci" && (flag == "-p" || flag == "--package" || flag == "--from" || flag == "--spec")
			if hasVal {
				if explicit {
					out = append(out, val)
				}
				continue
			}
			if valueFlags[flag] {
				if explicit && i+1 < len(args) {
					out = append(out, args[i+1])
				}
				i++
			}
			continue
		}
		out = append(out, a)
		break
	}
	return out
}

// specName strips the version from a package spec: "@scope/pkg@1.2.3",
// "pkg==1.0", "pkg[extra]>=2".
func specName(spec, eco string) string {
	switch eco {
	case "npm":
		if i := strings.LastIndexByte(spec, '@'); i > 0 {
			return spec[:i]
		}
	case "pypi":
		if i := strings.IndexAny(spec, "=<>!~[@ ;"); i > 0 {
			return spec[:i]
		}
	}
	return spec
}
