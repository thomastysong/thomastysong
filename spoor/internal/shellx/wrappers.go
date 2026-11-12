package shellx

import "strings"

// wrapDef is the table form of a wrapper: options, then optionally some
// positionals, then the wrapped command.
type wrapDef struct {
	spec    *optSpec
	skip    int  // positionals consumed before the command (timeout DURATION)
	bg      bool // the wrapper detaches the command
	reparse bool // the remaining words are one shell string (watch)
	noStdin bool // the wrapped command does not read the wrapper's stdin
	pre     func(a *analyzer, c *simple, o *opts) bool
}

func tableWrap(d wrapDef) wrapper {
	return func(a *analyzer, c *simple, in flow) (flow, int) {
		sp := d.spec
		if sp == nil {
			sp = &optSpec{}
		}
		cp := *sp
		cp.posStop = true
		o := parseOpts(c.rest(), &cp)
		if d.pre != nil && !d.pre(a, c, &o) {
			return noFlow(), wrapNone
		}
		if d.bg {
			a.f.Background = true
		}
		if len(o.pos) <= d.skip {
			return noFlow(), wrapNone
		}
		rest := o.pos[d.skip:]
		if d.reparse {
			return a.sub(joinArgs(rest), Posix, OriginWrapper, c.depth+1, noFlow()), wrapReparsed
		}
		return a.runInner(c, rest, in, !d.noStdin, false), wrapDelegated
	}
}

func init() {
	plain := tableWrap(wrapDef{})
	registerWrap(plain, "builtin", "winpty", "busybox", "toybox", "eatmydata", "chronic", "unbuffer", "rlwrap", "dumb-init", "tini")
	registerWrap(tableWrap(wrapDef{bg: true}), "nohup", "setsid", "daemonize")
	registerWrap(tableWrap(wrapDef{spec: &optSpec{short: "n", long: longSet("--adjustment")}}), "nice")
	registerWrap(tableWrap(wrapDef{spec: &optSpec{short: "cnpPu", long: longSet("--class", "--classdata", "--pid", "--pgid", "--uid")}}), "ionice")
	registerWrap(tableWrap(wrapDef{spec: &optSpec{short: "ioe", long: longSet("--input", "--output", "--error")}}), "stdbuf")
	registerWrap(tableWrap(wrapDef{spec: &optSpec{short: "fo", long: longSet("--format", "--output")}}), "time", "gtime")
	registerWrap(tableWrap(wrapDef{spec: &optSpec{short: "ks", long: longSet("--kill-after", "--signal")}, skip: 1}), "timeout", "gtimeout")
	registerWrap(tableWrap(wrapDef{spec: &optSpec{long: longSet("--userspec", "--groups")}, skip: 1}), "chroot")
	registerWrap(tableWrap(wrapDef{spec: &optSpec{short: "SG", long: longSet("--setuid", "--setgid", "--propagation", "--setgroups", "--map-user", "--map-group", "--root", "--wd")}}), "unshare")
	registerWrap(tableWrap(wrapDef{spec: &optSpec{short: "tSGW", long: longSet("--target", "--setuid", "--setgid", "--wdns")}, pre: func(a *analyzer, c *simple, o *opts) bool {
		// Entering the namespaces of PID 1 from a container is a host escape.
		if t, ok := o.get("-t", "--target"); ok && t.s == "1" {
			a.priv("docker_privileged")
		}
		return true
	}}), "nsenter")
	registerWrap(tableWrap(wrapDef{spec: &optSpec{short: "eopsuaPSXEbI", long: longSet("--output", "--trace", "--attach")}}), "strace", "ltrace")
	registerWrap(tableWrap(wrapDef{spec: &optSpec{short: "tw"}}), "caffeinate")
	registerWrap(tableWrap(wrapDef{spec: &optSpec{oneDash: true, long: longSet("-e", "-d")}}), "arch")
	registerWrap(tableWrap(wrapDef{spec: &optSpec{short: "nsfep", long: longSet("--server-num", "--server-args", "--error-file", "--auth-file", "--xauth-protocol")}}), "xvfb-run")
	registerWrap(tableWrap(wrapDef{spec: &optSpec{short: "f"}}), "proxychains", "proxychains4")
	registerWrap(tableWrap(wrapDef{pre: func(a *analyzer, c *simple, o *opts) bool {
		a.nettool("tor")
		return true
	}}), "torsocks", "torify")
	registerWrap(tableWrap(wrapDef{spec: &optSpec{short: "a"}}), "exec")
	registerWrap(tableWrap(wrapDef{pre: func(a *analyzer, c *simple, o *opts) bool {
		// "command -v x" looks x up; it does not run it.
		return !o.has("-v", "-V")
	}}), "command")
	registerWrap(tableWrap(wrapDef{spec: &optSpec{short: "pfdP"}}), "sshpass")
	registerWrap(tableWrap(wrapDef{spec: &optSpec{short: "n", long: longSet("--interval")}, reparse: true, noStdin: true}), "watch")
	registerWrap(tableWrap(wrapDef{spec: &optSpec{short: "ugCh", long: longSet("--user", "--group", "--chdir", "--host")}, pre: func(a *analyzer, c *simple, o *opts) bool {
		a.sudo()
		return true
	}}), "pkexec", "gsudo", "run0")
	registerWrap(tableWrap(wrapDef{spec: &optSpec{short: "Cu"}, pre: func(a *analyzer, c *simple, o *opts) bool {
		a.sudo()
		return true
	}}), "doas")

	registerWrap(wrapSudo, "sudo", "sudoedit")
	registerWrap(wrapEnv, "env")
	registerWrap(wrapXargs, "xargs", "gxargs")
	registerWrap(wrapFind, "find", "gfind", "fd", "fdfind")
	registerWrap(wrapSu, "su", "runuser")
	registerWrap(wrapSSH, "ssh", "autossh", "mosh")
	registerWrap(wrapFlock, "flock")
	registerWrap(wrapScript, "script")
	registerWrap(wrapParallel, "parallel")
	registerWrap(wrapDocker, "docker", "podman", "nerdctl")
	registerWrap(wrapKubectl, "kubectl", "oc")
	// poetry and conda are package managers first; install.go routes their
	// "run" subcommand here.
	registerWrap(wrapRunner, "pipenv", "bundle", "hatch", "pdm",
		"mise", "op", "doppler", "aws-vault", "direnv", "dotenv", "infisical", "chamber", "nix-shell", "nix")
	registerWrap(wrapStart, "start")
	registerWrap(wrapCall, "call")
	registerWrap(wrapPsexec, "psexec", "psexec64", "paexec")
	registerWrap(wrapWSL, "wsl")
	registerWrap(wrapRunas, "runas")
	registerWrap(wrapForfiles, "forfiles")
}

var sudoSpec = &optSpec{
	short: "ugUpCDrtThR",
	long: longSet("--user", "--group", "--other-user", "--prompt", "--close-from", "--chdir", "--role",
		"--type", "--command-timeout", "--host", "--chroot"),
	posStop: true,
}

func wrapSudo(a *analyzer, c *simple, in flow) (flow, int) {
	a.sudo()
	o := parseOpts(c.rest(), sudoSpec)
	if o.has("-l", "--list", "-v", "--validate", "-k", "-K", "-V", "--version") && len(o.pos) == 0 {
		return noFlow(), wrapNone
	}
	pos := o.pos
	// sudo accepts VAR=value before the command.
	for len(pos) > 0 {
		name, _, ok := splitAssign(pos[0].s)
		if !ok {
			break
		}
		a.envAssign(name)
		pos = pos[1:]
	}
	if c.name == "sudoedit" || o.has("-e", "--edit") {
		for _, p := range pos {
			a.write(p.s)
		}
		return noFlow(), wrapNone
	}
	if len(pos) == 0 {
		return noFlow(), wrapNone
	}
	return a.runInner(c, pos, in, true, false), wrapDelegated
}

// splitAssign parses NAME=value where NAME is a valid variable name.
func splitAssign(s string) (name, val string, ok bool) {
	i := strings.IndexByte(s, '=')
	if i <= 0 {
		return "", "", false
	}
	for j := 0; j < i; j++ {
		if !isIdentByte(s[j]) || (j == 0 && s[j] >= '0' && s[j] <= '9') {
			return "", "", false
		}
	}
	return s[:i], s[i+1:], true
}

var envSpec = &optSpec{short: "uCS", long: longSet("--unset", "--chdir", "--split-string"), posStop: true}

func wrapEnv(a *analyzer, c *simple, in flow) (flow, int) {
	o := parseOpts(c.rest(), envSpec)
	pos := o.pos
	for len(pos) > 0 {
		name, val, ok := splitAssign(pos[0].s)
		if !ok {
			break
		}
		a.envAssign(name)
		a.assignFacts(name, arg{s: val, dyn: pos[0].dyn})
		pos = pos[1:]
	}
	if s, ok := o.get("-S", "--split-string"); ok {
		// env -S 'cmd args' splits the string itself.
		var args []arg
		for _, f := range strings.Fields(s.s) {
			args = append(args, arg{s: f, dyn: s.dyn, t: s.t})
		}
		args = append(args, pos...)
		pos = args
	}
	if len(pos) == 0 {
		return noFlow(), wrapNone // plain "env" prints the environment
	}
	return a.runInner(c, pos, in, true, false), wrapDelegated
}

var xargsSpec = &optSpec{
	short:   "InPsLdEa",
	long:    longSet("--max-args", "--max-procs", "--max-chars", "--max-lines", "--delimiter", "--arg-file", "--eof", "--process-slot-var"),
	posStop: true,
}

func wrapXargs(a *analyzer, c *simple, in flow) (flow, int) {
	o := parseOpts(c.rest(), xargsSpec)
	if f, ok := o.get("-a", "--arg-file"); ok {
		a.read(f.s)
	}
	if len(o.pos) == 0 {
		return noFlow(), wrapNone
	}
	// The wrapped command gets its remaining arguments from xargs' input, so
	// its argument list is incomplete: mark it dynamic.
	return a.runInner(c, o.pos, in, false, true), wrapDelegated
}

// wrapFind runs every -exec/-execdir/-ok command and derives find's own
// facts (delete, secret hunting).
func wrapFind(a *analyzer, c *simple, in flow) (flow, int) {
	args := c.rest()
	if c.name == "fd" || c.name == "fdfind" {
		return wrapFd(a, c, in)
	}
	var roots []arg
	i := 0
	for ; i < len(args); i++ {
		s := args[i].s
		if s == "-H" || s == "-L" || s == "-P" {
			continue
		}
		if strings.HasPrefix(s, "-") || s == "(" || s == "!" || s == ")" {
			break
		}
		roots = append(roots, args[i])
	}
	expr := args[i:]
	filtered, del := false, false
	ran := false
	for j := 0; j < len(expr); j++ {
		s := expr[j].s
		switch s {
		case "-exec", "-execdir", "-ok", "-okdir":
			k := j + 1
			for k < len(expr) && expr[k].s != ";" && expr[k].s != "+" {
				k++
			}
			inner := expr[j+1 : k]
			if len(inner) > 0 {
				if n := commandName(inner[0]); n == "rm" || n == "shred" || n == "unlink" {
					del = true
				}
				a.runInner(c, append([]arg(nil), inner...), noFlow(), false, true)
				ran = true
			}
			j = k
		case "-delete":
			del = true
		case "-name", "-iname", "-path", "-ipath", "-wholename", "-regex", "-iregex", "-lname":
			filtered = true
			if j+1 < len(expr) {
				if secretPattern(expr[j+1].s) {
					a.recon("find_secrets")
				}
				j++
			}
		case "-type", "-mtime", "-mmin", "-atime", "-amin", "-ctime", "-cmin", "-size", "-newer", "-user",
			"-group", "-perm", "-maxdepth", "-mindepth", "-empty", "-uid", "-gid", "-inum", "-links":
			if s != "-maxdepth" && s != "-mindepth" {
				filtered = true
			}
			if s == "-perm" && j+1 < len(expr) && (strings.Contains(expr[j+1].s, "4000") || strings.Contains(expr[j+1].s, "u=s") || strings.Contains(expr[j+1].s, "2000") || strings.Contains(expr[j+1].s, "6000")) {
				// Hunting for setuid binaries is privilege-escalation recon.
				a.recon("find_secrets")
			}
			if s != "-empty" {
				j++
			}
		}
	}
	if del {
		if len(roots) == 0 {
			roots = []arg{{s: "."}}
		}
		for _, r := range roots {
			n := normPath(r.s)
			switch {
			case isRootLike(n), isHomeRoot(n), n == "..", strings.HasPrefix(n, "../"), unsetVarRoot(r.s) && !r.guard:
				a.destructive("find_delete")
			case !filtered && (n == "." || n == "*" || n == ""):
				// "find . -delete" removes everything under the cwd.
				a.destructive("find_delete")
			}
			a.del(r.s)
		}
	}
	if ran {
		return flow{rep: c.idx}, wrapReparsed
	}
	return noFlow(), wrapNone
}

func wrapFd(a *analyzer, c *simple, in flow) (flow, int) {
	args := c.rest()
	for j := 0; j < len(args); j++ {
		s := args[j].s
		if s == "-x" || s == "--exec" || s == "-X" || s == "--exec-batch" {
			k := j + 1
			for k < len(args) && args[k].s != ";" {
				k++
			}
			if k > j+1 {
				a.runInner(c, append([]arg(nil), args[j+1:k]...), noFlow(), false, true)
				return flow{rep: c.idx}, wrapReparsed
			}
		}
		if j == 0 && secretPattern(s) {
			a.recon("find_secrets")
		}
	}
	return noFlow(), wrapNone
}

// secretPattern reports a file-name or content pattern that hunts for
// credentials.
func secretPattern(p string) bool {
	l := strings.ToLower(p)
	for _, k := range []string{"id_rsa", "id_ed25519", "id_dsa", "id_ecdsa", ".pem", ".key", ".env", ".kdbx", ".pfx", ".p12",
		"secret", "passw", "credential", "token", "api_key", "apikey", "api-key", "private key", "private_key",
		"wallet", ".aws", "akia", "aws_access", "authorization:", "bearer ", ".npmrc", ".netrc", "kubeconfig", "htpasswd", "shadow"} {
		if strings.Contains(l, k) {
			return true
		}
	}
	return false
}

func wrapSu(a *analyzer, c *simple, in flow) (flow, int) {
	a.priv("su")
	sp := &optSpec{short: "cgGsuwlU", long: longSet("--command", "--group", "--supp-group", "--shell", "--user", "--whitelist-environment", "--session-command")}
	if c.name == "su" {
		// "su -l" takes no value; only runuser's -l does.
		sp = &optSpec{short: "cgGsw", long: sp.long}
	}
	o := parseOpts(c.rest(), sp)
	if code, ok := o.get("-c", "--command", "--session-command"); ok {
		return a.sub(code.s, Posix, OriginWrapper, c.depth+1, in), wrapReparsed
	}
	if c.name == "runuser" {
		// runuser -u user -- cmd args
		if _, ok := o.get("-u", "--user"); ok && len(o.pos) > 0 {
			return a.runInner(c, o.pos, in, true, false), wrapDelegated
		}
	}
	return noFlow(), wrapNone
}

var sshSpec = &optSpec{
	short:   "bcDEeFIiJLlmOopQRSWw",
	posStop: true,
}

func wrapSSH(a *analyzer, c *simple, in flow) (flow, int) {
	o := parseOpts(c.rest(), sshSpec)
	if o.has("-R") {
		a.nettool("ssh_reverse_tunnel")
	}
	for _, v := range o.all("-o") {
		l := strings.ToLower(v.s)
		if strings.HasPrefix(l, "remoteforward") {
			a.nettool("ssh_reverse_tunnel")
		}
		if strings.HasPrefix(l, "proxycommand") || strings.HasPrefix(l, "localcommand") {
			// ssh -o ProxyCommand=... runs a local command.
			if i := strings.IndexAny(v.s, "= "); i > 0 {
				a.sub(v.s[i+1:], Posix, OriginWrapper, c.depth+1, noFlow())
			}
		}
	}
	for _, v := range o.all("-i") {
		a.read(v.s)
	}
	for _, v := range o.all("-F") {
		a.read(v.s)
	}
	for _, v := range o.all("-J") {
		for _, h := range strings.Split(v.s, ",") {
			a.host(sshTarget(h))
		}
	}
	if o.has("-f") {
		a.f.Background = true
	}
	if len(o.pos) == 0 {
		return noFlow(), wrapNone
	}
	a.host(sshTarget(o.pos[0].s))
	pos := o.pos[1:]
	if c.name == "mosh" && len(pos) > 0 && pos[0].s == "--" {
		pos = pos[1:]
	}
	if len(pos) == 0 {
		// No remote command: a heredoc or pipe is the remote shell's input.
		if static, t, has := c.input(a, in); has && static != nil {
			a.inline("sh", *static)
			origin := OriginInlinePrefix + c.name
			if t&tCoded != 0 {
				origin = OriginDecoded
			}
			a.sub(*static, Posix, origin, c.depth+1, noFlow())
			return flow{rep: c.idx}, wrapReparsed
		}
		return noFlow(), wrapNone
	}
	// ssh joins its arguments with spaces and the remote shell parses them.
	return a.sub(joinArgs(pos), Posix, OriginWrapper, c.depth+1, in), wrapReparsed
}

func wrapFlock(a *analyzer, c *simple, in flow) (flow, int) {
	o := parseOpts(c.rest(), &optSpec{short: "wEc", long: longSet("--timeout", "--conflict-exit-code", "--command"), posStop: true})
	if code, ok := o.get("-c", "--command"); ok {
		return a.sub(code.s, Posix, OriginWrapper, c.depth+1, in), wrapReparsed
	}
	if len(o.pos) < 2 {
		return noFlow(), wrapNone
	}
	rest := o.pos[1:]
	if rest[0].s == "-c" && len(rest) > 1 {
		return a.sub(rest[1].s, Posix, OriginWrapper, c.depth+1, in), wrapReparsed
	}
	return a.runInner(c, rest, in, true, false), wrapDelegated
}

func wrapScript(a *analyzer, c *simple, in flow) (flow, int) {
	o := parseOpts(c.rest(), &optSpec{short: "ctTIOBEm", long: longSet("--command", "--timing", "--log-in", "--log-out", "--log-io", "--echo", "--output-limit")})
	if code, ok := o.get("-c", "--command"); ok {
		return a.sub(code.s, Posix, OriginWrapper, c.depth+1, in), wrapReparsed
	}
	return noFlow(), wrapNone
}

func wrapParallel(a *analyzer, c *simple, in flow) (flow, int) {
	o := parseOpts(c.rest(), &optSpec{short: "jSIaNLnPlC", long: longSet("--jobs", "--sshlogin", "--arg-file", "--max-args", "--delimiter", "--colsep", "--joblog", "--results", "--tmpdir", "--timeout", "--retries"), posStop: true})
	var cmd []arg
	for _, p := range o.pos {
		if strings.HasPrefix(p.s, ":::") {
			break
		}
		cmd = append(cmd, p)
	}
	if len(cmd) == 0 {
		return noFlow(), wrapNone
	}
	// parallel hands the command line to a shell.
	return a.sub(joinArgs(cmd), Posix, OriginWrapper, c.depth+1, noFlow()), wrapReparsed
}

// wrapRunner handles "tool run|exec [opts] [--] cmd args" environment
// runners. They matter because "poetry run python -c ..." is still python.
func wrapRunner(a *analyzer, c *simple, in flow) (flow, int) {
	args := c.rest()
	if len(args) == 0 {
		return noFlow(), wrapNone
	}
	skip := 0
	switch c.name {
	case "nix-shell":
		o := parseOpts(args, &optSpec{short: "pIiA", long: longSet("--run", "--command", "--packages", "--attr", "--arg", "--argstr", "--expr")})
		if code, ok := o.get("--run", "--command"); ok {
			return a.sub(code.s, Posix, OriginWrapper, c.depth+1, in), wrapReparsed
		}
		return noFlow(), wrapNone
	case "nix":
		if s := strings.ToLower(args[0].s); s != "develop" && s != "shell" && s != "run" {
			return noFlow(), wrapNone
		}
		for i := 1; i < len(args); i++ {
			if (args[i].s == "-c" || args[i].s == "--command" || args[i].s == "--") && i+1 < len(args) {
				return a.runInner(c, args[i+1:], in, true, false), wrapDelegated
			}
		}
		return noFlow(), wrapNone
	case "dotenv":
		if args[0].s == "run" {
			args = args[1:]
		}
	case "bundle", "mise", "aws-vault", "chamber", "direnv":
		s := strings.ToLower(args[0].s)
		if s != "exec" && !(c.name == "mise" && s == "x") {
			return noFlow(), wrapNone
		}
		args = args[1:]
		if c.name == "aws-vault" || c.name == "chamber" || c.name == "direnv" {
			skip = 1 // profile / service / directory
		}
	default:
		if strings.ToLower(args[0].s) != "run" {
			return noFlow(), wrapNone
		}
		args = args[1:]
	}
	for i := range args {
		if args[i].s == "--" {
			return a.runInner(c, args[i+1:], in, true, false), wrapDelegated
		}
	}
	// No "--": skip options, then the fixed positionals, then the command.
	i := 0
	for i < len(args) && strings.HasPrefix(args[i].s, "-") {
		s := args[i].s
		if !strings.Contains(s, "=") {
			switch s {
			case "-n", "--name", "-p", "--prefix", "--with", "--python", "-e", "--env", "--cwd", "-C", "--project", "--config", "-c":
				i++
			}
		}
		i++
	}
	i += skip
	if i >= len(args) {
		return noFlow(), wrapNone
	}
	return a.runInner(c, args[i:], in, true, false), wrapDelegated
}

// Windows wrappers.

func wrapStart(a *analyzer, c *simple, in flow) (flow, int) {
	if c.dialect != Cmd {
		// POSIX has no start; in PowerShell it is the Start-Process alias,
		// which has its own handler.
		return noFlow(), wrapNone
	}
	args := c.rest()
	i := 0
	// start ["title"] [/d path] [/b] [/min] ... program args
	if i < len(args) && args[i].quoted {
		i++
	}
	for i < len(args) && strings.HasPrefix(args[i].s, "/") && len(args[i].s) <= 16 {
		l := strings.ToLower(args[i].s)
		if l == "/b" || l == "/min" {
			a.f.Background = true
		}
		if l == "/d" {
			i++
		}
		i++
	}
	if i >= len(args) {
		return noFlow(), wrapNone
	}
	return a.runInner(c, args[i:], in, false, false), wrapDelegated
}

func wrapCall(a *analyzer, c *simple, in flow) (flow, int) {
	if c.dialect == Posix {
		return noFlow(), wrapNone
	}
	args := c.rest()
	if len(args) == 0 || strings.HasPrefix(args[0].s, ":") {
		return noFlow(), wrapNone
	}
	return a.runInner(c, args, in, true, false), wrapDelegated
}

func wrapPsexec(a *analyzer, c *simple, in flow) (flow, int) {
	args := c.rest()
	i := 0
	for i < len(args) {
		s := args[i].s
		l := strings.ToLower(s)
		switch {
		case strings.HasPrefix(s, "\\\\"):
			a.host(strings.TrimLeft(s, "\\"))
			i++
		case l == "-u" || l == "-p" || l == "-w" || l == "-n" || l == "-a":
			i += 2
		case strings.HasPrefix(s, "-") || strings.HasPrefix(s, "/") && len(s) <= 12:
			if l == "-s" || l == "-h" {
				a.sudo()
			}
			if l == "-d" {
				a.f.Background = true
			}
			i++
		default:
			return a.runInner(c, args[i:], in, false, false), wrapDelegated
		}
	}
	return noFlow(), wrapNone
}

func wrapWSL(a *analyzer, c *simple, in flow) (flow, int) {
	args := c.rest()
	for i := 0; i < len(args); i++ {
		l := strings.ToLower(args[i].s)
		switch l {
		case "-d", "--distribution", "-u", "--user", "--cd":
			i++
		case "-e", "--exec", "--":
			if i+1 < len(args) {
				return a.runInner(c, args[i+1:], in, true, false), wrapDelegated
			}
		default:
			if strings.HasPrefix(l, "-") {
				continue
			}
			// "wsl cmd args" runs the line through the default shell.
			return a.sub(joinArgs(args[i:]), Posix, OriginWrapper, c.depth+1, in), wrapReparsed
		}
	}
	return noFlow(), wrapNone
}

func wrapRunas(a *analyzer, c *simple, in flow) (flow, int) {
	a.sudo()
	args := c.rest()
	for i := range args {
		if strings.HasPrefix(args[i].s, "/") {
			continue
		}
		return a.sub(joinArgs(args[i:]), Cmd, OriginWrapper, c.depth+1, noFlow()), wrapReparsed
	}
	return noFlow(), wrapNone
}

func wrapForfiles(a *analyzer, c *simple, in flow) (flow, int) {
	args := c.rest()
	for i := 0; i+1 < len(args); i++ {
		if strings.EqualFold(args[i].s, "/c") {
			return a.sub(args[i+1].s, Cmd, OriginWrapper, c.depth+1, noFlow()), wrapReparsed
		}
	}
	return noFlow(), wrapNone
}
