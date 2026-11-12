package features

import (
	"reflect"
	"strings"

	"github.com/thomastysong/spoor/internal/classify"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/shellx"
	"github.com/thomastysong/spoor/internal/toolmap"
)

// maxProcArgs bounds the argv rendered back into a command line for
// process.exec events.
const maxProcArgs = 4096

// commandText returns the command line a shell-family event runs: the
// target command of any tool that carries one, or the argv of an observed
// child process.
func commandText(e *event.Event) string {
	if e.Target != nil && e.Target.Command != "" {
		return e.Target.Command
	}
	if e.Type == event.TypeProcessExec && e.Process != nil && len(e.Process.Args) > 0 {
		args := e.Process.Args
		if len(args) > maxProcArgs {
			args = args[:maxProcArgs]
		}
		return toolmap.CommandFromArgv(args)
	}
	return ""
}

func (c *computer) dialectHint() shellx.Dialect {
	if c.e.Tool != nil {
		switch strings.ToLower(c.e.Tool.Name) {
		case "powershell", "pwsh":
			return shellx.PowerShell
		}
	}
	return ""
}

// analyze runs shellx behind its own recover: shellx guards itself, and
// this second guard is what keeps a parser bug from crashing the hook.
func (c *computer) analyze(cmd string) (f *shellx.Facts) {
	defer func() {
		if recover() != nil {
			c.f["content.analyzer_error"] = true
			f = nil
		}
	}()
	return shellx.Analyze(cmd, c.dialectHint())
}

// tailRescan is how much of the end of a command line is analysed on its
// own when the analyzer stopped early (shellx caps the number of commands),
// so a payload appended after padding is still seen.
const tailRescan = 8 << 10

// analyzeBounded analyses the head and tail of an oversized command line
// separately (concatenating them would fuse two unrelated fragments into one
// word), and re-analyses the last 8 KiB when an analysis was truncated.
func (c *computer) analyzeBounded(cmd string) *shellx.Facts {
	parts := []string{cmd}
	if len(cmd) > maxScan {
		c.f["content.truncated_scan"] = true
		parts = []string{cutHead(cmd, scanHead), cutTail(cmd, scanTail)}
	}
	var out *shellx.Facts
	for _, p := range parts {
		out = mergeFacts(out, c.analyze(p))
	}
	if out != nil && out.Truncated && len(cmd) > tailRescan {
		out = mergeFacts(out, c.analyze(cutTail(cmd, tailRescan)))
	}
	return out
}

// mergeFacts folds b into a: lists are unioned (strings) or appended,
// booleans ORed except ParseOK, which holds only if both parses did.
// Pipelines index into Commands and are dropped from b.
func mergeFacts(a, b *shellx.Facts) *shellx.Facts {
	if a == nil {
		return b
	}
	if b == nil {
		return a
	}
	av, bv := reflect.ValueOf(a).Elem(), reflect.ValueOf(b).Elem()
	for i := 0; i < av.NumField(); i++ {
		name := av.Type().Field(i).Name
		fa, fb := av.Field(i), bv.Field(i)
		switch fa.Kind() {
		case reflect.Bool:
			if name == "ParseOK" {
				fa.SetBool(fa.Bool() && fb.Bool())
			} else {
				fa.SetBool(fa.Bool() || fb.Bool())
			}
		case reflect.Slice:
			if name == "Pipelines" {
				continue
			}
			if fa.Type().Elem().Kind() == reflect.String {
				seen := make(map[string]bool, fa.Len())
				for j := 0; j < fa.Len(); j++ {
					seen[fa.Index(j).String()] = true
				}
				for j := 0; j < fb.Len(); j++ {
					if v := fb.Index(j); !seen[v.String()] {
						seen[v.String()] = true
						fa.Set(reflect.Append(fa, v))
					}
				}
			} else {
				fa.Set(reflect.AppendSlice(fa, fb))
			}
		}
	}
	return a
}

func (c *computer) shell() {
	cmd := commandText(c.e)
	if cmd == "" {
		return
	}
	fx := c.analyzeBounded(cmd)
	if fx == nil {
		return
	}
	cmd = c.bound(cmd)
	f := c.f
	f["shell.parse_ok"] = fx.ParseOK
	f["shell.dialect"] = string(fx.Dialect)
	f["shell.truncated"] = fx.Truncated
	f["shell.downloads"] = fx.Downloads
	f["shell.pipe_to_interpreter"] = fx.PipeToInterpreter
	f["shell.download_and_execute"] = fx.DownloadAndExecute
	f["shell.eval"] = fx.Eval
	f["shell.sudo"] = fx.Sudo
	f["shell.background"] = fx.Background
	f["shell.heredoc"] = fx.HereDoc
	f["shell.decoded"] = len(fx.Decoded) > 0

	var names, argv []string
	cmds := make([]map[string]any, 0, min(len(fx.Commands), maxCmds))
	dynamic := false
	for _, cm := range fx.Commands {
		dynamic = dynamic || cm.Dynamic
		uniq(&names, cm.Name)
		for _, a := range cm.Args {
			if len(argv) < maxArgv {
				argv = append(argv, cutHead(a, maxArgLen))
			}
		}
		if len(cmds) < maxCmds {
			args := cm.Args
			if len(args) > maxCmdArg {
				args = args[:maxCmdArg]
			}
			cargs := make([]string, len(args))
			for i, a := range args {
				cargs[i] = cutHead(a, maxArgLen)
			}
			cmds = append(cmds, map[string]any{
				"name":    cm.Name,
				"path":    cutHead(cm.Path, maxArgLen),
				"args":    cargs,
				"origin":  cm.Origin,
				"dynamic": cm.Dynamic,
			})
		}
	}
	f["shell.dynamic"] = dynamic
	c.setList("shell.commands", names)
	if len(argv) > 0 {
		f["shell.argv"] = argv
	}
	if len(cmds) > 0 {
		f["shell.cmds"] = cmds
	}

	c.setList("shell.urls", fx.URLs)
	c.setList("shell.hosts", fx.Hosts)
	c.urls = append(c.urls, fx.URLs...)
	c.hosts = append(c.hosts, fx.Hosts...)
	c.setList("shell.host_classes", hostClasses(fx.Hosts))

	c.setList("shell.reads", fx.Reads)
	c.setList("shell.writes", fx.Writes)
	c.setList("shell.deletes", fx.Deletes)
	pc := c.pathCtx()
	c.setList("shell.read_classes", pathClasses(fx.Reads, pc))
	c.setList("shell.write_classes", pathClasses(fx.Writes, pc))
	c.setList("shell.delete_classes", pathClasses(fx.Deletes, pc))

	c.setList("shell.interpreters", fx.Interpreters)
	var langs []string
	for _, ic := range fx.Inline {
		uniq(&langs, ic.Lang)
	}
	c.setList("shell.inline_langs", langs)

	c.setList("shell.obfuscation", fx.Obfuscation)
	c.setList("shell.opaque", fx.Opaque)
	c.setList("shell.executes_paths", fx.ExecutesPaths)
	c.setList("shell.destructive", fx.Destructive)
	c.setList("shell.persistence", fx.Persistence)
	c.setList("shell.defense_evasion", fx.DefenseEvasion)
	c.setList("shell.cred_access", fx.CredAccess)
	c.setList("shell.exfil", fx.Exfil)
	c.setList("shell.net_tools", fx.NetTools)
	c.setList("shell.recon", fx.Recon)
	c.setList("shell.privilege", fx.Privilege)
	c.setList("shell.git_ops", fx.GitOps)
	c.setList("shell.env_assign", fx.EnvAssign)

	c.installs(fx.Installs)

	kinds := secretKinds(cmd)
	f["shell.has_secret"] = len(kinds) > 0
	c.setList("shell.secret_kinds", kinds)
}

func (c *computer) installs(list []shellx.PkgInstall) {
	f := c.f
	var flat, managers, sources []string
	entries := make([]map[string]any, 0, min(len(list), maxList))
	exec := false
	for _, in := range list {
		exec = exec || in.Exec
		uniq(&managers, in.Manager)
		if len(in.Packages) == 0 {
			uniq(&flat, in.Manager+":")
		}
		for _, p := range in.Packages {
			uniq(&flat, in.Manager+":"+cutHead(p, maxArgLen))
			if isPackageURL(p) {
				uniq(&sources, cutHead(p, maxArgLen))
			}
		}
		for _, fl := range in.Flags {
			if v := flagSource(fl); v != "" {
				uniq(&sources, cutHead(v, maxArgLen))
			}
		}
		if len(entries) < maxList {
			entries = append(entries, map[string]any{
				"manager":  in.Manager,
				"packages": capStrings(in.Packages),
				"global":   in.Global,
				"exec":     in.Exec,
				"flags":    capStrings(in.Flags),
			})
		}
	}
	f["shell.install_exec"] = exec
	c.setList("shell.installs", flat)
	c.setList("shell.install_managers", managers)
	c.setList("shell.install_sources", sources)
	if len(entries) > 0 {
		f["shell.install_entries"] = entries
	}
	for _, s := range sources {
		if h := classify.URLHost(s); h != "" && strings.Contains(s, "://") {
			c.urls = append(c.urls, s)
		}
	}
}

func capStrings(in []string) []string {
	n := len(in)
	if n > maxList {
		n = maxList
	}
	out := make([]string, n)
	for i := 0; i < n; i++ {
		out[i] = cutHead(in[i], maxArgLen)
	}
	return out
}

// isPackageURL reports a package spec that names its own source instead of
// the default registry: a URL, a git remote, a local archive.
func isPackageURL(p string) bool {
	l := strings.ToLower(p)
	if strings.Contains(l, "://") {
		return true
	}
	for _, pre := range []string{"git+", "git@", "github:", "gitlab:", "bitbucket:", "file:"} {
		if strings.HasPrefix(l, pre) {
			return true
		}
	}
	return false
}

// flagSource extracts the source a registry-style flag names. shellx keeps
// such flags as "--name=value" and environment redirections as
// "env:NAME=value".
func flagSource(fl string) string {
	name, val, ok := strings.Cut(fl, "=")
	if !ok || val == "" {
		return ""
	}
	if strings.HasPrefix(name, "env:") {
		return val
	}
	switch name {
	case "--index-url", "-i", "--extra-index-url", "--registry", "--find-links", "-f", "--source", "-s",
		"--index", "--default-index", "--git", "--repository", "--channel", "-c", "--from", "--tap",
		"--repofrompath", "--trusted-host":
		return val
	}
	return ""
}

func (c *computer) pathCtx() classify.PathCtx {
	return classify.PathCtx{CWD: c.ctx.CWD, Home: c.ctx.Home, OS: c.ctx.OS}
}

// pathClasses is the union of classify.PathClasses over the first maxPaths
// paths, sorted.
func pathClasses(paths []string, ctx classify.PathCtx) []string {
	var all []string
	for i, p := range paths {
		if i >= maxPaths {
			break
		}
		all = append(all, classify.PathClasses(p, ctx)...)
	}
	return sortedUniq(all)
}

func hostClasses(hosts []string) []string {
	var all []string
	for i, h := range hosts {
		if i >= maxList {
			break
		}
		all = append(all, classify.HostClasses(h)...)
	}
	return sortedUniq(all)
}

// secretKinds returns the sorted kinds of credentials in s.
func secretKinds(s string) []string {
	hits := classify.FindSecrets(s)
	if len(hits) == 0 {
		return nil
	}
	kinds := make([]string, 0, len(hits))
	for _, h := range hits {
		kinds = append(kinds, h.Kind)
	}
	return sortedUniq(kinds)
}
