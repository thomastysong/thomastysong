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
// child process, and whether that argv was cut to its first and last
// maxProcArgs/2 entries.
func commandText(e *event.Event) (string, bool) {
	if e.Target != nil && e.Target.Command != "" {
		return e.Target.Command, false
	}
	if e.Type == event.TypeProcessExec && e.Process != nil && len(e.Process.Args) > 0 {
		args, cut := headTailCut(e.Process.Args, maxProcArgs)
		return toolmap.CommandFromArgv(args), cut
	}
	return "", false
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
	return shellx.AnalyzeWith(cmd, c.dialectHint(), shellx.Options{OS: c.ctx.OS})
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
	raw, argvCut := commandText(c.e)
	if raw == "" {
		return
	}
	fx := c.analyzeBounded(raw)
	if fx == nil {
		return
	}
	cmd := c.bound(raw)
	// An analysis that stopped early (or saw only the head and tail of an
	// oversized command line) leaves every list it produced incomplete.
	c.shellFacts(fx, cmd, fx.Truncated || argvCut || len(cmd) != len(raw))
}

// shellFacts stores the shell.* features of one analysis. text is the
// (bounded) text that was analysed, scanned for literal credentials;
// partial says every list is incomplete. Written scripts go through the
// same function (script.go), so a script run later gets exactly the facts
// a shell event carrying its content would have had.
func (c *computer) shellFacts(fx *shellx.Facts, text string, partial bool) {
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

	var names uniqList
	dynamic := false
	for _, cm := range fx.Commands {
		dynamic = dynamic || cm.Dynamic
		names.add(cm.Name)
	}
	f["shell.dynamic"] = dynamic
	c.setDerived("shell.commands", names.list, partial)
	c.argv(fx.Commands, partial)
	c.cmds(fx.Commands, partial)

	list := func(key string, l []string) []string {
		kept := c.setList(key, l)
		if kept != nil && (partial || len(l) >= shellxListCap) {
			c.markCut(key)
		}
		return kept
	}
	hosts := list("shell.hosts", fx.Hosts)
	list("shell.urls", fx.URLs)
	c.urls = append(c.urls, fx.URLs...)
	c.hosts = append(c.hosts, fx.Hosts...)
	hostsCut := c.cut["shell.hosts"]
	c.netCut = c.netCut || hostsCut || c.cut["shell.urls"]
	c.setDerived("shell.host_classes", hostClasses(hosts), hostsCut)

	pc := c.pathCtx()
	for _, fam := range []struct {
		key, classes string
		paths        []string
	}{
		{"shell.reads", "shell.read_classes", fx.Reads},
		{"shell.writes", "shell.write_classes", fx.Writes},
		{"shell.deletes", "shell.delete_classes", fx.Deletes},
		{"shell.changes", "shell.change_classes", fx.Changes},
	} {
		kept := list(fam.key, c.homeClimbs(fam.paths))
		c.setDerived(fam.classes, pathClasses(kept, pc), c.cut[fam.key])
	}
	list("shell.aliases", c.homeClimbs(fx.Aliases))
	list("shell.proc_root", fx.ProcRoot)

	list("shell.interpreters", fx.Interpreters)
	var langs uniqList
	for _, ic := range fx.Inline {
		langs.add(ic.Lang)
	}
	c.setDerived("shell.inline_langs", langs.list, partial)

	list("shell.obfuscation", fx.Obfuscation)
	list("shell.opaque", fx.Opaque)
	list("shell.executes_paths", c.homeClimbs(fx.ExecutesPaths))
	list("shell.destructive", fx.Destructive)
	list("shell.persistence", fx.Persistence)
	list("shell.defense_evasion", fx.DefenseEvasion)
	list("shell.cred_access", fx.CredAccess)
	list("shell.exfil", fx.Exfil)
	list("shell.net_tools", fx.NetTools)
	list("shell.recon", fx.Recon)
	list("shell.privilege", fx.Privilege)
	list("shell.git_ops", fx.GitOps)
	list("shell.env_assign", fx.EnvAssign)

	c.installs(fx.Installs, partial || len(fx.Installs) >= shellxListCap)

	var kinds []string
	switch {
	case c.secrets != nil:
		kinds = *c.secrets
	case c.secretsSkipped:
		c.markCut("shell.secret_kinds")
	default:
		kinds = secretKinds(text)
	}
	f["shell.has_secret"] = len(kinds) > 0
	c.setDerived("shell.secret_kinds", kinds, partial)
}

// argv stores shell.argv: every literal argument of every command, the
// first and last maxArgv/2 when there are more. It walks the commands
// twice instead of building the full list, which a hostile command line
// can make very long.
func (c *computer) argv(cmds []shellx.Command, partial bool) {
	total := 0
	for _, cm := range cmds {
		total += len(cm.Args)
	}
	if total == 0 {
		return
	}
	head, tailFrom := total, total
	if total > maxArgv {
		head, tailFrom = maxArgv/2, total-(maxArgv-maxArgv/2)
		c.markCut("shell.argv")
	}
	out := make([]string, 0, min(total, maxArgv))
	i := 0
	for _, cm := range cmds {
		for _, a := range cm.Args {
			if i < head || i >= tailFrom {
				out = append(out, a)
			}
			i++
		}
	}
	c.f["shell.argv"] = out
	if partial {
		c.markCut("shell.argv")
	}
}

// cmds stores shell.cmds for the any_command quantifier: the first and last
// maxCmds/2 commands, each with its first and last maxCmdArg/2 arguments
// when there are more. Argument slices are shared with the analysis, which
// is private to this Compute call; rules never modify them.
func (c *computer) cmds(cmds []shellx.Command, partial bool) {
	if len(cmds) == 0 {
		return
	}
	kept, cut := headTailCut(cmds, maxCmds)
	out := make([]map[string]any, 0, len(kept))
	for _, cm := range kept {
		args, argsCut := headTailCut(cm.Args, maxCmdArg)
		cut = cut || argsCut
		if args == nil {
			args = []string{}
		}
		out = append(out, map[string]any{
			"name":    cm.Name,
			"path":    cm.Path,
			"args":    args,
			"origin":  cm.Origin,
			"dynamic": cm.Dynamic,
		})
	}
	c.f["shell.cmds"] = out
	if cut || partial {
		c.markCut("shell.cmds")
	}
}

func (c *computer) installs(list []shellx.PkgInstall, partial bool) {
	f := c.f
	var flat, managers, sources uniqList
	kept, cut := headTailCut(list, maxList)
	cut = cut || partial
	entries := make([]map[string]any, 0, len(kept))
	exec := false
	for _, in := range list {
		exec = exec || in.Exec
		managers.add(in.Manager)
		if len(in.Packages) == 0 {
			flat.add(in.Manager + ":")
		}
		for _, p := range in.Packages {
			flat.add(in.Manager + ":" + p)
			if isPackageURL(p) {
				sources.add(p)
			}
		}
		for _, fl := range in.Flags {
			if v := flagSource(fl); v != "" {
				sources.add(v)
			}
		}
	}
	for _, in := range kept {
		pkgs, pc := headTailCut(in.Packages, maxCmdArg)
		flags, fc := headTailCut(in.Flags, maxCmdArg)
		cut = cut || pc || fc
		entries = append(entries, map[string]any{
			"manager":  in.Manager,
			"packages": append([]string{}, pkgs...),
			"global":   in.Global,
			"exec":     in.Exec,
			"flags":    append([]string{}, flags...),
		})
	}
	f["shell.install_exec"] = exec
	c.setDerived("shell.installs", flat.list, partial)
	c.setDerived("shell.install_managers", managers.list, partial)
	c.setDerived("shell.install_sources", sources.list, partial)
	if len(entries) > 0 {
		f["shell.install_entries"] = entries
		if cut {
			c.markCut("shell.install_entries")
		}
	}
	for _, s := range sources.list {
		if h := classify.URLHost(s); h != "" && strings.Contains(s, "://") {
			c.urls = append(c.urls, s)
		}
	}
	c.netCut = c.netCut || c.cut["shell.install_sources"]
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

// pathClasses is the union of classify.PathClasses over paths (callers
// pass lists already cut to maxList), sorted.
func pathClasses(paths []string, ctx classify.PathCtx) []string {
	var all []string
	for _, p := range paths {
		all = append(all, classify.PathClasses(p, ctx)...)
	}
	return sortedUniq(all)
}

// hostClasses is the union of classify.HostClasses over hosts (callers pass
// lists already cut to maxList), sorted.
func hostClasses(hosts []string) []string {
	var all []string
	for _, h := range hosts {
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
