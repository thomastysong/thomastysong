package discovery

import (
	"strconv"
	"strings"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/shellx"
)

// Hook risk flags.
const (
	flagHookRemoteFetchExec = "hook_remote_fetch_exec"
	flagHookEncoded         = "hook_encoded"
	flagHookRunsRepoScript  = "hook_runs_repo_script"
	flagHookNetworkTool     = "hook_network_tool"
)

// scanHookFiles records one hook asset per declared handler in the
// context's hook files (managed for uc nil, the user's, or a project's).
func (s *scanner) scanHookFiles(uc *userCtx, project string) {
	scope := event.ScopeManaged
	switch {
	case project != "":
		scope = event.ScopeProject
	case uc != nil:
		scope = event.ScopeUser
	}
	parent := map[string]int{}
	var order []hookFile
	for i := range s.products {
		p := &s.products[i]
		for _, f := range s.hookFilesOf(p, scope, uc, project) {
			if j, ok := parent[f.path]; ok {
				// Agents win over apps as the reported reader.
				if s.products[j].Kind != string(event.AssetAgent) && p.Kind == string(event.AssetAgent) {
					parent[f.path] = i
				}
				continue
			}
			parent[f.path] = i
			order = append(order, f)
		}
	}
	for _, f := range order {
		if !s.g.alive() {
			return
		}
		hs, _, ok := s.handlersIn(f, uc, project)
		if !ok {
			continue
		}
		s.addHooks(hs, f.path, f.scope, s.products[parent[f.path]].ID, uc, project, "")
	}
}

func (s *scanner) addHooks(hs []hookHandler, file string, scope event.Scope, parentID string, uc *userCtx, project, plugin string) {
	sortHandlers(hs)
	for _, h := range hs {
		name := h.event
		if h.matcher != "" {
			name += ":" + h.matcher
		}
		a := &event.Asset{
			Kind:   event.AssetHook,
			Name:   safeText(name, 256),
			Parent: parentID,
			Path:   safeText(file, 1024),
			Scope:  scope,
			SHA256: h.definitionHash(),
			Detail: map[string]string{
				"event":   h.event,
				"type":    safeText(h.typ, 32),
				"handler": strconv.Itoa(h.index),
			},
		}
		if h.matcher != "" {
			a.Detail["matcher"] = h.matcher
		}
		if h.async {
			a.Detail["async"] = "true"
		}
		if h.spoor {
			a.Detail["spoor"] = "true"
			if h.spoorAgent != "" {
				a.Detail["spoor_agent"] = h.spoorAgent
			}
		}
		if project != "" {
			a.Detail["project"] = safeText(project, 1024)
		}
		if plugin != "" {
			a.Detail["plugin"] = safeText(plugin, 256)
		}
		if uc != nil {
			a.Owner = uc.u.Name
		}
		if h.url != "" {
			a.Detail["url_host"] = safeText(urlHost(h.url), 256)
		}
		a.RiskFlags = hookRiskFlags(h.command, scope == event.ScopeProject)
		s.add(&record{a: a, uc: uc, content: h.command})
	}
}

// projectDirVars are the variables agents set to the project root for hook
// processes; a hook that runs a file through them runs repository content.
var projectDirVars = []string{"CLAUDE_PROJECT_DIR", "GEMINI_PROJECT_DIR", "CURSOR_PROJECT_DIR", "CODEX_PROJECT_DIR", "PWD"}

// hookRiskFlags reads a hook command with the shell analyzer. A hook is
// code that runs on every matching agent event, often with the user's full
// privileges and outside any agent sandbox.
func hookRiskFlags(cmd string, projectScope bool) (flags []string) {
	if strings.TrimSpace(cmd) == "" {
		return nil
	}
	defer func() {
		if recover() != nil {
			flags = []string{flagHookEncoded} // unreadable to the analyzer: opaque
		}
	}()
	fs := flagSet{}
	for _, line := range strings.Split(cmd, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		dialect := shellx.Dialect("")
		f := shellx.Analyze(line, dialect)
		if f.DownloadAndExecute || f.PipeToInterpreter && f.Downloads {
			fs.add(flagHookRemoteFetchExec)
		}
		if len(f.Decoded) > 0 {
			fs.add(flagHookEncoded)
		}
		for _, o := range f.Obfuscation {
			switch o {
			case "base64_decode_exec", "encoded_command", "hex_escape", "rev_exec", "char_concat":
				fs.add(flagHookEncoded)
			}
		}
		if len(f.NetTools) > 0 || f.Downloads || len(f.Exfil) > 0 {
			fs.add(flagHookNetworkTool)
		}
		for _, p := range f.ExecutesPaths {
			if repoRelative(p) || projectScope && !strings.HasPrefix(p, "/") {
				fs.add(flagHookRunsRepoScript)
			}
		}
		for _, v := range projectDirVars[:4] {
			if strings.Contains(line, "$"+v) || strings.Contains(line, "${"+v) || strings.Contains(line, "%"+v+"%") || strings.Contains(line, "$env:"+v) {
				fs.add(flagHookRunsRepoScript)
			}
		}
	}
	return fs.list()
}

// repoRelative reports a path that resolves against the working directory
// (the repository the agent was opened in) or a project-root variable.
func repoRelative(p string) bool {
	if p == "" {
		return false
	}
	if strings.HasPrefix(p, "./") || strings.HasPrefix(p, `.\`) || strings.HasPrefix(p, "../") {
		return true
	}
	for _, v := range projectDirVars {
		if strings.Contains(p, v) {
			return true
		}
	}
	if strings.HasPrefix(p, "/") || strings.HasPrefix(p, "~") || strings.HasPrefix(p, "$") || strings.HasPrefix(p, "%") ||
		len(p) >= 2 && p[1] == ':' || strings.HasPrefix(p, `\\`) {
		return false
	}
	return strings.ContainsAny(p, `/\`)
}

// urlHost extracts the host of a URL without a parser that might choke.
func urlHost(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
	}
	if i := strings.IndexAny(u, "/?#"); i >= 0 {
		u = u[:i]
	}
	if i := strings.LastIndexByte(u, '@'); i >= 0 {
		u = u[i+1:]
	}
	if h, _, ok := strings.Cut(u, ":"); ok && !strings.HasPrefix(u, "[") {
		u = h
	}
	return strings.ToLower(u)
}
