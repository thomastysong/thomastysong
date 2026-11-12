package discovery

import (
	"sort"
	"strings"

	"github.com/thomastysong/spoor/internal/event"
)

// Project control-file flags.
const (
	flagAutorunHook        = "autorun_hook"
	flagAutorunRule        = "autorun_rule"
	flagAutorunTask        = "autorun_task"
	flagEscalatePerms      = "settings_escalate_permissions"
	flagBaseURLOverride    = "base_url_override"
	flagGitExecKey         = "git_exec_key"
	flagIDEExecPath        = "ide_exec_path_in_workspace"
	flagIDEAutoApprove     = "ide_auto_approve"
	maxProjectControlFiles = 512
)

// pcFile accumulates findings for one project control file.
type pcFile struct {
	path    string
	parent  string
	flags   flagSet
	keys    map[string]bool // names of the keys that raised flags (never values)
	control bool            // an agent control file: reported even when clean
}

type pcSet struct {
	s     *scanner
	uc    *userCtx
	dir   string
	files map[string]*pcFile
	order []string
}

func (ps *pcSet) get(p, parent string, control bool) *pcFile {
	f := ps.files[p]
	if f == nil {
		f = &pcFile{path: p, parent: parent, flags: flagSet{}, keys: map[string]bool{}}
		ps.files[p] = f
		ps.order = append(ps.order, p)
	}
	if f.parent == "" {
		f.parent = parent
	}
	f.control = f.control || control
	return f
}

func (ps *pcSet) flag(p, parent, flag, key string) {
	f := ps.get(p, parent, false)
	f.flags.add(flag)
	if key != "" {
		f.keys[key] = true
	}
}

func (ps *pcSet) loc(p string) loc { return ps.s.locFor(p, ps.uc, ps.dir) }

func (ps *pcSet) doc(rel, syntax string) (string, any, bool) {
	p := joinLogical(ps.dir, rel)
	l := ps.loc(p)
	d := ps.s.doc(l, ownerFor(l, ps.uc), syntax)
	if d.err != nil || d.doc == nil {
		return p, nil, false
	}
	return p, d.doc, true
}

// scanProjectConfig inventories a project's agent and IDE control files:
// files that make an agent or editor run something, or widen what it may
// do, as soon as the folder is opened.
func (s *scanner) scanProjectConfig(uc *userCtx, dir string) {
	ps := &pcSet{s: s, uc: uc, dir: dir, files: map[string]*pcFile{}}
	// Hook files of every agent (.claude/settings*.json, .codex/hooks.json,
	// .cursor/hooks.json, .github/hooks/*.json, .gemini/settings.json ...).
	for i := range s.products {
		p := &s.products[i]
		for _, f := range s.hookFilesOf(p, event.ScopeProject, uc, dir) {
			hs, _, ok := s.handlersIn(f, uc, dir)
			if !ok {
				continue
			}
			pf := ps.get(f.path, p.ID, true)
			if len(hs) > 0 {
				pf.flags.add(flagAutorunHook)
				pf.keys["hooks"] = true
			}
		}
	}
	ps.claudeSettings(".claude/settings.json")
	ps.claudeSettings(".claude/settings.local.json")
	ps.geminiSettings()
	ps.dotenv(".gemini/.env", "gemini-cli")
	ps.codexConfig()
	ps.cursorRules()
	ps.vscodeTasks(".vscode/tasks.json", "tasks")
	ps.vscodeSettings(".vscode/settings.json", nil)
	ps.workspaces()
	ps.gitConfig()
	for p, flags := range s.projectSettingFlags(uc, dir) {
		pf := ps.get(p, "", true)
		pf.flags.add(flags...)
	}
	n := 0
	for _, p := range ps.order {
		f := ps.files[p]
		if len(f.flags) == 0 && !f.control {
			continue
		}
		n++
		if n > maxProjectControlFiles {
			break
		}
		s.addProjectConfig(f, uc, dir)
	}
}

func (s *scanner) addProjectConfig(f *pcFile, uc *userCtx, dir string) {
	l := s.locFor(f.path, uc, dir)
	data, _, err := s.g.readFile(l, ownerFor(l, uc), maxConfigBytes)
	if err != nil {
		return
	}
	rel, _ := relLogical(dir, f.path, s.goos)
	a := &event.Asset{
		Kind:      event.AssetProjectConfig,
		Name:      safeText(rel, 256),
		Parent:    f.parent,
		Path:      safeText(f.path, 1024),
		Scope:     event.ScopeProject,
		SHA256:    sha256Hex(data),
		RiskFlags: f.flags.list(),
		Detail:    map[string]string{"project": safeText(dir, 1024)},
	}
	if len(f.keys) > 0 {
		a.Detail["keys"] = strings.Join(sortedKeys(f.keys), ",")
	}
	if uc != nil {
		a.Owner = uc.u.Name
	}
	s.add(&record{a: a, uc: uc})
}

// Claude Code project settings.
var claudeHelperKeys = [][]string{
	{"apiKeyHelper"}, {"awsAuthRefresh"}, {"awsCredentialExport"}, {"otelHeadersHelper"},
	{"statusLine", "command"}, {"fileSuggestion", "command"},
}

func (ps *pcSet) claudeSettings(rel string) {
	p, doc, ok := ps.doc(rel, "json")
	if !ok {
		return
	}
	ps.get(p, "claude-code", true)
	for _, k := range claudeHelperKeys {
		if v, ok := getPath(doc, k...); ok {
			if s, _ := asString(v); s != "" {
				// Helpers are commands Claude Code runs itself.
				ps.flag(p, "claude-code", flagAutorunHook, strings.Join(k, "."))
			}
		}
	}
	switch getString(doc, "permissions", "defaultMode") {
	case "bypassPermissions", "dontAsk", "auto":
		ps.flag(p, "claude-code", flagEscalatePerms, "permissions.defaultMode")
	}
	if allow, ok := getPath(doc, "permissions", "allow"); ok {
		for _, x := range asList(allow) {
			switch s, _ := asString(x); strings.TrimSpace(s) {
			case "Bash", "Bash(*)", "Bash(:*)", "*", "mcp__*":
				ps.flag(p, "claude-code", flagEscalatePerms, "permissions.allow")
			}
		}
	}
	if v, ok := getPath(doc, "enableAllProjectMcpServers"); ok {
		if b, _ := asBool(v); b {
			ps.flag(p, "claude-code", flagEscalatePerms, "enableAllProjectMcpServers")
		}
	}
	if env, ok := asMap(mustGet(doc, "env")); ok {
		for _, k := range sortedKeys(env) {
			if baseURLKey(k) {
				ps.flag(p, "claude-code", flagBaseURLOverride, "env."+safeKey(k))
			}
		}
	}
}

// baseURLKey matches variables that redirect an agent's model traffic.
func baseURLKey(k string) bool {
	u := strings.ToUpper(k)
	return strings.HasSuffix(u, "_BASE_URL") || strings.HasSuffix(u, "_API_BASE") || u == "BASE_URL" ||
		strings.HasSuffix(u, "_BASE_URI") || strings.HasSuffix(u, "_API_URL") || strings.HasSuffix(u, "_ENDPOINT")
}

// safeKey renders a key name from a hostile file for Detail: names only,
// bounded, and never something that looks like a credential.
func safeKey(k string) string {
	k = safeText(k, 64)
	var b strings.Builder
	for _, c := range k {
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '.' || c == '-' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

func (ps *pcSet) geminiSettings() {
	p, doc, ok := ps.doc(".gemini/settings.json", "json")
	if !ok {
		return
	}
	ps.get(p, "gemini-cli", true)
	for _, k := range [][]string{{"tools", "discoveryCommand"}, {"tools", "callCommand"}} {
		if s := getString(doc, k...); s != "" {
			ps.flag(p, "gemini-cli", flagAutorunHook, strings.Join(k, "."))
		}
	}
	for _, k := range [][]string{{"general", "defaultApprovalMode"}, {"defaultApprovalMode"}, {"tools", "approvalMode"}} {
		switch strings.ToLower(getString(doc, k...)) {
		case "yolo", "auto_edit":
			ps.flag(p, "gemini-cli", flagEscalatePerms, strings.Join(k, "."))
		}
	}
	for _, k := range [][]string{{"tools", "autoAccept"}, {"autoAccept"}} {
		if v, ok := getPath(doc, k...); ok {
			if b, _ := asBool(v); b {
				ps.flag(p, "gemini-cli", flagEscalatePerms, strings.Join(k, "."))
			}
		}
	}
	if v, ok := getPath(doc, "hooksConfig", "enabled"); ok {
		if b, ok := asBool(v); ok && !b {
			ps.flag(p, "gemini-cli", "hooks_disabled", "hooksConfig.enabled")
		}
	}
}

// dotenv flags model-endpoint overrides in a .env file; only key names
// are kept.
func (ps *pcSet) dotenv(rel, parent string) {
	p := joinLogical(ps.dir, rel)
	l := ps.loc(p)
	data, _, err := ps.s.g.readFile(l, ownerFor(l, ps.uc), 1<<20)
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "export "))
		k, _, ok := strings.Cut(line, "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		if k = strings.TrimSpace(k); baseURLKey(k) {
			ps.flag(p, parent, flagBaseURLOverride, safeKey(k))
		}
	}
}

func (ps *pcSet) codexConfig() {
	p, doc, ok := ps.doc(".codex/config.toml", "toml")
	if !ok {
		return
	}
	ps.get(p, "codex", true)
	if h, ok := asMap(mustGet(doc, "hooks")); ok && len(h) > 0 {
		ps.flag(p, "codex", flagAutorunHook, "hooks")
	}
	if v, ok := getPath(doc, "notify"); ok && len(asList(v)) > 0 {
		ps.flag(p, "codex", flagAutorunHook, "notify")
	}
	if getString(doc, "approval_policy") == "never" {
		ps.flag(p, "codex", flagEscalatePerms, "approval_policy")
	}
	if getString(doc, "sandbox_mode") == "danger-full-access" {
		ps.flag(p, "codex", flagEscalatePerms, "sandbox_mode")
	}
	for _, k := range []string{"openai_base_url", "chatgpt_base_url", "model_provider_base_url"} {
		if getString(doc, k) != "" {
			ps.flag(p, "codex", flagBaseURLOverride, k)
		}
	}
	if mp, ok := asMap(mustGet(doc, "model_providers")); ok {
		for _, name := range sortedKeys(mp) {
			if getString(mp[name], "base_url") != "" {
				ps.flag(p, "codex", flagBaseURLOverride, "model_providers.*.base_url")
			}
		}
	}
}

// cursorRules flags .cursor/rules/*.mdc files that apply to every request.
func (ps *pcSet) cursorRules() {
	root := joinLogical(ps.dir, ".cursor/rules")
	var walk func(d string, depth int)
	count := 0
	walk = func(d string, depth int) {
		if depth > 4 || count > maxContentFiles {
			return
		}
		ents, err := ps.s.g.readDir(ps.loc(d))
		if err != nil {
			return
		}
		for _, e := range ents {
			p := joinLogical(d, e.name)
			switch {
			case e.kind == kindDir:
				walk(p, depth+1)
			case e.kind == kindRegular && strings.HasSuffix(strings.ToLower(e.name), ".mdc"):
				count++
				l := ps.loc(p)
				data, _, err := ps.s.g.readFile(l, ownerFor(l, ps.uc), 1<<20)
				if err == nil && alwaysApply(string(data)) {
					ps.flag(p, "cursor", flagAutorunRule, "alwaysApply")
				}
			}
		}
	}
	walk(root, 0)
}

func alwaysApply(text string) bool {
	if !strings.HasPrefix(strings.TrimPrefix(text, "\ufeff"), "---") {
		return false
	}
	lines := strings.SplitN(text, "\n", 128)
	for _, l := range lines[1:] {
		l = strings.TrimSpace(strings.TrimRight(l, "\r"))
		if l == "---" {
			return false
		}
		if v, ok := strings.CutPrefix(l, "alwaysApply:"); ok {
			return strings.EqualFold(strings.Trim(strings.TrimSpace(v), `"'`), "true")
		}
	}
	return false
}

// vscodeTasks flags tasks that run when the folder is opened.
func (ps *pcSet) vscodeTasks(rel, key string) {
	p, doc, ok := ps.doc(rel, "json")
	if !ok {
		return
	}
	ps.checkTasks(p, doc)
}

func (ps *pcSet) checkTasks(p string, doc any) {
	for _, t := range asList(mustGet(doc, "tasks")) {
		if strings.EqualFold(getString(t, "runOptions", "runOn"), "folderOpen") {
			ps.flag(p, "vscode", flagAutorunTask, "tasks.runOptions.runOn")
			return
		}
	}
}

// execPathSuffixes are the endings of VS Code-family setting names that
// name an executable (or a directory of executables) the editor or an
// extension will run.
var execPathSuffixes = []string{"path", "executable", "executablepath", "command", "commandpath", "binpath",
	"interpreter", "tsdk", "nodepath", "serverpath", "goroot", "shell.linux", "shell.osx", "shell.windows", "runtime"}

// vscodeSettings flags auto-approve switches and executable paths that
// point into the workspace (a repository can ship the "linter" the editor
// runs on open).
func (ps *pcSet) vscodeSettings(rel string, doc any) {
	var p string
	if doc == nil {
		var ok bool
		if p, doc, ok = ps.doc(rel, "json"); !ok {
			return
		}
	} else {
		p = joinLogical(ps.dir, rel)
	}
	m, ok := asMap(doc)
	if !ok {
		return
	}
	var walk func(prefix string, v any, depth int)
	walk = func(prefix string, v any, depth int) {
		if depth > 6 {
			return
		}
		low := strings.ToLower(prefix)
		if strings.Contains(low, "autoapprove") && truthyApproval(v) {
			ps.flag(p, "vscode", flagIDEAutoApprove, safeKey(prefix))
		}
		if strings.HasSuffix(low, "allowedcommands") {
			for _, x := range asList(v) {
				if s, _ := asString(x); s == "*" {
					ps.flag(p, "vscode", flagIDEAutoApprove, safeKey(prefix))
				}
			}
		}
		if strings.HasSuffix(low, "initialpermissionmode") || strings.HasSuffix(low, "dangerouslyskippermissions") {
			if s, _ := asString(v); s == "bypassPermissions" {
				ps.flag(p, "vscode", flagIDEAutoApprove, safeKey(prefix))
			} else if b, ok := asBool(v); ok && b {
				ps.flag(p, "vscode", flagIDEAutoApprove, safeKey(prefix))
			}
		}
		switch t := v.(type) {
		case string:
			for _, suf := range execPathSuffixes {
				if strings.HasSuffix(low, suf) && workspacePath(t) {
					ps.flag(p, "vscode", flagIDEExecPath, safeKey(prefix))
					break
				}
			}
		case map[string]any:
			for _, k := range sortedKeys(t) {
				walk(prefix+"."+k, t[k], depth+1)
			}
		}
	}
	for _, k := range sortedKeys(m) {
		walk(k, m[k], 0)
	}
}

func truthyApproval(v any) bool {
	switch t := v.(type) {
	case bool:
		return t
	case string:
		return strings.EqualFold(t, "true")
	case map[string]any:
		for _, x := range t {
			if b, ok := asBool(x); ok && b {
				return true
			}
			if m, ok := asMap(x); ok {
				if b, ok := asBool(m["approve"]); ok && b {
					return true
				}
			}
		}
	}
	return false
}

// workspacePath reports a path that resolves inside the opened folder.
func workspacePath(v string) bool {
	v = strings.TrimSpace(v)
	if v == "" || len(v) > 4096 {
		return false
	}
	if strings.Contains(v, "${workspaceFolder") || strings.Contains(v, "${workspaceRoot}") || strings.Contains(v, "${fileWorkspaceFolder}") {
		return true
	}
	if strings.HasPrefix(v, "./") || strings.HasPrefix(v, `.\`) {
		return true
	}
	if strings.HasPrefix(v, "/") || strings.HasPrefix(v, "~") || strings.HasPrefix(v, "$") || strings.HasPrefix(v, "%") ||
		strings.HasPrefix(v, "../") || len(v) >= 2 && v[1] == ':' || strings.HasPrefix(v, `\\`) {
		return false
	}
	// "node_modules/.bin/x" or "venv\Scripts\python.exe": relative with a
	// separator resolves against the workspace; a bare name is a PATH lookup.
	return strings.ContainsAny(v, `/\`)
}

// workspaces checks *.code-workspace files at the project root.
func (ps *pcSet) workspaces() {
	ents, err := ps.s.g.readDir(loc{root: ps.dir, user: true})
	if err != nil {
		return
	}
	for _, e := range ents {
		if e.kind != kindRegular || !strings.HasSuffix(strings.ToLower(e.name), ".code-workspace") {
			continue
		}
		p, doc, ok := ps.doc(e.name, "json")
		if !ok {
			continue
		}
		if st, ok := getPath(doc, "settings"); ok {
			ps.vscodeSettings(e.name, st)
		}
		if t, ok := getPath(doc, "tasks"); ok {
			ps.checkTasks(p, t)
		}
	}
}

// gitExecKeys returns the exec-sink keys set in a git config: settings that
// make git run a program the repository chose (core.fsmonitor runs on every
// status). Only canonical key names are returned.
func gitExecKeys(text string) []string {
	keys := map[string]bool{}
	section, sub := "", ""
	for _, raw := range strings.Split(text, "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}
		if line[0] == '[' {
			end := strings.IndexByte(line, ']')
			if end < 0 {
				continue
			}
			hdr := strings.TrimSpace(line[1:end])
			section, sub = hdr, ""
			if i := strings.IndexAny(hdr, " \t"); i >= 0 {
				section = hdr[:i]
				sub = strings.Trim(strings.TrimSpace(hdr[i:]), `"`)
			} else if i := strings.IndexByte(hdr, '.'); i >= 0 {
				section, sub = hdr[:i], hdr[i+1:]
			}
			section = strings.ToLower(section)
			line = strings.TrimSpace(line[end+1:])
			if line == "" {
				continue
			}
		}
		k, v, hasV := strings.Cut(line, "=")
		k = strings.ToLower(strings.TrimSpace(k))
		v = strings.Trim(strings.TrimSpace(v), `"`)
		if !hasV {
			v = "true"
		}
		switch section {
		case "core":
			switch k {
			case "fsmonitor":
				if lv := strings.ToLower(v); lv != "true" && lv != "false" && lv != "" && lv != "0" && lv != "1" {
					keys["core.fsmonitor"] = true
				}
			case "sshcommand", "hookspath", "pager", "editor", "gitproxy", "askpass":
				keys["core."+k] = true
			}
		case "alias":
			if strings.HasPrefix(v, "!") {
				keys["alias.*"] = true
			}
		case "filter":
			if k == "clean" || k == "smudge" || k == "process" {
				keys["filter.*."+k] = true
			}
		case "diff":
			if sub != "" && (k == "textconv" || k == "command") {
				keys["diff.*."+k] = true
			}
		case "merge":
			if sub != "" && k == "driver" {
				keys["merge.*.driver"] = true
			}
		case "credential":
			if k == "helper" && strings.HasPrefix(v, "!") {
				keys["credential.helper"] = true
			}
		case "include":
			if k == "path" {
				keys["include.path"] = true
			}
		case "includeif":
			if k == "path" {
				keys["includeIf.*.path"] = true
			}
		case "sequence":
			if k == "editor" {
				keys["sequence.editor"] = true
			}
		}
	}
	out := sortedKeys(keys)
	sort.Strings(out)
	return out
}

func (ps *pcSet) gitConfig() {
	p := joinLogical(ps.dir, ".git/config")
	l := ps.loc(p)
	data, _, err := ps.s.g.readFile(l, ownerFor(l, ps.uc), 1<<20)
	if err != nil {
		return
	}
	for _, k := range gitExecKeys(string(data)) {
		ps.flag(p, "", flagGitExecKey, k)
	}
}
