package discovery

import (
	"strings"

	"github.com/thomastysong/spoor/internal/catalog"
	"github.com/thomastysong/spoor/internal/event"
)

// Telemetry.Hooks values.
const (
	hooksManaged     = "managed"
	hooksUser        = "user"
	hooksMissing     = "missing"
	hooksModified    = "modified"
	hooksUnsupported = "unsupported"
	hooksDisabled    = "disabled"
)

// hookFile is one file an agent reads hooks from.
type hookFile struct {
	path     string
	syntax   string
	scope    event.Scope
	fallback bool // a dedicated hook file of an agent without a dialect
}

// hookFilesOf lists the existing hook-bearing files of a product for one
// scope. Managed drop-in directories (managed-settings.d, policy.d) are
// read whole, and Claude Code's managed-settings.json is included because
// it can carry hooks next to the drop-ins.
func (s *scanner) hookFilesOf(p *catalog.Product, scope event.Scope, uc *userCtx, project string) []hookFile {
	if p.Hooks == nil {
		return nil
	}
	var pats []string
	switch scope {
	case event.ScopeManaged:
		for _, f := range p.Hooks.ManagedPaths.For(s.goos) {
			pats = append(pats, f)
			if d := dirName(cleanLogical(f)); strings.HasSuffix(d, ".d") {
				pats = append(pats, d+"/*.json")
			}
		}
		if p.Hooks.Dialect == catalog.DialectClaude || p.Hooks.Dialect == catalog.DialectGemini {
			for _, st := range p.Settings {
				if st.Format != "json" && st.Format != "jsonc" {
					continue
				}
				for _, f := range st.File.For(s.goos) {
					if classifySettingPath(f) == scopeManagedFile {
						pats = append(pats, f)
					}
				}
			}
		}
	case event.ScopeUser:
		pats = p.Hooks.UserPaths.For(s.goos)
	case event.ScopeProject:
		for _, f := range p.Hooks.ProjectPaths {
			pats = append(pats, "./"+strings.TrimPrefix(f, "./"))
		}
	}
	var out []hookFile
	seen := map[string]bool{}
	for _, pat := range pats {
		var e string
		if strings.HasPrefix(pat, "./") {
			if project == "" {
				continue
			}
			e = joinLogical(project, strings.TrimPrefix(pat, "./"))
		} else {
			var ok bool
			if e, ok = s.expand(pat, uc); !ok {
				continue
			}
		}
		for _, m := range s.glob(e, uc, project, 256) {
			if seen[m] {
				continue
			}
			seen[m] = true
			syntax := hookSyntax(m)
			if syntax == "plist" {
				continue
			}
			if l := s.locFor(m, uc, project); s.g.isDir(l) {
				continue
			}
			base := strings.ToLower(baseName(m))
			fallback := p.Hooks.Dialect == "" && !strings.HasPrefix(base, "settings") && !strings.HasPrefix(base, "config")
			out = append(out, hookFile{path: m, syntax: syntax, scope: scope, fallback: fallback})
		}
	}
	return out
}

// handlersIn parses one hook file (cached through s.doc). A file that is
// not a config (Cline keeps one executable script per hook event) is itself
// the handler.
func (s *scanner) handlersIn(f hookFile, uc *userCtx, project string) ([]hookHandler, fmeta, bool) {
	l := s.locFor(f.path, uc, project)
	owner := ""
	if f.scope != event.ScopeManaged {
		owner = ownerFor(l, uc)
	}
	if f.syntax == "script" {
		data, meta, err := s.g.readFile(l, owner, maxCommandLen)
		if err != nil {
			return nil, meta, false
		}
		h := hookHandler{event: safeText(baseName(f.path), 128), typ: "script", command: string(data)}
		h.spoor, h.spoorAgent = spoorHook(h.command)
		return []hookHandler{h}, meta, true
	}
	d := s.doc(l, owner, f.syntax)
	if d.err != nil || d.doc == nil {
		return nil, d.meta, false
	}
	hs := extractHooks(d.doc, f.fallback)
	if len(hs) >= maxHandlers {
		s.led.capped("hook handlers truncated: " + homeRelNote(l))
	}
	return hs, d.meta, true
}

// hookSyntax picks how a hook file is read: a config syntax by extension,
// or "script" for an extensionless or script file.
func hookSyntax(p string) string {
	switch pathExt(p) {
	case ".json", ".jsonc":
		return "json"
	case ".toml":
		return "toml"
	case ".yaml", ".yml":
		return "yaml"
	case ".plist":
		return "plist"
	}
	return "script"
}

func matchesAgent(p *catalog.Product, id string) bool {
	if id == "" || id == p.ID {
		return id == p.ID
	}
	for _, a := range p.Aliases {
		if strings.EqualFold(a, id) {
			return true
		}
	}
	return false
}

// telemetry states how well spoor can see one agent for one user.
func (s *scanner) telemetry(i int, uc *userCtx, disabled bool) *event.Telemetry {
	p := &s.products[i]
	t := &event.Telemetry{Hooks: s.hookStatus(p, uc, disabled)}
	if p.Transcript != nil {
		t.Transcript = s.transcriptStatus(p, uc)
	}
	t.NativeOTel = s.nativeOTel(p, uc)
	if t.Hooks == hooksUnsupported && t.Transcript == "" && t.NativeOTel == "" {
		if p.Kind != string(event.AssetAgent) {
			return nil
		}
	}
	return t
}

func (s *scanner) hookStatus(p *catalog.Product, uc *userCtx, disabled bool) string {
	if p.Hooks == nil || p.Hooks.Dialect == "" {
		return hooksUnsupported
	}
	managed, user, modified := false, false, false
	for _, f := range s.hookFilesOf(p, event.ScopeManaged, nil, "") {
		hs, _, ok := s.handlersIn(f, nil, "")
		if !ok {
			continue
		}
		for _, h := range hs {
			if !h.spoor {
				continue
			}
			if matchesAgent(p, h.spoorAgent) {
				managed = true
				if mf := s.managed[p.ID]; mf != nil && mf.insecure[systemLoc(f.path).String()] {
					modified = true
				}
			} else {
				modified = true
			}
		}
	}
	for _, f := range s.hookFilesOf(p, event.ScopeUser, uc, "") {
		hs, _, ok := s.handlersIn(f, uc, "")
		if !ok {
			continue
		}
		for _, h := range hs {
			if h.spoor && matchesAgent(p, h.spoorAgent) {
				user = true
			}
		}
	}
	switch {
	case managed && !modified:
		// Managed hooks survive the user-level kill switches of Claude Code
		// and Copilot (disableAllHooks); for the others the switch is reported.
		if disabled && p.Hooks.Dialect != catalog.DialectClaude && p.Hooks.Dialect != catalog.DialectCopilot {
			return hooksDisabled
		}
		return hooksManaged
	case modified:
		return hooksModified
	case disabled:
		return hooksDisabled
	case user:
		return hooksUser
	}
	return hooksMissing
}

// Telemetry.Transcript values.
const (
	transcriptFound     = "found"
	transcriptNone      = "none"
	transcriptRelocated = "relocated"
)

func (s *scanner) transcriptStatus(p *catalog.Product, uc *userCtx) string {
	tr := p.Transcript
	relocated := false
	if tr.HomeEnv != "" {
		if v := uc.env[tr.HomeEnv]; v != "" {
			relocated = true
		}
	}
	for _, g := range tr.Globs.For(s.goos) {
		e, ok := s.expand(g, uc)
		if !ok {
			continue
		}
		if len(s.glob(e, uc, "", 1)) > 0 {
			if relocated {
				return transcriptRelocated
			}
			return transcriptFound
		}
		if !s.g.alive() {
			break
		}
	}
	if relocated {
		return transcriptRelocated
	}
	return transcriptNone
}

// Telemetry.NativeOTel values.
const (
	otelEnabled     = "enabled"
	otelDisabled    = "disabled"
	otelUnsupported = "unsupported"
)

// nativeOTel reports whether the agent's own OpenTelemetry export is
// switched on in a settings file spoor can see (the environment of a
// running process is the process monitor's business).
func (s *scanner) nativeOTel(p *catalog.Product, uc *userCtx) string {
	if p.Hooks == nil {
		return ""
	}
	var check func(doc any) bool
	switch p.Hooks.Dialect {
	case catalog.DialectClaude:
		check = func(doc any) bool {
			v, ok := getPath(doc, "env", "CLAUDE_CODE_ENABLE_TELEMETRY")
			if !ok {
				return false
			}
			t := scalarString(v)
			return t == "1" || strings.EqualFold(t, "true")
		}
	case catalog.DialectCodex:
		check = func(doc any) bool {
			ex, ok := getPath(doc, "otel", "exporter")
			if !ok {
				return false
			}
			if str, ok := ex.(string); ok {
				return str != "" && str != "none"
			}
			return true
		}
	case catalog.DialectGemini:
		check = func(doc any) bool {
			v, ok := getPath(doc, "telemetry", "enabled")
			b, _ := asBool(v)
			return ok && b
		}
	default:
		return otelUnsupported
	}
	files := append(s.hookFilesOf(p, event.ScopeManaged, nil, ""), s.hookFilesOf(p, event.ScopeUser, uc, "")...)
	for _, f := range files {
		var l loc
		owner := ""
		if f.scope == event.ScopeManaged {
			l = systemLoc(f.path)
		} else {
			l = s.locFor(f.path, uc, "")
			owner = ownerFor(l, uc)
		}
		if d := s.doc(l, owner, f.syntax); d.err == nil && d.doc != nil && check(d.doc) {
			return otelEnabled
		}
	}
	if p.Hooks.Dialect == catalog.DialectCodex {
		// Codex keeps [otel] in config.toml next to hooks.json.
		for _, m := range p.MCP {
			for _, f := range m.Paths.For(s.goos) {
				e, ok := s.expand(f, uc)
				if !ok || !strings.HasSuffix(e, ".toml") {
					continue
				}
				l := s.locFor(e, uc, "")
				if d := s.doc(l, ownerFor(l, uc), "toml"); d.err == nil && d.doc != nil && check(d.doc) {
					return otelEnabled
				}
			}
		}
	}
	return otelDisabled
}
