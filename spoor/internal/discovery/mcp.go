package discovery

import (
	"strings"

	"github.com/thomastysong/spoor/internal/classify"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/mcpconf"
)

const flagUntrustedLocation = "untrusted_location"

// mcpSite is one MCP configuration file and the products that read it.
type mcpSite struct {
	path    string
	format  string
	scope   event.Scope
	readers []int // product indexes; the first is the reported parent
}

// mcpSites lists the existing MCP config files for a context: machine-wide
// (uc nil), a user's home, or a project. Several products often read one
// file (~/.cursor/mcp.json for the Cursor IDE and CLI); it is parsed once
// and its servers are reported under the first agent, the others listed in
// Detail["also_read_by"].
func (s *scanner) mcpSites(uc *userCtx, project string) []*mcpSite {
	byPath := map[string]*mcpSite{}
	var order []string
	for i := range s.products {
		p := &s.products[i]
		for _, m := range p.MCP {
			var pats []string
			scope := event.Scope(m.Scope)
			if scope == "" {
				scope = event.ScopeUser
			}
			if project != "" {
				for _, pp := range m.ProjectPaths {
					pats = append(pats, joinLogical(project, strings.TrimPrefix(pp, "./")))
				}
				scope = event.ScopeProject
			} else {
				for _, f := range m.Paths.For(s.goos) {
					home := isHomePath(f)
					if (uc == nil) == home {
						continue
					}
					if e, ok := s.expand(f, uc); ok {
						pats = append(pats, e)
					}
				}
			}
			for _, pat := range pats {
				for _, f := range s.glob(pat, uc, project, 512) {
					if s.g.isDir(s.locFor(f, uc, project)) {
						continue
					}
					site := byPath[f]
					if site == nil {
						site = &mcpSite{path: f, format: m.Format, scope: scope}
						byPath[f] = site
						order = append(order, f)
					}
					site.readers = appendIdx(site.readers, i)
				}
			}
		}
	}
	if project != "" {
		// .code-workspace files carry MCP servers under "settings".
		if ents, err := s.g.readDir(loc{root: project, user: true}); err == nil {
			for _, e := range ents {
				if e.kind == kindRegular && strings.HasSuffix(strings.ToLower(e.name), ".code-workspace") {
					f := joinLogical(project, e.name)
					if byPath[f] == nil {
						site := &mcpSite{path: f, format: string(mcpconf.FormatVSCode), scope: event.ScopeProject}
						if vi, ok := s.byID["vscode"]; ok {
							site.readers = []int{vi}
						}
						byPath[f] = site
						order = append(order, f)
					}
				}
			}
		}
	}
	out := make([]*mcpSite, 0, len(order))
	for _, f := range order {
		site := byPath[f]
		sortReaders(s, site.readers)
		out = append(out, site)
	}
	return out
}

func appendIdx(l []int, i int) []int {
	for _, x := range l {
		if x == i {
			return l
		}
	}
	return append(l, i)
}

// sortReaders puts agents first, then catalog order, so the reported parent
// is the product that executes what the server returns.
func sortReaders(s *scanner, r []int) {
	rank := func(i int) int {
		if s.products[i].Kind == string(event.AssetAgent) {
			return 0
		}
		return 1
	}
	for a := 1; a < len(r); a++ {
		for b := a; b > 0 && (rank(r[b]) < rank(r[b-1]) || rank(r[b]) == rank(r[b-1]) && r[b] < r[b-1]); b-- {
			r[b], r[b-1] = r[b-1], r[b]
		}
	}
}

// scanMCPFiles parses every MCP config for the context and records one
// mcp_server asset per declared server.
func (s *scanner) scanMCPFiles(uc *userCtx, project string) {
	for _, site := range s.mcpSites(uc, project) {
		if !s.g.alive() {
			return
		}
		l := s.locFor(site.path, uc, project)
		owner := ""
		if site.scope != event.ScopeManaged && site.scope != event.ScopeSystem {
			owner = ownerFor(l, uc)
		}
		data, _, err := s.g.readFile(l, owner, maxConfigBytes)
		if err != nil {
			continue
		}
		servers, perr := mcpconf.Parse(site.path, data, mcpconf.Format(site.format))
		if perr != nil {
			s.led.errored()
			s.led.note("MCP config not fully read: " + homeRelNote(l) + ": " + perr.Error())
		}
		for _, srv := range servers {
			s.addMCP(site, srv, uc, project)
		}
	}
}

func (s *scanner) addMCP(site *mcpSite, srv mcpconf.Server, uc *userCtx, project string) {
	parent := s.products[site.readers[0]]
	norm := mcpconf.Normalize(srv)
	m := norm
	a := &event.Asset{
		Kind:      event.AssetMCPServer,
		Name:      safeText(srv.Name, 256),
		Parent:    parent.ID,
		Path:      safeText(site.path, 1024),
		Scope:     site.scope,
		SHA256:    mcpconf.DefinitionHash(srv),
		MCP:       &m,
		RiskFlags: mcpconf.RiskFlags(srv),
		Detail:    map[string]string{"format": site.format},
	}
	if srv.Project != "" {
		// Declared under projects.<path> in ~/.claude.json: local scope.
		a.Detail["project"] = safeText(srv.Project, 1024)
		if a.Scope == event.ScopeUser {
			a.Scope = event.ScopeProject
		}
	} else if project != "" {
		a.Detail["project"] = safeText(project, 1024)
	}
	if len(site.readers) > 1 {
		var ids []string
		for _, r := range site.readers[1:] {
			ids = append(ids, s.products[r].ID)
		}
		a.Detail["also_read_by"] = strings.Join(ids, ",")
	}
	if uc != nil {
		a.Owner = uc.u.Name
	}
	if s.untrustedLaunch(srv, uc) {
		a.RiskFlags = mergeFlags(a.RiskFlags, flagUntrustedLocation)
	}
	s.add(&record{a: a, uc: uc})
}

// knownToolDirs are hidden home directories where launchers and package
// managers legitimately keep executables.
var knownToolDirs = map[string]bool{
	".local": true, ".npm": true, ".nvm": true, ".cargo": true, ".bun": true, ".deno": true,
	".volta": true, ".pyenv": true, ".rbenv": true, ".asdf": true, ".config": true, ".rustup": true,
	".fnm": true, ".sdkman": true, ".pnpm": true, ".yarn": true, ".npm-global": true, ".linuxbrew": true,
	".docker": true, ".vscode": true, ".vscode-server": true, ".cursor": true, ".claude": true, ".codex": true,
	".gemini": true, ".copilot": true, ".windsurf": true, ".codeium": true, ".kiro": true, ".continue": true,
	".opencode": true, ".goose": true, ".mise": true, ".proto": true, ".jenv": true, ".gradle": true, ".m2": true,
	".dotnet": true, ".go": true, ".poetry": true, ".pixi": true, ".conda": true, ".miniconda3": true, ".anaconda3": true,
}

// untrustedLaunch reports a stdio server whose command or script lives in
// a temp or Downloads directory, or in a hidden directory under the home
// that is not a known tool directory: places malware stages payloads and
// users rarely look.
func (s *scanner) untrustedLaunch(srv mcpconf.Server, uc *userCtx) bool {
	cands := []string{srv.Command}
	for _, a := range srv.Args {
		if looksLikePath(a) {
			cands = append(cands, a)
		}
		if len(cands) > 16 {
			break
		}
	}
	ctx := classify.PathCtx{OS: s.goos}
	if uc != nil {
		ctx.Home = uc.home
	}
	for _, c := range cands {
		if c == "" || !looksLikePath(c) {
			continue
		}
		for _, cl := range classify.PathClasses(c, ctx) {
			if cl == classify.PathTemp || cl == classify.PathDownloads {
				return true
			}
		}
		if s.hiddenOutsideTools(c, uc) {
			return true
		}
	}
	return false
}

func looksLikePath(a string) bool {
	if a == "" || len(a) > 4096 || strings.HasPrefix(a, "-") || strings.Contains(a, "://") {
		return false
	}
	return strings.ContainsAny(a, `/\`) || strings.HasPrefix(a, "~")
}

func (s *scanner) hiddenOutsideTools(p string, uc *userCtx) bool {
	if uc == nil {
		return false
	}
	p = expandHomeRef(cleanLogical(p), uc.home)
	rel, ok := relLogical(uc.home, p, s.goos)
	if !ok || rel == "" {
		return false
	}
	first, _, _ := strings.Cut(rel, "/")
	if s.goos == "windows" {
		// Win32 path normalization drops trailing dots and spaces:
		// "%USERPROFILE%\.evil. \x.exe" runs from ".evil".
		first = strings.TrimRight(first, ". ")
		if first == "" {
			first = "."
		}
	}
	if !strings.HasPrefix(first, ".") || len(first) < 2 || first == ".." {
		return false
	}
	if knownToolDirs[strings.ToLower(first)] {
		return false
	}
	// A hidden directory that is some catalogued product's state directory
	// is a known tool directory too. The comparison is by whole element
	// (".c" is not ".claude"), case-folded where the filesystem folds case.
	for _, d := range s.stateDirHeads(uc) {
		if d == first || foldCase(s.goos) && strings.EqualFold(d, first) {
			return false
		}
	}
	return true
}

// stateDirHeads lists the first home-relative element of every catalogued
// state directory as expanded for the user (".claude", ".codex" ...).
func (s *scanner) stateDirHeads(uc *userCtx) []string {
	if uc.heads != nil {
		return uc.heads
	}
	seen := map[string]bool{}
	var out []string
	for i := range s.products {
		for _, sd := range s.products[i].StateDirs.For(s.goos) {
			e, ok := s.expand(sd, uc)
			if !ok {
				continue
			}
			rel, ok := relLogical(uc.home, e, s.goos)
			if !ok || rel == "" {
				continue
			}
			head, _, _ := strings.Cut(rel, "/")
			if strings.HasPrefix(head, ".") && !seen[head] {
				seen[head] = true
				out = append(out, head)
			}
		}
	}
	if out == nil {
		out = []string{}
	}
	uc.heads = out
	return out
}

// expandHomeRef resolves the spellings of "the user's home" at the start of
// a launch path (~, $HOME, ${HOME}, %USERPROFILE%, $env:USERPROFILE,
// ${env:USERPROFILE}), so a path written either way is classified alike.
// Matching ignores case: Windows variable names are case-insensitive.
func expandHomeRef(p, home string) string {
	if p == "~" {
		return home
	}
	if strings.HasPrefix(p, "~/") {
		return joinLogical(home, p[2:])
	}
	for _, v := range []string{"$HOME", "${HOME}", "%USERPROFILE%", "$env:USERPROFILE", "${env:USERPROFILE}", "%HOME%"} {
		if hasPrefixFold(p, v) {
			rest := p[len(v):]
			if rest == "" {
				return home
			}
			if rest[0] == '/' {
				return joinLogical(home, strings.TrimLeft(rest, "/"))
			}
		}
	}
	return p
}
