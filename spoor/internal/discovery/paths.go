package discovery

import (
	"os"
	"sort"
	"strings"

	"github.com/thomastysong/spoor/internal/catalog"
	"github.com/thomastysong/spoor/internal/platform"
)

// userCtx is one home being scanned.
type userCtx struct {
	u    platform.UserHome
	home string            // cleaned logical home
	env  map[string]string // expansion environment (never emitted)
	// heads caches stateDirHeads for this user.
	heads []string
}

// windowsMachineVars are the machine-wide variables catalog paths use on
// Windows. They are the same for every user, so the daemon's own values are
// correct; per-user variables (APPDATA, LOCALAPPDATA ...) are never taken
// from the daemon's environment but derived from the scanned home by Expand.
var windowsMachineVars = map[string]string{
	"ProgramData":       `C:\ProgramData`,
	"ProgramFiles":      `C:\Program Files`,
	"ProgramFiles(x86)": `C:\Program Files (x86)`,
	"ProgramW6432":      `C:\Program Files`,
	"SystemDrive":       `C:`,
	"SystemRoot":        `C:\Windows`,
	"windir":            `C:\Windows`,
	"ALLUSERSPROFILE":   `C:\ProgramData`,
	"PUBLIC":            `C:\Users\Public`,
}

func machineEnv(goos string) map[string]string {
	out := map[string]string{}
	if goos != "windows" {
		return out
	}
	for k, def := range windowsMachineVars {
		v := os.Getenv(k)
		if v == "" || len(v) > 512 {
			v = def
		}
		out[k] = v
	}
	return out
}

// expand resolves a catalog path for a user (uc may be nil for system
// paths). It returns false for project-relative entries ("./..."), for
// paths that still hold an unresolved variable and for relative results:
// guessing a value would read the wrong file.
func (s *scanner) expand(p string, uc *userCtx) (string, bool) {
	if p == "" || strings.HasPrefix(p, "./") || strings.HasPrefix(p, `.\`) {
		return "", false
	}
	env := s.sysEnv
	home := ""
	if uc != nil {
		env = uc.env
		home = uc.home
	} else if strings.HasPrefix(p, "~") || strings.Contains(p, "$HOME") || strings.Contains(strings.ToUpper(p), "%USERPROFILE%") {
		return "", false
	}
	e := catalog.Expand(p, home, env, s.goos)
	if len(catalog.Unexpanded(e, s.goos)) > 0 {
		return "", false
	}
	e = cleanLogical(e)
	if !isAbsLogical(e) {
		return "", false
	}
	if uc != nil {
		// A catalogued location inside a personal directory (Cline keeps
		// its hooks under ~/Documents/Cline) may be read: the catalog, not
		// a crawl, points there.
		if rel, ok := relLogical(uc.home, e, s.goos); ok && isPersonalRel(rel) {
			s.g.allowPath(staticPrefix(e))
		}
	}
	return e, true
}

// isHomePath reports whether a catalog entry is relative to the user (it
// expands differently per home), as opposed to a machine-wide path.
func isHomePath(p string) bool {
	if strings.HasPrefix(p, "~") {
		return true
	}
	up := strings.ToUpper(p)
	for _, v := range []string{"$HOME", "${HOME", "%USERPROFILE%", "%APPDATA%", "%LOCALAPPDATA%", "$XDG_", "${XDG_"} {
		if strings.Contains(up, v) {
			return true
		}
	}
	// ${CLAUDE_CONFIG_DIR:-~/.claude} and friends: the default is in the home.
	return strings.Contains(p, ":-~")
}

func isAbsLogical(p string) bool {
	if strings.HasPrefix(p, "/") {
		return true
	}
	return len(p) >= 3 && p[1] == ':' && p[2] == '/'
}

// locFor confines a logical path to the most specific known root: the
// project directory, then the user's home, then (for system paths) its
// parent directory.
func (s *scanner) locFor(full string, uc *userCtx, project string) loc {
	if project != "" {
		if rel, ok := relLogical(project, full, s.goos); ok {
			return loc{root: cleanLogical(project), rel: rel, user: true, uid: uidOf(uc)}
		}
	}
	if uc != nil && uc.home != "" {
		if rel, ok := relLogical(uc.home, full, s.goos); ok {
			return loc{root: uc.home, rel: rel, home: true, user: true, uid: uc.u.UID}
		}
		// A user-context path outside the home came from the user's own
		// data (a relocated state directory in their environment, a path in
		// their agent state): it is read only if the user owns the file.
		l := systemLoc(full)
		l.user, l.uid = true, uc.u.UID
		return l
	}
	return systemLoc(full)
}

// projectRoot is the location of a project directory itself.
func projectRoot(dir string, uc *userCtx) loc {
	return loc{root: cleanLogical(dir), user: true, uid: uidOf(uc)}
}

func uidOf(uc *userCtx) string {
	if uc == nil {
		return ""
	}
	return uc.u.UID
}

// ownerFor is the uid a file at l must belong to when the scan is
// privileged: the user's, for anything in their home or project; none for
// system files (their ownership is reported as posture instead).
func ownerFor(l loc, uc *userCtx) string {
	if uc == nil || !l.user {
		return ""
	}
	return uc.u.UID
}

func hasWild(s string) bool { return strings.ContainsAny(s, "*?") }

// staticPrefix is the part of a glob before its first wildcard element.
func staticPrefix(p string) string {
	if !hasWild(p) {
		return p
	}
	comps := strings.Split(p, "/")
	for i, c := range comps {
		if hasWild(c) {
			return strings.Join(comps[:i], "/")
		}
	}
	return p
}

// glob expands a catalog glob (already variable-expanded) to existing
// paths, walking only below the static prefix of the pattern. "*" and "?"
// stay within one element and "**" crosses up to maxWalkDepth elements.
// limit stops the walk early (0 means maxGlobMatches).
func (s *scanner) glob(pattern string, uc *userCtx, project string, limit int) []string {
	if limit <= 0 || limit > maxGlobMatches {
		limit = maxGlobMatches
	}
	pattern = cleanLogical(pattern)
	if !hasWild(pattern) {
		if s.g.exists(s.locFor(pattern, uc, project)) {
			return []string{pattern}
		}
		return nil
	}
	comps := strings.Split(pattern, "/")
	i := 0
	for i < len(comps) && !hasWild(comps[i]) {
		i++
	}
	static := strings.Join(comps[:i], "/")
	if static == "" {
		static = "/"
	}
	if len(static) == 2 && static[1] == ':' {
		static += "/"
	}
	cur := []string{static}
	rest := comps[i:]
	for j, c := range rest {
		last := j == len(rest)-1
		var next []string
		switch {
		case c == "**":
			for _, d := range cur {
				next = append(next, d)
				next = append(next, s.descendants(d, uc, project, limit*4)...)
			}
		case hasWild(c):
			for _, d := range cur {
				ents, err := s.g.readDir(s.locFor(d, uc, project))
				if err != nil {
					continue
				}
				for _, e := range ents {
					if !last && e.kind != kindDir {
						continue
					}
					if matchElem(c, e.name, foldCase(s.goos)) {
						next = append(next, joinLogical(d, e.name))
					}
				}
			}
		default:
			for _, d := range cur {
				next = append(next, joinLogical(d, c))
			}
		}
		cur = dedupe(next)
		if len(cur) == 0 || !s.g.alive() {
			return nil
		}
		if len(cur) > limit*4 {
			cur = cur[:limit*4]
			s.globCapped(pattern, limit)
		}
	}
	var out []string
	for i, p := range cur {
		if s.g.exists(s.locFor(p, uc, project)) {
			out = append(out, p)
			if len(out) >= limit {
				if i < len(cur)-1 {
					s.globCapped(pattern, limit)
				}
				break
			}
		}
	}
	return out
}

// globCapped records a glob cut short by its limit. A limit of one asks
// whether anything matches at all, which is not a cut.
func (s *scanner) globCapped(pattern string, limit int) {
	if limit > 1 {
		s.led.capped("matches truncated at " + itoa(limit) + ": " + pattern)
	}
}

// descendants lists every directory below d (links not followed), breadth
// first, to maxWalkDepth.
func (s *scanner) descendants(d string, uc *userCtx, project string, limit int) []string {
	var out []string
	level := []string{d}
	for depth := 0; depth < maxWalkDepth && len(level) > 0; depth++ {
		var next []string
		for _, dir := range level {
			ents, err := s.g.readDir(s.locFor(dir, uc, project))
			if err != nil {
				continue
			}
			for _, e := range ents {
				if e.kind == kindDir && !skipDirName(e.name) {
					p := joinLogical(dir, e.name)
					next = append(next, p)
					out = append(out, p)
					if len(out) >= limit {
						s.led.capped("directory walk truncated: " + d)
						return out
					}
				}
			}
		}
		level = next
	}
	return out
}

// skipDirName prunes dependency caches and VCS internals from ** walks:
// they are large and never hold an agent's own configuration.
func skipDirName(n string) bool {
	switch n {
	case "node_modules", ".git", "__pycache__", ".venv", "venv", "site-packages", ".cache", "vendor", ".gradle", ".m2", "target", "dist", "build":
		return true
	}
	return false
}

// matchElem matches one path element against a pattern with * and ?.
// Character classes are taken literally, as the catalog documents.
func matchElem(pattern, name string, fold bool) bool {
	if fold {
		pattern, name = strings.ToLower(pattern), strings.ToLower(name)
	}
	// Iterative wildcard match with backtracking on the last star.
	p, n := 0, 0
	star, mark := -1, 0
	for n < len(name) {
		switch {
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == name[n]):
			p++
			n++
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, n
			p++
		case star >= 0:
			p = star + 1
			mark++
			n = mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

func dedupe(in []string) []string {
	if len(in) < 2 {
		return in
	}
	seen := make(map[string]bool, len(in))
	out := in[:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// baseName returns the last element of a logical path.
func baseName(p string) string {
	p = strings.TrimSuffix(cleanLogical(p), "/")
	if i := strings.LastIndexByte(p, '/'); i >= 0 {
		return p[i+1:]
	}
	return p
}

// dirName returns the parent of a logical path.
func dirName(p string) string {
	p = cleanLogical(p)
	i := strings.LastIndexByte(p, '/')
	switch {
	case i < 0:
		return ""
	case i == 0:
		return "/"
	case i == 2 && p[1] == ':':
		return p[:3]
	}
	return p[:i]
}
