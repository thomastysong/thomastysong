package privacy

import (
	"errors"
	"path"
	"strings"

	"github.com/thomastysong/thomastysong/hawkbell/internal/classify"
	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// Exclusions are evaluated before any content processing, on identity
// fields only (working directory, repository root and remote, account), so
// an excluded session's prompts and commands are never inspected by this
// package. Health records are the sensor's own and are never excluded.
//
// Glob syntax: "*", "?" and "[...]" match within one path segment, "**"
// matches any number of segments, a leading "~/" is the acting user's
// home. A pattern names a directory tree: "/work/clients" also excludes
// "/work/clients/acme/src". A pattern that is not anchored ("/", "~",
// "C:\", "**") matches at any depth, as if prefixed by "**/".

const (
	maxGlobSegs = 64
	maxPathSegs = 256
)

// Excluded reports whether e belongs to an excluded path, repository or
// user. Callers drop such events before any content processing and count
// them.
func (p *Policy) Excluded(e *event.Event) (excluded bool) {
	if p == nil || e == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			// A matcher bug must not turn exclusion off for this event:
			// failing towards "excluded" drops one record, failing the
			// other way processes content the operator opted out of.
			excluded = true
		}
	}()
	if e.Kind == event.KindHealth {
		return false
	}
	ex := p.Exclude
	if len(ex.Paths) == 0 && len(ex.Repos) == 0 && len(ex.Users) == 0 {
		return false
	}
	goos := eventOS(e)
	fold := goos == "darwin" || goos == "windows"
	if len(ex.Users) > 0 {
		for _, u := range userCandidates(e) {
			if matchUser(ex.Users, u) {
				return true
			}
		}
	}
	if len(ex.Paths) > 0 {
		home := p.homeOf(actingUser(e), goos)
		for _, dir := range pathCandidates(e) {
			for _, g := range ex.Paths {
				if matchPathGlob(g, dir, home, fold) {
					return true
				}
			}
		}
	}
	if len(ex.Repos) > 0 && e.Repo != nil && e.Repo.Remote != "" {
		remote := normalizeRemote(e.Repo.Remote)
		for _, g := range ex.Repos {
			if matchRepoGlob(g, remote) {
				return true
			}
		}
	}
	return false
}

func userCandidates(e *event.Event) []string {
	var out []string
	add := func(s string) {
		if s != "" {
			out = append(out, s)
		}
	}
	if e.User != nil {
		add(e.User.Name)
		add(e.User.ID)
	}
	if e.Process != nil {
		add(e.Process.User)
	}
	if e.Asset != nil {
		add(e.Asset.Owner)
	}
	if e.Check != nil {
		add(e.Check.Owner)
	}
	return out
}

func pathCandidates(e *event.Event) []string {
	var out []string
	if e.Session != nil && e.Session.CWD != "" {
		out = append(out, e.Session.CWD)
	}
	if e.Repo != nil && e.Repo.Root != "" {
		out = append(out, e.Repo.Root)
	}
	// Project-scoped declarations live inside the project tree.
	if e.Asset != nil && e.Asset.Scope == event.ScopeProject && e.Asset.Path != "" {
		out = append(out, e.Asset.Path)
	}
	if e.Check != nil && e.Check.Scope == event.ScopeProject && e.Check.Subject != "" {
		out = append(out, e.Check.Subject)
	}
	return out
}

// matchUser matches account names case-insensitively (Windows and macOS
// names are; on Linux a case-insensitive match can only exclude more).
// "DOMAIN\user" also matches on its user part.
func matchUser(globs []string, u string) bool {
	cands := []string{strings.ToLower(u)}
	if i := strings.LastIndexByte(u, '\\'); i >= 0 && i < len(u)-1 {
		cands = append(cands, strings.ToLower(u[i+1:]))
	}
	for _, g := range globs {
		// "DOMAIN\user": the backslash is a literal, not a glob escape.
		g = strings.ReplaceAll(strings.ToLower(strings.TrimSpace(g)), `\`, `\\`)
		if g == "" {
			continue
		}
		for _, c := range cands {
			if ok, err := path.Match(g, c); err == nil && ok {
				return true
			}
		}
	}
	return false
}

func checkGlob(g string) error {
	if strings.TrimSpace(g) == "" {
		return errors.New("empty pattern")
	}
	for _, seg := range strings.Split(strings.ReplaceAll(g, `\`, "/"), "/") {
		if seg == "**" {
			continue
		}
		if _, err := path.Match(seg, ""); err != nil {
			return err
		}
	}
	return nil
}

// normPath turns a path into "/"-separated segments: backslashes become
// slashes, runs of separators collapse, "." segments go and ".." pops.
func normPath(p string, fold bool) []string {
	p = strings.ReplaceAll(p, `\`, "/")
	if fold {
		p = strings.ToLower(p)
	}
	var segs []string
	for _, s := range strings.Split(p, "/") {
		switch s {
		case "", ".":
			continue
		case "..":
			if len(segs) > 0 {
				segs = segs[:len(segs)-1]
			}
			continue
		}
		segs = append(segs, s)
		if len(segs) > maxPathSegs {
			break
		}
	}
	return segs
}

// matchPathGlob reports whether glob g names dir or one of its ancestors.
func matchPathGlob(g, dir, home string, fold bool) bool {
	g = strings.TrimSpace(g)
	if g == "" || dir == "" {
		return false
	}
	switch {
	case g == "~" || strings.HasPrefix(g, "~/") || strings.HasPrefix(g, `~\`):
		if home == "" {
			return false
		}
		g = home + "/" + g[1:]
	case strings.HasPrefix(g, "/") || strings.HasPrefix(g, `\`) || strings.HasPrefix(g, "**"):
	case len(g) >= 2 && g[1] == ':':
	default:
		g = "**/" + g
	}
	// Collapse dot segments in the pattern but keep "**".
	pat := normPath(g, fold)
	if len(pat) > maxGlobSegs {
		return false
	}
	return matchSegs(pat, normPath(dir, fold), true)
}

// matchSegs matches pattern segments against path segments; with prefix
// the pattern may stop before the path does (directory-tree semantics).
// Dynamic programming over (pattern, path) positions keeps "**" linear in
// the product of the lengths instead of exponential.
func matchSegs(pat, segs []string, prefix bool) bool {
	n, m := len(pat), len(segs)
	// ok[i][j]: pat[i:] matches segs[j:]
	ok := make([][]bool, n+1)
	for i := range ok {
		ok[i] = make([]bool, m+1)
	}
	for j := 0; j <= m; j++ {
		ok[n][j] = prefix || j == m
	}
	for i := n - 1; i >= 0; i-- {
		for j := m; j >= 0; j-- {
			if pat[i] == "**" {
				v := ok[i+1][j]
				if !v && j < m {
					v = ok[i][j+1]
				}
				ok[i][j] = v
				continue
			}
			if j == m {
				continue
			}
			if matched, err := path.Match(pat[i], segs[j]); err == nil && matched {
				ok[i][j] = ok[i+1][j+1]
			}
		}
	}
	return ok[0][0]
}

// normalizeRemote reduces a git remote to "host/owner/repo" in lower case:
// no scheme, credentials, port or ".git" suffix, so one pattern matches the
// HTTPS, SSH and scp forms of the same repository.
func normalizeRemote(raw string) string {
	s := strings.TrimSpace(raw)
	if i := strings.Index(s, "://"); i > 0 && i < 32 {
		host := classify.URLHost(s)
		rest := s[i+3:]
		if j := strings.IndexAny(rest, "/"); j >= 0 {
			rest = rest[j:]
		} else {
			rest = ""
		}
		s = host + rest
	} else if at := strings.IndexByte(s, '@'); at >= 0 && strings.IndexByte(s[at:], ':') > 0 && !strings.Contains(s[:at], "/") {
		// scp form: user@host:owner/repo
		rest := s[at+1:]
		c := strings.IndexByte(rest, ':')
		s = rest[:c] + "/" + strings.TrimLeft(rest[c+1:], "/")
	} else if c := strings.IndexByte(s, ':'); c > 1 && !strings.Contains(s[:c], "/") && !strings.HasPrefix(s[c:], `:\`) {
		// host:owner/repo
		s = s[:c] + "/" + strings.TrimLeft(s[c+1:], "/")
	}
	if q := strings.IndexAny(s, "?#"); q >= 0 {
		s = s[:q]
	}
	s = strings.ToLower(strings.TrimRight(strings.ReplaceAll(s, `\`, "/"), "/"))
	s = strings.TrimSuffix(s, ".git")
	return s
}

// matchRepoGlob matches a repository pattern against a normalized remote.
// Patterns are normalized the same way, so "github.com/acme/*",
// "git@github.com:acme/secret.git" and "acme/secret" all work.
func matchRepoGlob(g, remote string) bool {
	g = strings.TrimSpace(g)
	if g == "" || remote == "" {
		return false
	}
	ng := normalizeRemote(g)
	if strings.Contains(g, "*") && !strings.Contains(g, "://") {
		// Normalization must not eat glob characters.
		ng = strings.ToLower(strings.TrimSuffix(strings.TrimRight(strings.ReplaceAll(g, `\`, "/"), "/"), ".git"))
		if at := strings.IndexByte(ng, '@'); at >= 0 && strings.IndexByte(ng[at:], ':') > 0 {
			rest := ng[at+1:]
			c := strings.IndexByte(rest, ':')
			ng = rest[:c] + "/" + rest[c+1:]
		}
	}
	pat := normPath(ng, false)
	if len(pat) == 0 || len(pat) > maxGlobSegs {
		return false
	}
	if !strings.Contains(pat[0], ".") && pat[0] != "**" && !strings.ContainsAny(pat[0], "*?[") {
		// No host in the pattern: "acme/secret" matches on any host.
		pat = append([]string{"**"}, pat...)
	}
	return matchSegs(pat, normPath(remote, false), true)
}
