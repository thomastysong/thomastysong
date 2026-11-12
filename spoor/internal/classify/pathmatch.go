package classify

import (
	"path"
	"strings"
	"sync"
)

// Pattern syntax used by the rule tables (pathrules.go):
//
//	/etc/shadow        rooted at the filesystem (or drive) root
//	.ssh/config        these components, in this order, ending the path, at any depth
//	.gnupg/**          a directory at any depth: the directory itself and everything below
//	/etc/cron.d/**     a rooted directory and everything below
//	*.pem  id_*        wildcards within one component (path.Match syntax)
//
// "**" is only supported as the final component. Windows patterns are written
// without a drive letter and with forward slashes.

type osMask uint8

const (
	osAny     osMask = 0
	osLinux   osMask = 1 << iota // 2
	osDarwin                     // 4
	osWindows                    // 8
	osPosix   = osLinux | osDarwin
)

func maskFor(os string) osMask {
	switch os {
	case "windows":
		return osWindows
	case "darwin":
		return osDarwin
	}
	return osLinux
}

// ruleGroup is a list of patterns that assign one class.
type ruleGroup struct {
	class pathClass
	os    osMask // 0: every OS
	// ci makes the patterns case-insensitive on every OS. It is for names
	// whose meaning is a convention of tools rather than a location
	// ("*.PEM" is still a PEM file on Linux).
	ci bool
	// named: the last component of each pattern is the name the class is
	// about ("spoor" in /etc/spoor/**). An input wildcard with no literal
	// text there matches it only when the input names something literal
	// below it: "/etc/*/disabled" can reach /etc/spoor/disabled, while
	// "/usr/local/bin/*" and "/var/log/*" are about every name in the
	// directory.
	named bool
	pats  []string
}

type segPat struct {
	lit  string // as written
	low  string // lower-cased
	glob bool
}

type pathPat struct {
	class   pathClass
	os      osMask
	ci      bool
	named   bool
	rooted  bool
	subtree bool
	segs    []segPat
}

type patIndex struct {
	// byFirst holds patterns whose first component is a literal, keyed by its
	// lower-cased form: a path component is looked up once and only the few
	// patterns that could start there are verified.
	anyByFirst  map[string][]*pathPat
	rootByFirst map[string][]*pathPat
	// Patterns that start with a wildcard cannot be indexed.
	baseGlobs []*pathPat // single component, matched against the last component only
	anyGlobs  []*pathPat
	rootGlobs []*pathPat
	all       []*pathPat
}

var (
	patOnce sync.Once
	patIdx  *patIndex
)

func patterns() *patIndex {
	patOnce.Do(func() { patIdx = buildIndex(pathRules) })
	return patIdx
}

func buildIndex(groups []ruleGroup) *patIndex {
	idx := &patIndex{anyByFirst: map[string][]*pathPat{}, rootByFirst: map[string][]*pathPat{}}
	for _, g := range groups {
		for _, src := range g.pats {
			p := compilePattern(src)
			p.class, p.os, p.ci, p.named = g.class, g.os, g.ci, g.named
			idx.all = append(idx.all, p)
			first := p.segs[0]
			switch {
			case p.rooted && first.glob:
				idx.rootGlobs = append(idx.rootGlobs, p)
			case p.rooted:
				idx.rootByFirst[first.low] = append(idx.rootByFirst[first.low], p)
			case first.glob && len(p.segs) == 1 && !p.subtree:
				idx.baseGlobs = append(idx.baseGlobs, p)
			case first.glob:
				idx.anyGlobs = append(idx.anyGlobs, p)
			default:
				idx.anyByFirst[first.low] = append(idx.anyByFirst[first.low], p)
			}
		}
	}
	return idx
}

func compilePattern(src string) *pathPat {
	p := &pathPat{}
	s := src
	if strings.HasPrefix(s, "/") {
		p.rooted = true
		s = s[1:]
	}
	if strings.HasSuffix(s, "/**") {
		p.subtree = true
		s = s[:len(s)-3]
	}
	for _, part := range strings.Split(s, "/") {
		if part == "" || part == "**" {
			panic("classify: bad path pattern " + src)
		}
		glob := strings.ContainsAny(part, "*?[")
		if glob {
			if _, err := path.Match(part, ""); err != nil {
				panic("classify: bad glob in path pattern " + src)
			}
		}
		p.segs = append(p.segs, segPat{lit: part, low: strings.ToLower(part), glob: glob})
	}
	return p
}

// matchAt reports whether the pattern matches the path with its first
// component at index i.
func (p *pathPat) matchAt(lp *lexPath, i int, os osMask) bool {
	if p.os != osAny && p.os&os == 0 {
		return false
	}
	n := len(lp.segs)
	end := i + len(p.segs)
	if end > n || (!p.subtree && end != n) {
		return false
	}
	fold := lp.fold || p.ci
	strong := false
	for j := range p.segs {
		ok, firm := matchSeg(&p.segs[j], lp, i+j, fold)
		if !ok {
			return false
		}
		strong = strong || firm
		if p.named && j == len(p.segs)-1 && !firm && lp.wild[i+j] && !literalBelow(lp, end) {
			return false
		}
	}
	// A subtree match that continues below the pattern has matched every
	// pattern component against a directory name, which a bare "*" in the
	// input can do too; the firmness rule applies the same way.
	return strong
}

// matchSeg compares one pattern component with one path component. firm is
// false when the only reason for the match is a shell wildcard in the INPUT
// that carries no literal text ("*", "?"): "cat *" must not be classified as
// reading every well-known file name.
func matchSeg(sp *segPat, lp *lexPath, i int, fold bool) (ok, firm bool) {
	name, pat := lp.segs[i], sp.lit
	if fold {
		name, pat = lp.lsegs[i], sp.low
	}
	if !lp.wild[i] {
		if !sp.glob {
			return name == pat, true
		}
		m, _ := path.Match(pat, name)
		return m, true
	}
	// The input is itself a shell pattern: ask whether it COULD expand to a
	// name the rule matches.
	lit := literalLen(name)
	if !sp.glob {
		if name[0] != '.' && pat[0] == '.' {
			return false, false // shells do not expand "*" to dotfiles
		}
		m, _ := path.Match(name, pat)
		return m, lit >= 3
	}
	// Two patterns: nearly any pair CAN name a common file ("shad*" and
	// "*.ppk" both match "shad.ppk"), so compatibility alone would classify
	// every wildcard as everything. Require that the literal text of the two
	// agrees at the start or at the end.
	a, b := globPrefix(name), globPrefix(pat)
	as, bs := globSuffix(name), globSuffix(pat)
	if !strings.HasPrefix(a, b) && !strings.HasPrefix(b, a) {
		return false, false
	}
	if !strings.HasSuffix(as, bs) && !strings.HasSuffix(bs, as) {
		return false, false
	}
	if (a == "" || b == "") && (as == "" || bs == "") {
		return false, false
	}
	return true, lit >= 3
}

// literalBelow reports a component at index from or after it that holds
// no wildcard.
func literalBelow(lp *lexPath, from int) bool {
	for k := from; k < len(lp.segs); k++ {
		if !lp.wild[k] {
			return true
		}
	}
	return false
}

func literalLen(glob string) int {
	n := 0
	for i := 0; i < len(glob); i++ {
		if strings.IndexByte("*?[]", glob[i]) < 0 {
			n++
		}
	}
	return n
}

func globPrefix(g string) string {
	if i := strings.IndexAny(g, "*?["); i >= 0 {
		return g[:i]
	}
	return g
}

func globSuffix(g string) string {
	if i := strings.LastIndexAny(g, "*?]"); i >= 0 {
		return g[i+1:]
	}
	return g
}

// matchPatterns adds the class of every table pattern that matches lp.
func matchPatterns(lp *lexPath, os string, set *pathSet) {
	n := len(lp.segs)
	if n == 0 {
		return
	}
	idx := patterns()
	mask := maskFor(os)
	hasWild := false
	for _, w := range lp.wild {
		if w {
			hasWild = true
			break
		}
	}
	if hasWild {
		// Wildcards defeat the index; this path is rare, so scan everything.
		for _, p := range idx.all {
			if set.has(p.class) {
				continue
			}
			if p.rooted {
				if lp.abs && p.matchAt(lp, 0, mask) {
					set.add(p.class)
				}
				continue
			}
			for i := 0; i < n; i++ {
				if p.matchAt(lp, i, mask) {
					set.add(p.class)
					break
				}
			}
		}
		return
	}
	if lp.abs {
		for _, p := range idx.rootByFirst[lp.lsegs[0]] {
			if p.matchAt(lp, 0, mask) {
				set.add(p.class)
			}
		}
		for _, p := range idx.rootGlobs {
			if p.matchAt(lp, 0, mask) {
				set.add(p.class)
			}
		}
	}
	for i := 0; i < n; i++ {
		for _, p := range idx.anyByFirst[lp.lsegs[i]] {
			if p.matchAt(lp, i, mask) {
				set.add(p.class)
			}
		}
	}
	for _, p := range idx.baseGlobs {
		if p.matchAt(lp, n-1, mask) {
			set.add(p.class)
		}
	}
	for _, p := range idx.anyGlobs {
		if set.has(p.class) {
			continue
		}
		for i := 0; i < n; i++ {
			if p.matchAt(lp, i, mask) {
				set.add(p.class)
				break
			}
		}
	}
}
