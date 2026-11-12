package privacy

import (
	"regexp"
	"strings"
	"sync"
)

// Home-relative paths. A path under the acting user's home carries the
// account name (and often a client or project name next to it); "~/..."
// keeps what detection and triage need. Matching folds case on macOS and
// Windows, treats "/" and "\" (and doubled "\\" from escaped strings) as
// the same separator, and requires a boundary on both sides so
// "/home/bobby" is not rewritten for user "bob".

type homeRewriter struct {
	comps   []string // home path components; comps[0] == "" for an absolute POSIX path
	fold    bool
	others  func(name string) string // pseudonym for other users' homes, or nil
	enabled bool
}

func newHomeRewriter(home, goos string, others func(string) string) *homeRewriter {
	h := &homeRewriter{fold: goos == "darwin" || goos == "windows", others: others}
	if usableHome(home) {
		norm := strings.TrimRight(strings.ReplaceAll(home, `\`, "/"), "/")
		h.comps = strings.Split(norm, "/")
		h.enabled = true
	}
	return h
}

func isNameByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-'
}

func isSep(c byte) bool { return c == '/' || c == '\\' }

// matchAt reports the end of a home-directory match starting at i.
func (h *homeRewriter) matchAt(s string, i int) (int, bool) {
	j := i
	for k, comp := range h.comps {
		// A separator run ("/", "\", "\\") precedes every component except
		// the first, and the empty first component of a POSIX path is the
		// leading separator itself.
		if k == 0 && comp == "" || k > 1 || k == 1 && h.comps[0] != "" {
			n := 0
			for j < len(s) && isSep(s[j]) && n < 2 {
				j++
				n++
			}
			if n == 0 {
				return 0, false
			}
			if comp == "" {
				continue
			}
		}
		if j+len(comp) > len(s) {
			return 0, false
		}
		seg := s[j : j+len(comp)]
		if seg != comp && !(h.fold && strings.EqualFold(seg, comp)) {
			return 0, false
		}
		j += len(comp)
	}
	if j < len(s) && isNameByte(s[j]) {
		return 0, false // "/home/bobby" is not "/home/bob"
	}
	return j, true
}

// rewrite replaces the acting user's home with "~" and, when pseudonyms
// are on, other users' account names in home paths with "~u_...".
func (h *homeRewriter) rewrite(s string) string {
	if h == nil || s == "" {
		return s
	}
	if h.enabled && h.mayContain(s) {
		var b strings.Builder
		last := 0
		for i := 0; i < len(s); i++ {
			if i > 0 && (isNameByte(s[i-1]) || strings.IndexByte("~$%", s[i-1]) >= 0) {
				continue
			}
			end, ok := h.matchAt(s, i)
			if !ok {
				continue
			}
			if b.Len() == 0 && last == 0 {
				b.Grow(len(s))
			}
			b.WriteString(s[last:i])
			b.WriteByte('~')
			last = end
			i = end - 1
		}
		if last > 0 {
			b.WriteString(s[last:])
			s = b.String()
		}
	}
	if h.others != nil {
		s = rewriteOtherHomes(s, h.others)
	}
	return s
}

// mayContain is a cheap pre-check: the last component (the account name)
// must occur in s.
func (h *homeRewriter) mayContain(s string) bool {
	last := h.comps[len(h.comps)-1]
	if last == "" {
		return false
	}
	if strings.Contains(s, last) {
		return true
	}
	return h.fold && strings.Contains(strings.ToLower(s), strings.ToLower(last))
}

var (
	otherHomeOnce sync.Once
	otherHomeRe   *regexp.Regexp
)

// skipHomes are shared profile directories, not people.
var skipHomes = map[string]bool{
	"shared": true, "public": true, "default": true, "default user": true,
	"all users": true, "defaultaccount": true, "guest": true,
}

// rewriteOtherHomes pseudonymizes the account component of
// /home/<name>, /Users/<name> and X:\Users\<name> paths.
func rewriteOtherHomes(s string, pseudo func(string) string) string {
	if !strings.Contains(strings.ToLower(s), "home") && !strings.Contains(strings.ToLower(s), "users") {
		return s
	}
	otherHomeOnce.Do(func() {
		otherHomeRe = regexp.MustCompile(`(?i)(?:^|[^A-Za-z0-9._~$%-])((?:[A-Za-z]:)?[\\/]{1,2}(?:home|users)[\\/]{1,2})([^\\/\s"'` + "`" + `:;|&<>(),=\[\]{}*?]{1,64})`)
	})
	locs := otherHomeRe.FindAllStringSubmatchIndex(s, -1)
	if locs == nil {
		return s
	}
	var b strings.Builder
	last := 0
	for _, loc := range locs {
		nameStart, nameEnd := loc[4], loc[5]
		prefStart := loc[2]
		name := s[nameStart:nameEnd]
		if skipHomes[strings.ToLower(name)] || strings.HasPrefix(name, "u_") {
			continue
		}
		p := pseudo(name)
		if p == "" {
			continue
		}
		b.WriteString(s[last:prefStart])
		b.WriteString("~")
		b.WriteString(p)
		last = nameEnd
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}
