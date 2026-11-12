package catalog

import (
	"regexp"
	"runtime"
	"strings"
)

// maxGlobLen bounds the patterns we compile; overlay files are administrator
// input but a typo should not become a megabyte regular expression.
const maxGlobLen = 1024

// MatchGlob reports whether a path matches a catalog glob in full. "*" and
// "?" stay within one path element, "**" crosses elements ("a/**/b" also
// matches "a/b"). Both separators are accepted in either argument. Matching
// ignores case for windows and darwin, whose default filesystems do. The
// pattern must already be expanded (see Expand); character classes are not
// supported and match literally. A path containing a ".." element never
// matches.
func MatchGlob(pattern, path, goos string) bool {
	if goos == "" {
		goos = runtime.GOOS
	}
	if len(pattern) > maxGlobLen || len(path) > 32<<10 {
		return false
	}
	// Matching is lexical, so "projects/*/x.jsonl" would accept
	// "projects/../x.jsonl", which names a file outside the tree the pattern
	// describes. A path that has not been cleaned never matches.
	if hasDotDotElement(path) {
		return false
	}
	re, err := regexp.Compile(globRegexp(pattern, goos != "linux", "^", "$"))
	if err != nil {
		return false
	}
	return re.MatchString(slashed(path))
}

// globRegexp translates a glob into RE2 source between the given anchors.
func globRegexp(pattern string, fold bool, prefix, suffix string) string {
	p := slashed(pattern)
	var b strings.Builder
	b.Grow(len(p)*2 + 16)
	if fold {
		b.WriteString("(?i)")
	}
	b.WriteString(prefix)
	for i := 0; i < len(p); i++ {
		c := p[i]
		switch c {
		case '*':
			if i+1 < len(p) && p[i+1] == '*' {
				// "**/" may match nothing, so "a/**/b" covers "a/b".
				if i+2 < len(p) && p[i+2] == '/' {
					b.WriteString("(?:.*/)?")
					i += 2
				} else {
					b.WriteString(".*")
					i++
				}
			} else {
				b.WriteString("[^/]*")
			}
		case '?':
			b.WriteString("[^/]")
		default:
			if strings.IndexByte(`\.+()|[]{}^$`, c) >= 0 {
				b.WriteByte('\\')
			}
			b.WriteByte(c)
		}
	}
	b.WriteString(suffix)
	return b.String()
}

// slashed normalizes separators so one matcher serves every OS. Backslash is
// a legal filename byte on POSIX but never appears in catalog paths, and
// treating it as a separator there only loosens evidence matching slightly.
func slashed(p string) string {
	if strings.IndexByte(p, '\\') < 0 {
		return p
	}
	return strings.ReplaceAll(p, `\`, "/")
}

// installPathRegexp compiles an InstallPaths entry into a matcher for
// executable paths. The entry is not expanded: the matcher has to work for
// any user's home, so a leading "~", $VAR, ${VAR...} or %VAR% element becomes
// "any directory prefix". A match means the executable is that path or lives
// underneath it.
//
// The match is lexical evidence, not proof: "~" stands for any directory, so
// a binary placed in /tmp/.local/bin/ earns the same credit as one in a real
// home. Code-signature checks are what turn evidence into identity.
func installPathRegexp(entry string) (*regexp.Regexp, error) {
	p := slashed(entry)
	anchored := true
	switch {
	case p == "~" || strings.HasPrefix(p, "~/"):
		p = strings.TrimPrefix(p, "~")
		anchored = false
	case strings.HasPrefix(p, "${"):
		if end := matchBrace(p, 1); end > 0 {
			p = p[end+1:]
			anchored = false
		}
	case strings.HasPrefix(p, "$"):
		if i := strings.IndexByte(p, '/'); i > 0 {
			p = p[i:]
			anchored = false
		}
	case strings.HasPrefix(p, "%"):
		if i := strings.IndexByte(p[1:], '%'); i > 0 {
			p = p[i+2:]
			anchored = false
		}
	}
	p = strings.TrimRight(p, "/")
	return regexp.Compile(globRegexp(p, true, installPrefix(p, anchored), "(?:/.*)?$"))
}

func installPrefix(p string, anchored bool) string {
	switch {
	case strings.HasPrefix(p, "/Applications/"):
		// Per-user installs of a macOS app live in ~/Applications with the
		// same bundle layout.
		return "^(?:/Users/[^/]+)?"
	case anchored:
		return "^"
	}
	return "^.*"
}

// bundleExecutableRegexp matches the main executable of a macOS app bundle
// named by an InstallPaths entry: <bundle>.app/Contents/MacOS/<file>. It
// returns nil for entries that are not app bundles.
//
// The main executable of a bundle is identity even when its file name is
// not: Visual Studio Code runs as "Electron". Helpers, bundled tools and
// anything deeper in the bundle do not match.
func bundleExecutableRegexp(entry string) (*regexp.Regexp, error) {
	p := strings.TrimRight(slashed(entry), "/")
	if !strings.HasSuffix(strings.ToLower(p), ".app") || !strings.HasPrefix(p, "/") {
		return nil, nil
	}
	return regexp.Compile(globRegexp(p, true, installPrefix(p, true), "/Contents/MacOS/[^/]+$"))
}
