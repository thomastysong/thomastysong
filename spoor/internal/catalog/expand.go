package catalog

import (
	"runtime"
	"strings"
)

// Limits for Expand. The environment usually belongs to an agent process,
// so a value is attacker-controlled: an over-long or NUL-carrying value is
// treated as unset rather than spliced into a path.
const (
	maxExpandInput = 8 << 10
	maxVarValue    = 4 << 10
	maxVarName     = 128
)

// Expand resolves "~", $VAR, ${VAR}, ${VAR:-default} and (for windows)
// %VAR% in a catalog path without touching the filesystem.
//
//   - home is the home directory of the user being inspected. It always wins
//     for "~", $HOME and %USERPROFILE%, so a root daemon walking /home/* is
//     never redirected by its own environment.
//   - env is the environment to resolve other variables from; nil is fine.
//     Variables that only depend on the home (XDG_CONFIG_HOME, APPDATA,
//     LOCALAPPDATA ...) fall back to their conventional location under home
//     when env does not set them. Windows variable names are matched
//     case-insensitively.
//   - A variable that cannot be resolved is left in the output verbatim. The
//     alternative, substituting the empty string, would turn
//     "$CODEX_HOME/sessions" into "/sessions". Use Unexpanded to detect the
//     leftovers and skip the path.
//   - Expansion is a single pass: values are never re-expanded.
//   - For goos "windows" forward slashes become backslashes, so one pattern
//     ("~/.claude/settings.json") serves every OS. goos "" means the running
//     OS.
func Expand(p string, home string, env map[string]string, goos string) (out string) {
	// A panic here would take down whichever collector called us; returning
	// the input unexpanded makes the caller skip the path instead.
	defer func() {
		if r := recover(); r != nil {
			out = p
		}
	}()
	if goos == "" {
		goos = runtime.GOOS
	}
	if len(p) > maxExpandInput || strings.IndexByte(p, 0) >= 0 {
		return p
	}
	x := expander{home: cleanValue(home), env: env, windows: goos == "windows"}
	out = x.expand(p, 0)
	if x.windows {
		out = toBackslashes(out)
	}
	return out
}

// Unexpanded returns the names of the variables (and "~" for an unresolved
// home) still present in a string returned by Expand. A non-empty result
// means the path must not be used.
func Unexpanded(p string, goos string) []string {
	if goos == "" {
		goos = runtime.GOOS
	}
	var out []string
	if p == "~" || strings.HasPrefix(p, "~/") || strings.HasPrefix(p, `~\`) {
		out = append(out, "~")
	}
	x := expander{windows: goos == "windows", collect: &out}
	x.expand(p, 0)
	return out
}

type expander struct {
	home    string
	env     map[string]string
	windows bool
	// collect, when set, records variable names instead of resolving them.
	collect *[]string
}

func (x *expander) expand(p string, depth int) string {
	var b strings.Builder
	b.Grow(len(p) + 32)
	i := 0
	// "~" is the home only as the whole first path element; "~user" and a
	// tilde inside a name ("file~1") are left alone.
	if strings.HasPrefix(p, "~") && (len(p) == 1 || p[1] == '/' || p[1] == '\\') {
		if x.home != "" && x.collect == nil {
			b.WriteString(x.home)
		} else {
			b.WriteByte('~')
		}
		i = 1
	}
	for i < len(p) {
		c := p[i]
		switch {
		case c == '$' && i+1 < len(p) && p[i+1] == '{':
			end := matchBrace(p, i+1)
			if end < 0 {
				b.WriteByte(c)
				i++
				continue
			}
			body := p[i+2 : end]
			name, def, hasDef := strings.Cut(body, ":-")
			if !validVarName(name) {
				b.WriteString(p[i : end+1])
				i = end + 1
				continue
			}
			if x.collect != nil {
				if !hasDef {
					*x.collect = append(*x.collect, name)
				}
			} else if v, ok := x.lookup(name); ok {
				b.WriteString(v)
			} else if hasDef && depth < 2 {
				// The default is catalog text, not environment data, so it
				// may itself start with "~" or name another variable.
				b.WriteString(x.expand(def, depth+1))
			} else {
				b.WriteString(p[i : end+1])
			}
			i = end + 1
		case c == '$':
			j := i + 1
			for j < len(p) && isVarChar(p[j], j == i+1) {
				j++
			}
			name := p[i+1 : j]
			if name == "" {
				b.WriteByte(c)
				i++
				continue
			}
			if x.collect != nil {
				*x.collect = append(*x.collect, name)
				i = j
				continue
			}
			if v, ok := x.lookup(name); ok {
				b.WriteString(v)
			} else {
				b.WriteString(p[i:j])
			}
			i = j
		case c == '%' && x.windows:
			j := strings.IndexByte(p[i+1:], '%')
			if j <= 0 {
				b.WriteByte(c)
				i++
				continue
			}
			name := p[i+1 : i+1+j]
			if !validWinVarName(name) {
				b.WriteByte(c)
				i++
				continue
			}
			if x.collect != nil {
				*x.collect = append(*x.collect, name)
			} else if v, ok := x.lookup(name); ok {
				b.WriteString(v)
			} else {
				b.WriteString(p[i : i+j+2])
			}
			i += j + 2
		default:
			b.WriteByte(c)
			i++
		}
	}
	return b.String()
}

// lookup resolves one variable: the explicit home first, then env, then the
// conventional home-relative default.
func (x *expander) lookup(name string) (string, bool) {
	key := name
	if x.windows {
		key = strings.ToUpper(name)
	}
	if x.home != "" {
		if key == "HOME" || (x.windows && key == "USERPROFILE") {
			return x.home, true
		}
	}
	if v, ok := x.envGet(name); ok {
		return v, true
	}
	if x.windows {
		switch key {
		case "APPDATA":
			return x.underHome(`AppData\Roaming`)
		case "LOCALAPPDATA":
			return x.underHome(`AppData\Local`)
		case "PROGRAMDATA", "ALLUSERSPROFILE":
			return `C:\ProgramData`, true
		case "PROGRAMFILES", "PROGRAMW6432":
			return `C:\Program Files`, true
		case "PROGRAMFILES(X86)":
			return `C:\Program Files (x86)`, true
		case "SYSTEMDRIVE":
			return "C:", true
		case "SYSTEMROOT", "WINDIR":
			return `C:\Windows`, true
		}
	}
	// The XDG defaults apply on Windows too: tools built on xdg-basedir
	// (opencode, Kilo) use ~/.config and ~/.local/share there.
	switch key {
	case "XDG_CONFIG_HOME":
		return x.underHome(".config")
	case "XDG_DATA_HOME":
		return x.underHome(".local/share")
	case "XDG_STATE_HOME":
		return x.underHome(".local/state")
	case "XDG_CACHE_HOME":
		return x.underHome(".cache")
	}
	return "", false
}

func (x *expander) underHome(rel string) (string, bool) {
	if x.home == "" {
		return "", false
	}
	if x.windows {
		rel = toBackslashes(rel)
		return strings.TrimRight(x.home, `/\`) + `\` + rel, true
	}
	return strings.TrimRight(x.home, "/") + "/" + rel, true
}

func (x *expander) envGet(name string) (string, bool) {
	if x.env == nil {
		return "", false
	}
	if v, ok := x.env[name]; ok {
		v = cleanValue(v)
		return v, v != ""
	}
	if !x.windows {
		return "", false
	}
	// Windows variable names are case-insensitive but the map we are given
	// keeps whatever case the process used.
	for k, v := range x.env {
		if strings.EqualFold(k, name) {
			v = cleanValue(v)
			return v, v != ""
		}
	}
	return "", false
}

// cleanValue rejects values that cannot be part of a path. An empty result
// means "treat as unset".
func cleanValue(v string) string {
	if len(v) > maxVarValue || strings.ContainsAny(v, "\x00\n\r") {
		return ""
	}
	return v
}

func matchBrace(p string, open int) int {
	// p[open] == '{'. Braces do not nest in the syntax we accept except
	// inside a ":-default", where one nested ${...} is allowed.
	depth := 0
	for i := open; i < len(p); i++ {
		switch p[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func isVarChar(c byte, first bool) bool {
	if c == '_' || (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') {
		return true
	}
	return !first && c >= '0' && c <= '9'
}

func validVarName(s string) bool {
	if s == "" || len(s) > maxVarName {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isVarChar(s[i], i == 0) {
			return false
		}
	}
	return true
}

// validWinVarName also accepts the parentheses of "ProgramFiles(x86)".
func validWinVarName(s string) bool {
	if s == "" || len(s) > maxVarName {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !isVarChar(c, i == 0) && !(i > 0 && (c == '(' || c == ')')) {
			return false
		}
	}
	return true
}

// toBackslashes converts separators for Windows. A leading "//" stays a UNC
// prefix ("\\server\share") because both slashes are converted in place.
func toBackslashes(p string) string {
	if strings.IndexByte(p, '/') < 0 {
		return p
	}
	return strings.ReplaceAll(p, "/", `\`)
}
