// Package pathcanon computes the one lexical canonical form of a path that
// hawkbell's analysers emit and classify. It is purely lexical: no file is
// opened, no symlink resolved and no name looked up, because it runs in the
// hook process and on records shipped from other hosts.
//
// # The canonical form
//
//   - Separators are unified per style. A path is Windows-style when it
//     has a drive letter, a UNC or \\?\ / \\.\ / \??\ prefix, or when the
//     caller says the dialect is Windows (PowerShell, cmd.exe) and the path
//     contains a backslash. Windows-style paths accept both separators and
//     are written with backslashes; every other path separates on "/" only
//     (a backslash in a POSIX file name is an ordinary character).
//   - Duplicate separators are collapsed ("/etc//hawkbell" is "/etc/hawkbell"); a
//     trailing separator is dropped.
//   - "." segments are removed and ".." is resolved lexically. ".." at the
//     root stays at the root. A leading ".." of a relative path that cannot
//     be resolved stays, and so does ".." directly after an anchor whose
//     depth is unknown ("~", "$HOME", "%USERPROFILE%", any unresolved
//     variable or substitution) or after a segment holding an unresolved
//     expansion.
//   - A relative path is joined with Options.CWD first when the caller
//     knows the working directory (shellx tracks cd, pushd and
//     Set-Location on the command line). A home anchor followed by ".." is
//     replaced by Options.Home when that is an absolute path.
//   - On POSIX, /proc/<pid>/root, /proc/self/root, /proc/thread-self/root
//     and /proc/<pid>/task/<tid>/root are stripped wherever the walk reaches
//     them ("/proc/1/root/etc/x" is "/etc/x") and ProcRoot is reported:
//     naming a file through another process's root is a container-escape
//     signal in itself. /proc/self/cwd and /proc/thread-self/cwd become the
//     working directory.
//   - Windows forms are folded: \\?\C:\x and \??\C:\x are C:\x,
//     \\?\UNC\srv\share\x is \\srv\share\x, \\.\C:\x is C:\x, the drive
//     letter is upper-case, and ".." never climbs above a drive root or a
//     UNC share. The raw device namespace (\\.\PhysicalDrive0, \\.\C:,
//     \\.\pipe\x) is kept as written apart from separators.
//
// Case is kept. Linux file names are case-sensitive and evidence should
// read as the operand did; consumers that compare case-insensitively (the
// shellx classification form, classify on Windows and macOS, rules with
// (?i)) fold case themselves.
//
// URLs ("scheme://..."), process substitutions ("<(...)") and the empty
// string are returned unchanged. Glob characters and braces are ordinary
// characters, with one exception: when the caller says the glob is active
// (Options.Glob), a bracket expression that can match only one character
// is that character ("/etc/[h]awkbell" is "/etc/hawkbell"), because every shell
// expands it to exactly that name.
package pathcanon

import "strings"

// Flags report how a path was spelled.
type Flags uint8

const (
	// ProcRoot: the path went through /proc/<pid>/root (or self,
	// thread-self, a task's root), the root directory of a process.
	ProcRoot Flags = 1 << iota
)

// Options carry what the caller knows about the context.
type Options struct {
	// Windows says the dialect is Windows (PowerShell, cmd.exe), so a
	// backslash separates.
	Windows bool
	// CWD is the canonical working directory a relative path is joined
	// to, or "" when it is unknown. It may itself be relative ("sub", "..")
	// or anchored ("~/x").
	CWD string
	// Home is the absolute home directory, used only for a home anchor
	// followed by "..".
	Home string
	// Glob says glob characters in the path are active (an unquoted shell
	// word, a PowerShell -Path): a one-character bracket expression is then
	// replaced by its character.
	Glob bool
	// Posix says the path is a POSIX path whatever it looks like: a POSIX
	// shell on a host that is not Windows, where "a:" is an ordinary name
	// and not a drive or a PowerShell provider.
	Posix bool
	// Literal says the path holds no unresolved expansion: "$", "%" and
	// "`" in it are ordinary characters (a single-quoted shell word), so
	// ".." after them is resolved.
	Literal bool
}

// MaxLen is the longest input canonicalised; longer strings are returned
// unchanged.
const MaxLen = 32 << 10

// Clean returns the canonical form of p and how it was spelled.
func Clean(p string, o Options) (string, Flags) {
	if p == "" || len(p) > MaxLen || passThrough(p) {
		return p, 0
	}
	if canonicalPosix(p, o) {
		return p, 0
	}
	if simpleRel(p, o) {
		// A plain relative path: itself, or joined with a canonical
		// absolute working directory, without parsing either again.
		switch {
		case o.CWD == "":
			return p, 0
		case o.CWD == "/":
			if p != "proc" && !strings.HasPrefix(p, "proc/") {
				return "/" + p, 0
			}
		case canonicalPosix(o.CWD, Options{Windows: o.Windows, Posix: o.Posix}) && strings.IndexByte(o.CWD, '\\') < 0 &&
			o.CWD != "/proc" && !strings.HasPrefix(o.CWD, "/proc/"):
			return o.CWD + "/" + p, 0
		}
	}
	if o.Glob {
		p = collapseBrackets(p, IsWindows(p, o))
	}
	var fl Flags
	out := clean(p, o, &fl, 0)
	return out, fl
}

// canonicalPosix reports an absolute POSIX path that is already in
// canonical form, the common case, so it is returned without allocating.
func canonicalPosix(p string, o Options) bool {
	if p[0] != '/' || len(p) >= 2 && p[1] == '/' {
		return false
	}
	if o.Glob && strings.IndexByte(p, '[') >= 0 || o.Windows && !o.Posix && strings.IndexByte(p, '\\') >= 0 {
		return false
	}
	if strings.HasPrefix(p, "/proc/") || len(p) > 1 && p[len(p)-1] == '/' {
		return false
	}
	for i := 0; i+1 < len(p); i++ {
		if p[i] != '/' {
			continue
		}
		switch p[i+1] {
		case '/':
			return false
		case '.':
			// "/." or "/.." as a whole segment.
			r := p[i+2:]
			if r == "" || r[0] == '/' || r[0] == '.' && (len(r) == 1 || r[1] == '/') {
				return false
			}
		}
	}
	return true
}

// simpleRel reports a relative POSIX path that is already canonical and
// has no anchor: no empty, "." or ".." component, no trailing separator,
// no backslash, no colon, no leading "~", "$" or "%", no bracket to
// collapse, and nothing that reads as a Windows path.
func simpleRel(p string, o Options) bool {
	switch p[0] {
	case '/', '~', '$', '%', '\\', '<', '>':
		return false
	}
	if strings.ContainsAny(p, ":\\") || o.Glob && strings.IndexByte(p, '[') >= 0 || len(p) > 1 && p[len(p)-1] == '/' {
		return false
	}
	start := 0
	for i := 0; i <= len(p); i++ {
		if i < len(p) && p[i] != '/' {
			continue
		}
		switch p[start:i] {
		case "", ".", "..":
			return false
		}
		start = i + 1
	}
	return true
}

// collapseBrackets replaces each bracket expression that matches exactly
// one character ("[s]") by that character. A bracket expression runs from
// "[" to the first "]" after at least one character, as in pathname
// expansion; it cannot span a separator (win: a backslash separates too).
// Negations, ranges, classes and multi-character sets are kept: what they
// match depends on the directory.
func collapseBrackets(p string, win bool) string {
	if strings.IndexByte(p, '[') < 0 {
		return p
	}
	var b strings.Builder
	b.Grow(len(p))
	for i := 0; i < len(p); {
		if p[i] != '[' {
			b.WriteByte(p[i])
			i++
			continue
		}
		end := -1
		for k := i + 1; k < len(p); k++ {
			if p[k] == '/' || win && p[k] == '\\' {
				break
			}
			if p[k] == ']' && k >= i+2 {
				end = k
				break
			}
		}
		if end < 0 {
			b.WriteByte('[')
			i++
			continue
		}
		if c := p[i+1 : end]; len(c) == 1 && strings.IndexByte("[]!^/\\", c[0]) < 0 {
			b.WriteByte(c[0])
		} else {
			b.WriteString(p[i : end+1])
		}
		i = end + 1
	}
	return b.String()
}

// passThrough reports strings that are not file paths to rewrite.
func passThrough(p string) bool {
	if strings.HasPrefix(p, "<(") || strings.HasPrefix(p, ">(") {
		return true
	}
	if i := strings.Index(p, "://"); i > 1 && i <= 32 {
		for j := 0; j < i; j++ {
			c := p[j]
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '+' || c == '-' || c == '.') {
				return false
			}
		}
		return true
	}
	return false
}

// IsWindows reports whether p is a Windows-style path under o.
func IsWindows(p string, o Options) bool {
	if o.Posix {
		return false
	}
	if looksWindows(p) {
		return true
	}
	return o.Windows && strings.IndexByte(p, '\\') >= 0
}

// looksWindows reports paths that can only be Windows paths: a drive letter
// followed by a separator or the end, or a \\ / \??\ prefix.
func looksWindows(p string) bool {
	if len(p) >= 2 && p[1] == ':' && isLetter(p[0]) && (len(p) == 2 || p[2] == '\\' || p[2] == '/') {
		return true
	}
	if strings.HasPrefix(p, `\\`) || strings.HasPrefix(p, `\??\`) {
		return true
	}
	return strings.HasPrefix(p, "//?/") || strings.HasPrefix(p, "//./")
}

func isLetter(c byte) bool { return c|0x20 >= 'a' && c|0x20 <= 'z' }

// parsed is a path split into its fixed prefix and its segments.
type parsed struct {
	win    bool
	vol    string // Windows: "C:", `\\srv\share`; "" otherwise
	abs    bool   // rooted
	anchor string // leading segment of unknown depth ("~", "$HOME", "%APPDATA%")
	home   bool   // anchor is a spelling of the home directory
	// verbatim: a \\?\ or \??\ path, which Windows passes to the file
	// system without trimming trailing dots and spaces. keepVerbatim: it
	// has a component that trimming would change, so the prefix stays in
	// the canonical form (the name is not the trimmed one).
	verbatim, keepVerbatim bool
	segs                   []string
}

func clean(p string, o Options, fl *Flags, depth int) string {
	win := IsWindows(p, o)
	s := p
	if win {
		s = strings.ReplaceAll(s, `\`, "/")
	}
	pp := parsed{win: win}
	if win {
		var device bool
		s, device = pp.windowsVolume(s)
		if device {
			return strings.ReplaceAll(p, "/", `\`)
		}
	} else if strings.HasPrefix(s, "/") {
		pp.abs = true
	}
	s = strings.TrimLeft(s, "/")
	raw := splitSegs(s)
	if !pp.abs && pp.vol == "" && len(raw) > 0 {
		if a, home := anchorOf(raw[0], o); a {
			pp.anchor, pp.home = raw[0], home
			raw = raw[1:]
		}
	}
	if win && pp.abs && pp.vol == "" && depth == 0 {
		// "\ProgramData\x" is rooted on the drive of the working directory.
		if v := volumeOf(o.CWD); v != "" {
			pp.vol = v
		}
	}
	// A relative path is joined with the known working directory first.
	if !pp.abs && pp.vol == "" && pp.anchor == "" && o.CWD != "" && depth == 0 {
		if pp.win || IsWindows(o.CWD, o) {
			// A root working directory ("\\", "C:\\") already ends in a
			// separator; doubling it would make "\\x" a share.
			base := strings.TrimRight(o.CWD, `\/`)
			return clean(base+`\`+strings.ReplaceAll(p, "/", `\`), Options{Windows: true, Home: o.Home, Literal: o.Literal}, fl, depth+1)
		}
		return clean(strings.TrimRight(o.CWD, "/")+"/"+p, Options{Home: o.Home, Posix: o.Posix, Literal: o.Literal}, fl, depth+1)
	}
	segs, climbed := pp.walk(raw, o, fl)
	if climbed && pp.home && o.Home != "" && depth < 2 && isAbsHome(o.Home) {
		// "~/../../etc/x" with a known home: resolve against it.
		rest := strings.Join(raw, "/")
		return clean(o.Home+"/"+rest, Options{Windows: o.Windows, Posix: o.Posix, Literal: o.Literal}, fl, depth+1)
	}
	if win {
		// Win32 trims after resolving "." and "..".
		t := trimWin(segs)
		switch {
		case !pp.verbatim:
			segs = t
		case len(t) > 0 && &t[0] != &segs[0]:
			pp.keepVerbatim = true
		}
	}
	pp.segs = segs
	return pp.render()
}

func isAbsHome(h string) bool {
	return strings.HasPrefix(h, "/") || looksWindows(h)
}

// volumeOf returns the drive ("C:") or share (`\\srv\share`) of a Windows
// directory, or "".
func volumeOf(dir string) string {
	if !looksWindows(dir) {
		return ""
	}
	var pp parsed
	pp.windowsVolume(strings.ReplaceAll(dir, `\`, "/"))
	return pp.vol
}

// trimWin applies the trimming Win32 does to each component: a component
// that ends in a single period loses it ("hawkbell." is "hawkbell"), and the last
// component loses all trailing periods and spaces. (Win32 keeps those of
// the last component when the path ends in a separator; the canonical
// form drops that separator, so it trims them too.) A component of
// periods only is a valid name, and a wildcard component is a pattern.
func trimWin(raw []string) []string {
	var out []string
	for i, seg := range raw {
		t := seg
		switch {
		case seg == "" || strings.Trim(seg, ".") == "" || strings.ContainsAny(seg, "*?"):
			// "*." in cmd.exe means names without an extension.
		case i == len(raw)-1:
			if x := strings.TrimRight(seg, ". "); x != "" && strings.Trim(x, ".") != "" {
				t = x
			}
		case seg[len(seg)-1] == '.' && seg[len(seg)-2] != '.':
			t = seg[:len(seg)-1]
		}
		if t != seg && out == nil {
			out = append(make([]string, 0, len(raw)), raw[:i]...)
		}
		if out != nil {
			out = append(out, t)
		}
	}
	if out == nil {
		return raw
	}
	return out
}

func splitSegs(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, "/")
}

// windowsVolume consumes the volume of a slash-normalised Windows path and
// returns the rest. device reports the raw device namespace, which is kept
// as written.
func (pp *parsed) windowsVolume(s string) (rest string, device bool) {
	if strings.HasPrefix(s, "//") {
		s = "//" + strings.TrimLeft(s, "/")
	}
	l := strings.ToLower(s)
	switch {
	case strings.HasPrefix(l, "//?/unc/"):
		s = "//" + s[8:]
		pp.verbatim = true
	case strings.HasPrefix(l, "//?/"), strings.HasPrefix(l, "/??/"):
		s = s[4:]
		pp.verbatim = true
	case strings.HasPrefix(l, "//./"):
		r := s[4:]
		if len(r) >= 3 && r[1] == ':' && isLetter(r[0]) && r[2] == '/' && strings.Trim(r[3:], "/") != "" {
			s = r // \\.\C:\x is the file C:\x
			break
		}
		return "", true
	}
	if pp.verbatim && (nsPrefix(s) || !strings.HasPrefix(s, "//") && !(len(s) >= 2 && s[1] == ':' && isLetter(s[0]) && (len(s) == 2 || s[2] == '/'))) {
		// A namespace prefix inside another, or one not followed by a
		// drive or a share: kept as written.
		return "", true
	}
	if strings.HasPrefix(s, "//") {
		r := strings.TrimLeft(s, "/")
		parts := strings.SplitN(r, "/", 3)
		if len(parts) >= 2 && parts[0] != "" && parts[1] != "" {
			rest := ""
			if len(parts) == 3 {
				rest = parts[2]
			}
			if d := adminShare(parts[0], parts[1]); d != "" {
				// \\localhost\C$\x is C:\x.
				pp.vol, pp.abs = d, true
				return "/" + rest, false
			}
			pp.vol, pp.abs = `\\`+parts[0]+`\`+parts[1], true
			return rest, false
		}
		if parts[0] != "" {
			// A server without a share.
			pp.vol, pp.abs = `\\`+parts[0], true
			return "", false
		}
		pp.abs = true
		return r, false
	}
	if len(s) >= 2 && s[1] == ':' && isLetter(s[0]) {
		pp.vol = strings.ToUpper(s[:1]) + ":"
		s = s[2:]
		pp.abs = strings.HasPrefix(s, "/")
		return s, false
	}
	pp.abs = strings.HasPrefix(s, "/")
	return s, false
}

// nsPrefix reports a slash-normalised path that starts with a Win32 or NT
// namespace prefix (\\?\, \\.\, \??\), however many slashes lead it.
func nsPrefix(s string) bool {
	if strings.HasPrefix(s, "//") {
		s = "//" + strings.TrimLeft(s, "/")
	}
	return strings.HasPrefix(s, "//?/") || strings.HasPrefix(s, "//./") || strings.HasPrefix(s, "/??/") ||
		strings.HasPrefix(s, "//?") && len(s) == 3 || strings.HasPrefix(s, "//.") && len(s) == 3
}

// adminShare returns the drive a share of the local host stands for
// (\\localhost\C$ is C:), or "".
func adminShare(server, share string) string {
	switch strings.ToLower(server) {
	case "localhost", "127.0.0.1", "[::1]", "::1", "0:0:0:0:0:0:0:1":
	default:
		return ""
	}
	if len(share) == 2 && isLetter(share[0]) && share[1] == '$' {
		return strings.ToUpper(share[:1]) + ":"
	}
	return ""
}

// anchorOf reports a leading segment whose depth is unknown, and whether it
// names the home directory. A PowerShell drive or provider ("Env:",
// "HKCU:", "Registry::HKEY_...") is an anchor too: it is never relative to
// the working directory. Under o.Posix a colon is an ordinary character,
// and under o.Literal so are "$" and "%".
func anchorOf(seg string, o Options) (bool, bool) {
	if seg == "" {
		return false, false
	}
	if !o.Posix && len(seg) >= 2 && (seg[len(seg)-1] == ':' || strings.Contains(seg, "::")) {
		return true, false
	}
	switch seg[0] {
	case '~':
		return true, seg == "~"
	case '$', '%':
		if o.Literal {
			return false, false
		}
		l := strings.ToLower(seg)
		switch l {
		case "$home", "${home}", "%userprofile%", "$env:userprofile", "$env:home", "$userprofile":
			return true, true
		}
		return true, false
	}
	return false, false
}

// opaque reports a segment holding an unresolved expansion: ".." after it
// cannot be resolved because the expansion may hold several segments or
// none.
func opaque(seg string, o Options) bool {
	return !o.Literal && strings.ContainsAny(seg, "$%`")
}

// walk resolves "." and ".." and the /proc magic links. climbed reports a
// ".." that tried to climb out of the anchor.
func (pp *parsed) walk(raw []string, o Options, fl *Flags) (stack []string, climbed bool) {
	stack = make([]string, 0, len(raw))
	for i := 0; i < len(raw); i++ {
		seg := raw[i]
		switch seg {
		case "", ".":
			continue
		case "..":
			n := len(stack)
			switch {
			case n > 0 && stack[n-1] != ".." && !opaque(stack[n-1], o):
				stack = stack[:n-1]
			case n == 0 && pp.abs:
				// The root has no parent.
			default:
				if n == 0 && pp.anchor != "" {
					climbed = true
				}
				stack = append(stack, "..")
			}
			continue
		}
		stack = append(stack, seg)
		if pp.win || !pp.abs {
			continue
		}
		switch {
		case procRoot(stack):
			*fl |= ProcRoot
			stack = stack[:0]
		case procCwd(stack):
			// /proc/self/cwd is the working directory of the process that
			// opens the path: the command's own.
			stack = stack[:0]
			if o.CWD != "" && strings.HasPrefix(o.CWD, "/") {
				stack = append(stack, splitSegs(strings.TrimLeft(o.CWD, "/"))...)
			} else {
				pp.abs = false
				if o.CWD != "" {
					if a, home := anchorOf(firstSeg(o.CWD), o); a {
						pp.anchor, pp.home = firstSeg(o.CWD), home
						stack = append(stack, splitSegs(restSegs(o.CWD))...)
					} else {
						stack = append(stack, splitSegs(o.CWD)...)
					}
				}
			}
		}
	}
	return stack, climbed
}

func firstSeg(s string) string {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		return s[:i]
	}
	return s
}

func restSegs(s string) string {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		return s[i+1:]
	}
	return ""
}

// procRoot reports /proc/<id>/root and /proc/<id>/task/<id>/root. Any
// single component is taken as the id: only process directories have a
// root entry, so "/proc/$PID/root", "/proc/$(pgrep x)/root" and
// "/proc/*/root" name a process's root whatever the id turns out to be.
func procRoot(s []string) bool {
	switch len(s) {
	case 3:
		return s[0] == "proc" && s[2] == "root"
	case 5:
		return s[0] == "proc" && s[2] == "task" && s[4] == "root"
	}
	return false
}

func procCwd(s []string) bool {
	return len(s) == 3 && s[0] == "proc" && procSelf(s[1]) && s[2] == "cwd"
}

// procSelf reports the ids that name the process opening the path or the
// shell that runs it: "self", "thread-self", "$$" and "${$}".
func procSelf(s string) bool {
	return s == "self" || s == "thread-self" || s == "$$" || s == "${$}"
}

func digits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

func (pp *parsed) render() string {
	sep := "/"
	if pp.win {
		sep = `\`
	}
	body := strings.Join(pp.segs, sep)
	var b strings.Builder
	b.Grow(len(pp.vol) + len(pp.anchor) + len(body) + 2)
	switch {
	case pp.vol != "":
		if pp.keepVerbatim {
			if strings.HasPrefix(pp.vol, `\\`) {
				b.WriteString(`\\?\UNC\`)
				b.WriteString(pp.vol[2:])
			} else {
				b.WriteString(`\\?\`)
				b.WriteString(pp.vol)
			}
		} else {
			b.WriteString(pp.vol)
		}
		if pp.abs {
			b.WriteString(sep)
		}
		b.WriteString(body)
		out := b.String()
		if strings.HasPrefix(pp.vol, `\\`) {
			out = strings.TrimSuffix(out, sep)
		}
		return out
	case pp.keepVerbatim:
		// A verbatim path with no drive: keep the prefix, as above.
		b.WriteString(`\\?\`)
		if pp.abs {
			b.WriteString(sep)
		}
		if pp.anchor != "" {
			b.WriteString(pp.anchor)
			b.WriteString(sep)
		}
		b.WriteString(body)
		return b.String()
	case pp.abs:
		b.WriteString(sep)
		b.WriteString(body)
		return b.String()
	case pp.anchor != "":
		b.WriteString(pp.anchor)
		if body != "" {
			b.WriteString(sep)
			b.WriteString(body)
		}
		return b.String()
	}
	if body == "" {
		return "."
	}
	if pp.win && len(body) >= 2 && body[1] == ':' && isLetter(body[0]) || !pp.win && looksWindows(body) {
		// A relative path that starts with "a:" (or, in POSIX, with two
		// backslashes) would read as a drive or share when cleaned again.
		return "." + sep + body
	}
	return body
}

// IsRelative reports a path that is neither rooted, on a drive or share,
// nor anchored at a variable or "~".
func IsRelative(p string, o Options) bool {
	if p == "" {
		return false
	}
	win := IsWindows(p, o)
	switch p[0] {
	case '/', '~', '$', '%':
		return false
	case '\\':
		return !win
	}
	if a, _ := anchorOf(firstSeg(strings.ReplaceAll(p, `\`, "/")), o); a {
		return false
	}
	return !(win && len(p) >= 2 && p[1] == ':')
}

// Join returns the canonical form of rel joined to dir, as a shell's cd
// would compute it: rel when it is absolute or anchored, dir/rel otherwise.
func Join(dir, rel string, o Options) (string, Flags) {
	o.CWD = dir
	return Clean(rel, o)
}

// Dir returns the canonical directory part of a canonical path: "" for a
// bare name (the working directory).
func Dir(p string, windows bool) string {
	i := strings.LastIndexByte(p, '/')
	if windows || IsWindows(p, Options{}) {
		if j := strings.LastIndexByte(p, '\\'); j > i {
			i = j
		}
	}
	switch {
	case i < 0:
		return ""
	case i == 0:
		return p[:1]
	}
	d := p[:i]
	if len(d) == 2 && d[1] == ':' {
		return d + `\`
	}
	return d
}
