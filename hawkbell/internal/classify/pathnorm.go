package classify

import (
	"runtime"
	"strings"
)

// maxPathLen is above the longest path any supported OS can open (32,767
// UTF-16 units for Windows long paths). Longer input is not a path.
const maxPathLen = 32 << 10

// Volume markers for the namespaces that are not ordinary files.
const (
	volDevice   = "//." // Windows device namespace: \\.\PhysicalDrive0, \\.\pipe\x
	volRegistry = "reg:"
)

// PathCtx is what a lexical resolution needs to know about the session.
// Empty fields are allowed: without CWD relative paths stay relative, without
// Home "~" resolves to a placeholder home that still matches the any-user
// patterns, and OS "" means runtime.GOOS.
type PathCtx struct{ CWD, Home, OS string }

// lexPath is a path after purely syntactic normalization. Nothing here touches
// the filesystem, so a symlink can still make a harmless-looking path point at
// a sensitive one; callers that can stat should classify the resolved target
// as well (threat research rule R13).
type lexPath struct {
	vol   string   // lower-cased volume: "c:", "//server/share", volDevice, volRegistry; "" on POSIX
	abs   bool     // rooted
	segs  []string // components, original case, "." and ".." resolved
	lsegs []string // segs lower-cased
	wild  []bool   // segment contains shell wildcard characters
	up    int      // leading ".." of a relative path that climbs out of its base
	fold  bool     // compare case-insensitively
}

func (p *lexPath) base() string {
	if len(p.segs) == 0 {
		return ""
	}
	return p.segs[len(p.segs)-1]
}

func (p *lexPath) lbase() string {
	if len(p.lsegs) == 0 {
		return ""
	}
	return p.lsegs[len(p.lsegs)-1]
}

func normOS(os string) string {
	switch strings.ToLower(os) {
	case "linux", "darwin", "windows":
		return strings.ToLower(os)
	case "macos", "mac", "osx":
		return "darwin"
	case "win", "win32", "windows_nt":
		return "windows"
	case "":
		switch runtime.GOOS {
		case "darwin", "windows":
			return runtime.GOOS
		}
		return "linux"
	}
	// Any other Unix behaves like Linux for path purposes.
	return "linux"
}

// defaultHome is the stand-in used when the caller does not know the home
// directory. It is shaped like a real home so the any-user patterns match.
func defaultHome(os string) string {
	switch os {
	case "windows":
		return "C:/Users/_"
	case "darwin":
		return "/Users/_"
	}
	return "/home/_"
}

// otherHome guesses the home of a named user for "~user/..." forms.
func otherHome(user, os string) string {
	switch {
	case os == "windows":
		return "C:/Users/" + user
	case user == "root" && os == "darwin":
		return "/var/root"
	case user == "root":
		return "/root"
	case os == "darwin":
		return "/Users/" + user
	}
	return "/home/" + user
}

// cleanInput strips what is not part of the path: a NUL and everything after
// it (C APIs stop there, so "/etc/shadow\x00.png" opens /etc/shadow), line
// ends, one pair of surrounding quotes, and a file:// prefix.
func cleanInput(s string) string {
	if i := strings.IndexByte(s, 0); i >= 0 {
		s = s[:i]
	}
	s = strings.Trim(s, "\r\n\t")
	if len(s) >= 2 {
		if q := s[0]; (q == '"' || q == '\'') && s[len(s)-1] == q {
			s = s[1 : len(s)-1]
		}
	}
	if len(s) >= 7 && strings.EqualFold(s[:7], "file://") {
		rest := s[7:]
		// file://host/path keeps only the path; file:///C:/x keeps C:/x.
		if i := strings.IndexByte(rest, '/'); i > 0 {
			rest = rest[i:]
		}
		if len(rest) >= 3 && rest[0] == '/' && rest[2] == ':' {
			rest = rest[1:]
		}
		s = percentDecode(rest)
	}
	return s
}

// isRemoteURL reports scheme://... forms that are not local files.
func isRemoteURL(s string) bool {
	i := strings.Index(s, "://")
	if i <= 1 || i > 32 {
		return false // i == 1 would be a drive letter typed with slashes
	}
	for j := 0; j < i; j++ {
		if !isSchemeChar(s[j], j == 0) {
			return false
		}
	}
	return true
}

// expandVars resolves "~" and the environment variables whose value is known
// from the context. Unknown variables are left as written.
func expandVars(s string, home, cwd, os string) string {
	win := os == "windows"
	if s == "" {
		return s
	}
	if s[0] == '~' {
		end := len(s)
		for i := 1; i < len(s); i++ {
			if s[i] == '/' || (win && s[i] == '\\') {
				end = i
				break
			}
		}
		name := s[1:end]
		switch {
		case name == "":
			s = home + s[end:]
		case name == "+" && cwd != "":
			s = cwd + s[end:]
		case validUserName(name):
			s = otherHome(name, os) + s[end:]
		}
	}
	if !strings.ContainsAny(s, "$%") {
		return s
	}
	vars := knownVars(home, cwd, os)
	var b strings.Builder
	b.Grow(len(s) + 32)
	replaced := 0
	for i := 0; i < len(s); {
		if replaced >= 16 {
			b.WriteString(s[i:])
			break
		}
		name, n := varAt(s, i)
		if n > 0 {
			if v, ok := vars[strings.ToUpper(name)]; ok {
				b.WriteString(v)
				i += n
				replaced++
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
}

func validUserName(n string) bool {
	if len(n) > 64 {
		return false
	}
	for i := 0; i < len(n); i++ {
		if c := n[i]; !isAlnum(c) && c != '_' && c != '-' && c != '.' {
			return false
		}
	}
	return true
}

// varAt recognises $NAME, ${NAME}, $env:NAME and %NAME% at s[i:] and returns
// the name and the length of the reference (0 if there is none).
func varAt(s string, i int) (string, int) {
	isName := func(c byte) bool { return isAlnum(c) || c == '_' || c == '(' || c == ')' }
	switch s[i] {
	case '$':
		j := i + 1
		if j < len(s) && s[j] == '{' {
			end := strings.IndexByte(s[j:], '}')
			if end > 1 && end < 64 {
				return s[j+1 : j+end], end + 2
			}
			return "", 0
		}
		if len(s)-j > 4 && strings.EqualFold(s[j:j+4], "env:") {
			j += 4
		}
		k := j
		for k < len(s) && (isAlnum(s[k]) || s[k] == '_') {
			k++
		}
		if k > j {
			return s[j:k], k - i
		}
	case '%':
		k := i + 1
		for k < len(s) && isName(s[k]) && k-i < 64 {
			k++
		}
		if k > i+1 && k < len(s) && s[k] == '%' {
			return s[i+1 : k], k - i + 1
		}
	}
	return "", 0
}

func knownVars(home, cwd, os string) map[string]string {
	m := map[string]string{
		"HOME": home, "USERPROFILE": home,
		"XDG_CONFIG_HOME": home + "/.config",
		"XDG_DATA_HOME":   home + "/.local/share",
		"XDG_STATE_HOME":  home + "/.local/state",
		"XDG_CACHE_HOME":  home + "/.cache",
		// Relocation variables, at their defaults (research/agent-surfaces-a.md):
		// the real value is unknown here, and the default is where the
		// classification rules look.
		"CLAUDE_CONFIG_DIR": home + "/.claude",
		"CODEX_HOME":        home + "/.codex",
		"COPILOT_HOME":      home + "/.copilot",
	}
	if i := strings.LastIndexAny(home, `/\`); i >= 0 && i+1 < len(home) {
		user := home[i+1:]
		m["USER"], m["USERNAME"], m["LOGNAME"] = user, user, user
	}
	if cwd != "" {
		m["PWD"], m["CD"] = cwd, cwd
	}
	if os == "windows" {
		m["APPDATA"] = home + "/AppData/Roaming"
		m["LOCALAPPDATA"] = home + "/AppData/Local"
		m["TEMP"] = home + "/AppData/Local/Temp"
		m["TMP"] = m["TEMP"]
		m["PROGRAMDATA"] = "C:/ProgramData"
		m["ALLUSERSPROFILE"] = "C:/ProgramData"
		m["PROGRAMFILES"] = "C:/Program Files"
		m["PROGRAMFILES(X86)"] = "C:/Program Files (x86)"
		m["PROGRAMW6432"] = "C:/Program Files"
		m["SYSTEMROOT"] = "C:/Windows"
		m["WINDIR"] = "C:/Windows"
		m["SYSTEMDRIVE"] = "C:"
		m["HOMEDRIVE"] = "C:"
		m["PUBLIC"] = "C:/Users/Public"
		if len(home) > 2 && home[1] == ':' {
			m["HOMEDRIVE"] = home[:2]
			m["HOMEPATH"] = home[2:]
		}
	} else {
		m["TMPDIR"], m["TMP"], m["TEMP"] = "/tmp", "/tmp", "/tmp"
	}
	return m
}

// lex parses an expanded path string. base, when not nil, is the directory a
// relative path is resolved against.
func lex(s, os string, base *lexPath) *lexPath {
	win := os == "windows"
	p := &lexPath{}
	if win {
		s = strings.ReplaceAll(s, `\`, "/")
		s = p.splitWindowsVolume(s)
		if p.abs && p.vol == "" && base != nil {
			p.vol = base.vol // "\Windows" is on the drive of the working directory
		}
	} else if strings.HasPrefix(s, "/") {
		p.abs = true
	}
	var stack []string
	if !p.abs && base != nil {
		stack = append(stack, base.segs...)
		p.abs, p.vol = base.abs, base.vol
		p.up = base.up
	}
	for len(s) > 0 {
		var seg string
		if i := strings.IndexByte(s, '/'); i >= 0 {
			seg, s = s[:i], s[i+1:]
		} else {
			seg, s = s, ""
		}
		switch seg {
		case "", ".":
			continue
		case "..":
			switch {
			case len(stack) > 0:
				stack = stack[:len(stack)-1]
			case !p.abs:
				p.up++
			}
			continue
		}
		if win && p.vol != volRegistry && p.vol != volDevice {
			seg = cleanWindowsSegment(seg)
		} else if os == "darwin" {
			seg = stripIgnorable(seg)
		}
		if seg == "" {
			continue
		}
		stack = append(stack, seg)
	}
	p.segs = stack
	return p
}

// splitWindowsVolume consumes the volume part of a slash-normalized Windows
// path and returns the rest.
func (p *lexPath) splitWindowsVolume(s string) string {
	lower := strings.ToLower(s)
	// Extended-length and device namespaces.
	switch {
	case strings.HasPrefix(lower, "//?/unc/"):
		s, lower = "//"+s[8:], "//"+lower[8:]
	case strings.HasPrefix(lower, "//?/"), strings.HasPrefix(lower, "/??/"):
		s, lower = s[4:], lower[4:]
	case strings.HasPrefix(lower, "//./"):
		rest := s[4:]
		if len(rest) >= 2 && rest[1] == ':' {
			// \\.\C: is the raw volume; with a path after it, a plain file.
			if len(rest) == 2 || rest == rest[:2]+"/" {
				p.vol, p.abs = volDevice, true
				return rest[:2]
			}
			s, lower = rest, lower[4:]
			break
		}
		p.vol, p.abs = volDevice, true
		return rest
	}
	// Registry paths, as PowerShell and reg.exe write them.
	for _, pre := range []string{"registry::", "microsoft.powershell.core/registry::"} {
		if strings.HasPrefix(lower, pre) {
			s, lower = s[len(pre):], lower[len(pre):]
		}
	}
	for _, hive := range []string{"hklm:", "hkcu:", "hkcr:", "hku:", "hkcc:", "hkey_local_machine", "hkey_current_user", "hkey_classes_root", "hkey_users", "hkey_current_config", "hklm/", "hkcu/"} {
		if strings.HasPrefix(lower, hive) {
			p.vol, p.abs = volRegistry, true
			return s
		}
	}
	if strings.HasPrefix(s, "//") {
		// UNC: //server/share/rest.
		rest := s[2:]
		i := strings.IndexByte(rest, '/')
		if i < 0 {
			p.vol, p.abs = "//"+strings.ToLower(rest), true
			return ""
		}
		j := strings.IndexByte(rest[i+1:], '/')
		if j < 0 {
			p.vol, p.abs = "//"+strings.ToLower(rest), true
			return ""
		}
		p.vol, p.abs = "//"+strings.ToLower(rest[:i+1+j]), true
		return rest[i+1+j:]
	}
	if len(s) >= 2 && s[1] == ':' && (s[0] >= 'a' && s[0] <= 'z' || s[0] >= 'A' && s[0] <= 'Z') {
		// C:\x, and the drive-relative C:x, which is treated as rooted: the
		// per-drive working directory is not knowable here.
		p.vol, p.abs = strings.ToLower(s[:2]), true
		return s[2:]
	}
	// POSIX-looking paths from Git Bash, MSYS, Cygwin and WSL interop.
	for _, pre := range []string{"/cygdrive/", "/mnt/", "/"} {
		if strings.HasPrefix(lower, pre) {
			rest := s[len(pre):]
			if len(rest) >= 1 && (rest[0] >= 'a' && rest[0] <= 'z' || rest[0] >= 'A' && rest[0] <= 'Z') && (len(rest) == 1 || rest[1] == '/') {
				p.vol, p.abs = strings.ToLower(rest[:1])+":", true
				return rest[1:]
			}
		}
	}
	if strings.HasPrefix(s, "/") {
		p.abs = true // root of the current drive
	}
	return s
}

// cleanWindowsSegment applies the name normalization NTFS and Win32 perform,
// so ".mcp.json." , "settings.json " and "settings.json::$DATA" classify like
// the file they open (threat research rule R12, CVE-2025-59944 class).
func cleanWindowsSegment(seg string) string {
	if i := strings.IndexByte(seg, ':'); i >= 0 {
		seg = seg[:i] // alternate data stream
	}
	seg = strings.TrimRight(seg, ". ")
	if strings.EqualFold(seg, "git~1") {
		// The 8.3 alias every Windows git checkout has for ".git".
		return ".git"
	}
	return seg
}

// stripIgnorable removes the code points HFS+ ignores when comparing names
// (".g\u200cit" opens ".git" there). APFS does not ignore them, but the cost
// of treating them alike is nil and volumes of both kinds are in use.
func stripIgnorable(seg string) string {
	if isASCII(seg) {
		return seg
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 0x200c && r <= 0x200f, r >= 0x202a && r <= 0x202e,
			r >= 0x206a && r <= 0x206f, r == 0xfeff:
			return -1
		}
		return r
	}, seg)
}

// finish computes the derived fields once segs is final.
func (p *lexPath) finish(os string) {
	p.fold = os != "linux"
	if os == "linux" && len(p.segs) >= 2 && p.segs[0] == "mnt" && len(p.segs[1]) == 1 {
		// WSL mounts Windows drives at /mnt/<letter>; they are
		// case-insensitive like the NTFS volume behind them.
		p.fold = true
	}
	p.lsegs = make([]string, len(p.segs))
	p.wild = make([]bool, len(p.segs))
	for i, s := range p.segs {
		p.lsegs[i] = strings.ToLower(s)
		p.wild[i] = strings.ContainsAny(s, "*?[")
	}
}

// canonicalize rewrites aliases of the same location to one spelling so the
// rule tables need only that one.
func (p *lexPath) canonicalize(os string, cwd *lexPath) {
	if !p.abs || p.vol != "" {
		return
	}
	for range [8]struct{}{} {
		s := p.segs
		switch {
		case len(s) >= 3 && s[0] == "proc" && s[2] == "root" && procSelf(s[1]):
			// /proc/self/root/etc/shadow is /etc/shadow: a known way around
			// path deny lists (threat research rule R35).
			p.segs = s[3:]
		case len(s) >= 3 && s[0] == "proc" && s[2] == "cwd" && procSelfOnly(s[1]) && cwd != nil && cwd.abs:
			p.segs = append(append([]string(nil), cwd.segs...), s[3:]...)
		case os == "darwin" && len(s) >= 2 && s[0] == "private" && (s[1] == "etc" || s[1] == "var" || s[1] == "tmp"):
			p.segs = s[1:]
		case os == "darwin" && len(s) >= 3 && s[0] == "System" && s[1] == "Volumes" && s[2] == "Data":
			p.segs = s[3:]
		default:
			return
		}
	}
}

func procSelf(s string) bool { return procSelfOnly(s) || allDigits(s) }

func procSelfOnly(s string) bool { return s == "self" || s == "thread-self" }

// resolvePath runs the whole lexical pipeline for one path string.
func resolvePath(raw string, ctx PathCtx) (p *lexPath, cwd *lexPath, home *lexPath, os string) {
	os = normOS(ctx.OS)
	if os != "windows" && looksWindows(raw) {
		// A drive-letter or UNC path is a Windows path whatever the context
		// says (events replayed on another OS, a context with no OS set).
		os = "windows"
	}
	homeStr := cleanInput(ctx.Home)
	if homeStr == "" {
		homeStr = defaultHome(os)
	}
	home = lex(homeStr, os, nil)
	home.canonicalize(os, nil)
	home.finish(os)
	if c := cleanInput(ctx.CWD); c != "" {
		cwd = lex(expandVars(c, homeStr, "", os), os, nil)
		if !cwd.abs {
			cwd = nil // a relative CWD resolves nothing
		} else {
			cwd.canonicalize(os, nil)
			cwd.finish(os)
		}
	}
	cwdStr := ""
	if cwd != nil {
		cwdStr = ctx.CWD
	}
	p = lex(expandVars(raw, homeStr, cwdStr, os), os, cwd)
	p.canonicalize(os, cwd)
	p.finish(os)
	return p, cwd, home, os
}

// under reports whether p is dir or below it.
func (p *lexPath) under(dir *lexPath) bool {
	if dir == nil || !p.abs || !dir.abs || p.vol != dir.vol || len(p.segs) < len(dir.segs) {
		return false
	}
	fold := p.fold || dir.fold
	for i := range dir.segs {
		if fold {
			if p.lsegs[i] != dir.lsegs[i] {
				return false
			}
		} else if p.segs[i] != dir.segs[i] {
			return false
		}
	}
	return true
}

// looksWindows reports paths that can only be Windows paths: C:\x or \\server\x.
func looksWindows(s string) bool {
	if len(s) >= 3 && s[1] == ':' && s[2] == '\\' && (s[0] >= 'a' && s[0] <= 'z' || s[0] >= 'A' && s[0] <= 'Z') {
		return true
	}
	return strings.HasPrefix(s, `\\`) && !strings.Contains(s, "/")
}
