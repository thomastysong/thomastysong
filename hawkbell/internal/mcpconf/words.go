package mcpconf

import (
	"strings"
)

// maxScript bounds how much of a command line or inline script is read.
// Launch lines are short; anything longer is padding or an attack on the
// scanner, and the head is where the launcher is.
const maxScript = 64 << 10

// splitWords splits a command line into words the way a shell would, without
// expanding anything. Quotes group; a backslash escapes only a following
// space, quote or backslash-before-quote, so Windows paths survive.
func splitWords(s string) []string {
	cmds := splitScript(s, false)
	var out []string
	for _, c := range cmds {
		out = append(out, c...)
	}
	return out
}

// splitScript splits an inline shell script into simple commands at ; && ||
// | & and newlines when operators is true. It is a word-level reading: no
// expansion, no substitution, no heredocs. It exists to find the launcher in
// "sh -c 'cd /srv && exec npx -y pkg'"; anything subtler is package shellx's job.
func splitScript(s string, operators bool) [][]string {
	if len(s) > maxScript {
		s = s[:maxScript]
	}
	var (
		cmds  [][]string
		cur   []string
		word  strings.Builder
		open  bool // a word is in progress (covers the empty quoted word "")
		quote byte
	)
	endWord := func() {
		if open {
			cur = append(cur, word.String())
			word.Reset()
			open = false
		}
	}
	endCmd := func() {
		endWord()
		if len(cur) > 0 {
			cmds = append(cmds, cur)
			cur = nil
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if quote != 0 {
			switch {
			case c == quote:
				quote = 0
			case c == '\\' && quote == '"' && i+1 < len(s) && (s[i+1] == '"' || s[i+1] == '\\'):
				i++
				word.WriteByte(s[i])
			default:
				word.WriteByte(c)
			}
			continue
		}
		switch c {
		case '"', '\'':
			quote, open = c, true
		case ' ', '\t', '\r':
			endWord()
		case '\n':
			if operators {
				endCmd()
			} else {
				endWord()
			}
		case '\\':
			if i+1 < len(s) && (s[i+1] == ' ' || s[i+1] == '"' || s[i+1] == '\'') {
				i++
				word.WriteByte(s[i])
			} else {
				word.WriteByte(c)
			}
			open = true
		case ';', '|', '&':
			if operators {
				endCmd()
			} else {
				word.WriteByte(c)
				open = true
			}
		default:
			word.WriteByte(c)
			open = true
		}
	}
	endCmd()
	return cmds
}

// baseName returns the last path element, accepting both separators.
func baseName(p string) string {
	p = strings.TrimRight(p, `/\`)
	if i := strings.LastIndexAny(p, `/\`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// cmdBase is the executable name rules compare against: basename, lower
// case, Windows launcher extensions removed (npx.cmd, docker.exe).
func cmdBase(cmd string) string {
	b := strings.ToLower(baseName(strings.TrimSpace(cmd)))
	for _, ext := range []string{".exe", ".cmd", ".bat", ".com"} {
		if strings.HasSuffix(b, ext) && len(b) > len(ext) {
			return b[:len(b)-len(ext)]
		}
	}
	return b
}

// isPathLike reports whether s names a file by location rather than a
// program to be found on PATH.
func isPathLike(s string) bool {
	if s == "" {
		return false
	}
	if strings.ContainsAny(s, `/\`) {
		return true
	}
	return s[0] == '~' || s[0] == '.'
}

func isDriveAbs(p string) bool {
	return len(p) >= 3 && isLetter(p[0]) && p[1] == ':' && (p[2] == '\\' || p[2] == '/')
}

func isLetter(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z')
}

func isAbsPath(p string) bool {
	return strings.HasPrefix(p, "/") || strings.HasPrefix(p, `\\`) || isDriveAbs(p)
}

// joinPath resolves rel against dir lexically. It only has to be good enough
// to classify the location; nothing is opened.
func joinPath(dir, rel string) string {
	if dir == "" || isAbsPath(rel) || homeRelative(rel) {
		return rel
	}
	return strings.TrimRight(dir, `/\`) + "/" + rel
}

// homeVars are spellings of "the user's own directory tree" across shells
// and the template languages of agent configs.
var homeVars = []string{
	"~", "$home", "${home}", "%userprofile%", "%homepath%", "$env:userprofile",
	"%appdata%", "%localappdata%", "$env:appdata", "$env:localappdata",
	"%temp%", "%tmp%", "$env:temp", "$tmpdir", "${tmpdir}",
	"${userhome}", "${env:home}", "${env:userprofile}", "{env:home}",
	"${workspacefolder}", "${workspaceroot}", "${pwd}", "$pwd", "${cwd}",
	"${claude_plugin_root}", "${claude_plugin_data}", "${claude_project_dir}",
	"$claude_project_dir", "${plugin_root}",
}

func homeRelative(p string) bool {
	lp := strings.ToLower(p)
	for _, v := range homeVars {
		if strings.HasPrefix(lp, v) {
			rest := lp[len(v):]
			if rest == "" || rest[0] == '/' || rest[0] == '\\' {
				return true
			}
		}
	}
	return false
}

// userWritablePrefixes are absolute POSIX locations an unprivileged user can
// normally modify.
var userWritablePrefixes = []string{
	"/home/", "/users/", "/root/", "/tmp/", "/var/tmp/", "/private/tmp/",
	"/private/var/tmp/", "/var/folders/", "/private/var/folders/", "/dev/shm/",
	"/workspace/", "/workspaces/", "/mnt/c/users/",
}

// windowsSystemDirs are the drive-rooted trees a standard user cannot write.
// Everything else on a Windows volume inherits "Authenticated Users: Modify".
var windowsSystemDirs = []string{"/program files/", "/program files (x86)/", "/windows/", "/programdata/"}

// userWritable reports, from the spelling of the path alone, whether the
// file can be replaced by the user the agent runs as (and therefore by
// anything else running as that user). Unknown locations are not reported.
func userWritable(p string) bool {
	p = strings.TrimSpace(p)
	if p == "" {
		return false
	}
	if homeRelative(p) {
		return true
	}
	lp := strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
	if isDriveAbs(p) {
		rest := lp[2:]
		for _, sys := range windowsSystemDirs {
			if strings.HasPrefix(rest+"/", sys) {
				return false
			}
		}
		return true
	}
	if strings.HasPrefix(lp, "//") {
		return false // UNC share: writability is not knowable from here
	}
	if strings.HasPrefix(lp, "/") {
		for _, pre := range userWritablePrefixes {
			if strings.HasPrefix(lp+"/", pre) {
				return true
			}
		}
		return false
	}
	if strings.HasPrefix(lp, "$") || strings.HasPrefix(lp, "%") || strings.HasPrefix(lp, "{") {
		return false // rooted in a variable this package does not know
	}
	return true // relative: resolved against the project or home directory
}

// broadRoot reports whether p is a filesystem root or a whole home directory.
func broadRoot(p string) bool {
	p = strings.TrimSpace(p)
	if p == "" {
		return false
	}
	lp := strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
	if len(lp) > 1 {
		lp = strings.TrimRight(lp, "/")
		if lp == "" {
			lp = "/"
		}
	}
	switch lp {
	case "/", "~", "$home", "${home}", "%userprofile%", "$env:userprofile", "%homepath%",
		"${userhome}", "${env:home}", "{env:home}", "/home", "/users", "/root", "/mnt/c",
		"/mnt/c/users", "/host":
		return true
	}
	if len(lp) == 2 && isLetter(lp[0]) && lp[1] == ':' {
		return true // C: or C:\
	}
	rest := lp
	if len(lp) > 2 && isLetter(lp[0]) && lp[1] == ':' {
		rest = lp[2:]
	}
	if rest == "/users" {
		return true
	}
	for _, pre := range []string{"/home/", "/users/", "/mnt/c/users/"} {
		// exactly one more element: /home/alice, C:\Users\alice
		if strings.HasPrefix(rest, pre) && !strings.Contains(rest[len(pre):], "/") && len(rest) > len(pre) {
			return true
		}
	}
	return false
}
