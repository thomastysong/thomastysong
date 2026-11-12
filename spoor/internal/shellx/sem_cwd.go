package shellx

import (
	"strings"

	"github.com/thomastysong/spoor/internal/pathcanon"
)

// Working-directory tracking. A path operand is canonical only once it is
// joined with the directory it is relative to, so "cd /etc/spoor && touch
// disabled" records /etc/spoor/disabled. The analysis knows only what the
// command line itself does: the session's directory is not known here
// (features and classify resolve against it), and a cd to a directory the
// analysis cannot resolve ("cd $X", "cd -") makes the directory unknown,
// after which relative operands are recorded as written until a cd to an
// absolute or home-anchored directory.

// maxDirStack bounds the pushd stack.
const maxDirStack = 64

// cwdState is the working directory at one point of the analysis.
type cwdState struct {
	cwd  string
	lost bool
	stk  []string
}

func (a *analyzer) saveCwd() cwdState {
	return cwdState{cwd: a.cwd, lost: a.cwdLost, stk: append([]string(nil), a.dirStk...)}
}

func (a *analyzer) restoreCwd(s cwdState) {
	a.cwd, a.cwdLost, a.dirStk = s.cwd, s.lost, s.stk
}

// setCwd moves the tracked directory to the canonical dir; "" means unknown.
func (a *analyzer) setCwd(dir string) {
	if dir == "" {
		a.cwd, a.cwdLost = "", true
		return
	}
	if a.cwdLost && !rootedDir(dir) {
		return // relative to a directory nobody knows
	}
	a.cwd, a.cwdLost = dir, false
}

// rootedDir reports a canonical directory that does not depend on the
// directory before it: absolute, a drive or share, or home-anchored.
func rootedDir(d string) bool {
	if d == "" {
		return false
	}
	switch d[0] {
	case '/', '\\', '~', '$', '%':
		return true
	}
	return len(d) >= 2 && d[1] == ':'
}

func registerCwd() {
	register(hCd, "cd", "chdir", "pushd", "popd")
	register(hWinRename, "ren", "rename")
}

// hCd covers cd, chdir, pushd and popd in every dialect and PowerShell's
// Set-Location, Push-Location and Pop-Location.
func hCd(a *analyzer, c *simple, in flow, out *flow) {
	if c.bg && c.dialect == Posix {
		// "cd /x &" runs in a background subshell: the shell's directory
		// does not change.
		return
	}
	name := c.name
	if c.dialect == PowerShell {
		name = psCanonical(name)
	}
	switch name {
	case "popd", "pop-location":
		if n := len(a.dirStk); n > 0 {
			a.cwd, a.cwdLost = a.dirStk[n-1], a.dirStk[n-1] == ""
			a.dirStk = a.dirStk[:n-1]
		} else {
			a.setCwd("")
		}
		return
	}
	push := name == "pushd" || name == "push-location"
	target, ok := cdTarget(c)
	if push {
		cur := a.cwd
		if a.cwdLost {
			cur = ""
		}
		if len(a.dirStk) < maxDirStack {
			a.dirStk = append(a.dirStk, cur)
		}
	}
	if !ok {
		switch {
		case push:
			a.setCwd("") // pushd alone swaps the top two entries
		case c.dialect == Posix:
			a.setCwd("~") // cd alone goes home
		}
		return
	}
	if target.dyn || target.glob || target.proc || target.s == "-" || target.s == "" {
		a.setCwd("")
		return
	}
	dir, _ := pathcanon.Clean(target.s, a.canonOpts())
	a.setCwd(dir)
}

// cdTarget returns the directory operand of a cd-family command.
func cdTarget(c *simple) (arg, bool) {
	rest := c.rest()
	var words []arg
	for i := 0; i < len(rest); i++ {
		s := rest[i].s
		switch c.dialect {
		case Posix:
			if len(words) == 0 && (s == "-L" || s == "-P" || s == "-e" || s == "-@" || s == "-LP" || s == "-PL") {
				continue
			}
			if s == "--" && len(words) == 0 {
				continue
			}
		case Cmd:
			if strings.EqualFold(s, "/d") {
				continue
			}
		case PowerShell:
			if len(s) > 1 && s[0] == '-' {
				l := strings.ToLower(s)
				switch {
				case strings.HasPrefix(l, "-stack"):
					i++ // -StackName <name>
				case l == "-passthru" || strings.HasPrefix(l, "-path") || strings.HasPrefix(l, "-literal"):
				}
				continue
			}
		}
		words = append(words, rest[i])
	}
	switch {
	case len(words) == 0:
		return arg{}, false
	case c.dialect == Cmd && len(words) > 1:
		// cmd.exe's cd takes the rest of the line: cd C:\Program Files\x.
		w := words[0]
		for _, x := range words[1:] {
			w.s += " " + x.s
			w.dyn = w.dyn || x.dyn
			w.glob = w.glob || x.glob
		}
		return w, true
	}
	return words[0], true
}

// hWinRename covers cmd.exe's ren / rename and PowerShell's Rename-Item
// and Set-Acl: the first path is renamed (a move source) or has its
// access list replaced. POSIX rename (util-linux or perl) is left alone:
// its first words are expressions, not paths.
func hWinRename(a *analyzer, c *simple, in flow, out *flow) {
	if c.dialect == Posix && (c.name == "ren" || c.name == "rename") {
		return
	}
	name := c.name
	if c.dialect == PowerShell {
		name = psCanonical(name)
	}
	var target *arg
	rest := c.rest()
	for i := 0; i < len(rest); i++ {
		s := rest[i].s
		if len(s) > 1 && s[0] == '-' && c.dialect == PowerShell {
			l := strings.ToLower(s)
			switch {
			case strings.HasPrefix(l, "-path") || strings.HasPrefix(l, "-literalpath"):
				if j := strings.IndexByte(s, ':'); j > 0 && j+1 < len(s) {
					v := rest[i]
					v.s = s[j+1:]
					target = &v
				} else if i+1 < len(rest) {
					target = &rest[i+1]
				}
				i++
			case strings.HasPrefix(l, "-newname"), strings.HasPrefix(l, "-aclobject"), strings.HasPrefix(l, "-inputobject"),
				strings.HasPrefix(l, "-filter"), strings.HasPrefix(l, "-include"), strings.HasPrefix(l, "-exclude"),
				strings.HasPrefix(l, "-credential"), strings.HasPrefix(l, "-securitydescriptor"):
				i++
			}
			continue
		}
		if c.dialect == Cmd && strings.HasPrefix(s, "/") {
			continue
		}
		if target == nil {
			target = &rest[i]
		}
	}
	if target == nil || target.dyn && strings.HasPrefix(target.s, "$") && !strings.ContainsAny(target.s, `/\`) {
		return
	}
	if name == "set-acl" {
		a.attr(target.s)
		return
	}
	a.use(target.s, mMove)
}
