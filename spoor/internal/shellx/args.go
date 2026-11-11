package shellx

import "strings"

// optSpec describes just enough of a command's option grammar to separate
// option values from positional arguments. Getting this wrong is the classic
// analysis bug ("curl -o x URL" read as two URLs), so commands whose
// positionals matter have a spec.
type optSpec struct {
	short   string              // short option letters that take a value
	long    map[string]struct{} // long options (with dashes) that take a value
	oneDash bool                // multi-letter options use one dash (-name value); no clustering
	posStop bool                // options end at the first positional (sudo, env, docker run)
	slash   bool                // /name and /name:value are options (Windows tools)
}

func longSet(names ...string) map[string]struct{} {
	m := make(map[string]struct{}, len(names))
	for _, n := range names {
		m[n] = struct{}{}
	}
	return m
}

type optFlag struct {
	name   string
	val    arg
	hasVal bool
}

type opts struct {
	flags []optFlag
	pos   []arg
}

func (o *opts) has(names ...string) bool {
	for i := range o.flags {
		for _, n := range names {
			if o.flags[i].name == n {
				return true
			}
		}
	}
	return false
}

// hasFold is has for case-insensitive option names (Windows tools,
// PowerShell). names must be lower-case.
func (o *opts) hasFold(names ...string) bool {
	for i := range o.flags {
		l := strings.ToLower(o.flags[i].name)
		for _, n := range names {
			if l == n {
				return true
			}
		}
	}
	return false
}

func (o *opts) get(names ...string) (arg, bool) {
	for i := range o.flags {
		for _, n := range names {
			if o.flags[i].name == n && o.flags[i].hasVal {
				return o.flags[i].val, true
			}
		}
	}
	return arg{}, false
}

func (o *opts) all(names ...string) []arg {
	var out []arg
	for i := range o.flags {
		for _, n := range names {
			if o.flags[i].name == n && o.flags[i].hasVal {
				out = append(out, o.flags[i].val)
			}
		}
	}
	return out
}

func (o *opts) posStrs() []string { return strs(o.pos) }

// parseOpts splits args (without the command word) into options and
// positionals according to sp. A nil spec treats every dash word as a
// boolean flag.
func parseOpts(args []arg, sp *optSpec) opts {
	var o opts
	if sp == nil {
		sp = &optSpec{}
	}
	for i := 0; i < len(args); i++ {
		a := args[i]
		s := a.s
		if s == "--" {
			o.pos = append(o.pos, args[i+1:]...)
			break
		}
		if sp.slash && len(s) > 1 && s[0] == '/' && !strings.Contains(s[1:], "/") {
			name, val, hasVal := s, "", false
			if j := strings.IndexByte(s, ':'); j > 0 {
				name, val, hasVal = s[:j], s[j+1:], true
			}
			f := optFlag{name: "-" + strings.ToLower(name[1:]), hasVal: hasVal}
			f.val = arg{s: val, dyn: a.dyn, t: a.t}
			o.flags = append(o.flags, f)
			continue
		}
		if len(s) < 2 || s[0] != '-' || a.proc {
			o.pos = append(o.pos, a)
			if sp.posStop {
				o.pos = append(o.pos, args[i+1:]...)
				break
			}
			continue
		}
		if strings.HasPrefix(s, "--") || sp.oneDash {
			name := s
			if j := strings.IndexByte(s, '='); j > 0 {
				f := optFlag{name: s[:j], hasVal: true}
				f.val = arg{s: s[j+1:], dyn: a.dyn, t: a.t, exp: a.exp}
				o.flags = append(o.flags, f)
				continue
			}
			f := optFlag{name: name}
			if _, ok := sp.long[name]; ok && i+1 < len(args) {
				f.val, f.hasVal = args[i+1], true
				i++
			}
			o.flags = append(o.flags, f)
			continue
		}
		// Short option cluster: -abc, -ofile, -o file.
		for j := 1; j < len(s); j++ {
			c := s[j]
			f := optFlag{name: "-" + string(c)}
			if strings.IndexByte(sp.short, c) >= 0 {
				if j+1 < len(s) {
					v := s[j+1:]
					v = strings.TrimPrefix(v, "=")
					f.val, f.hasVal = arg{s: v, dyn: a.dyn, t: a.t, exp: a.exp}, true
				} else if i+1 < len(args) {
					f.val, f.hasVal = args[i+1], true
					i++
				}
				o.flags = append(o.flags, f)
				break
			}
			o.flags = append(o.flags, f)
		}
	}
	return o
}

// Helpers on simple for the many handlers that only need a quick look.

func (c *simple) rest() []arg {
	if len(c.args) <= 1 {
		return nil
	}
	return c.args[1:]
}

func (c *simple) argStr(i int) string {
	if i+1 < len(c.args) {
		return c.args[i+1].s
	}
	return ""
}

// has reports whether any argument before "--" equals one of flags.
func (c *simple) has(flags ...string) bool {
	for _, a := range c.rest() {
		if a.s == "--" {
			break
		}
		for _, f := range flags {
			if a.s == f {
				return true
			}
		}
	}
	return false
}

// hasFold is has with ASCII case folding; flags must be lower-case.
func (c *simple) hasFold(flags ...string) bool {
	for _, a := range c.rest() {
		l := strings.ToLower(a.s)
		for _, f := range flags {
			if l == f {
				return true
			}
		}
	}
	return false
}

// hasShort reports whether a short-option cluster contains letter, or one of
// the long spellings is present.
func (c *simple) hasShort(letter byte, long ...string) bool {
	for _, a := range c.rest() {
		s := a.s
		if s == "--" {
			break
		}
		if len(s) >= 2 && s[0] == '-' && s[1] != '-' && strings.IndexByte(s[1:], letter) >= 0 {
			return true
		}
		for _, l := range long {
			if s == l || strings.HasPrefix(s, l+"=") {
				return true
			}
		}
	}
	return false
}

// positionals returns the arguments that are not dash options. It is the
// lenient reading for commands without an optSpec.
func (c *simple) positionals() []arg {
	var out []arg
	rest := c.rest()
	for i, a := range rest {
		if a.s == "--" {
			out = append(out, rest[i+1:]...)
			break
		}
		if len(a.s) > 1 && a.s[0] == '-' && !a.proc {
			continue
		}
		out = append(out, a)
	}
	return out
}

// subcommand returns the first positional after skipping global options that
// take a value, plus the arguments after it.
func subcommand(args []arg, sp *optSpec) (string, []arg) {
	for i := 0; i < len(args); i++ {
		s := args[i].s
		if s == "--" {
			if i+1 < len(args) {
				return strings.ToLower(args[i+1].s), args[i+2:]
			}
			return "", nil
		}
		if len(s) > 1 && s[0] == '-' {
			if strings.Contains(s, "=") {
				continue
			}
			if sp != nil {
				if strings.HasPrefix(s, "--") || sp.oneDash {
					if _, ok := sp.long[s]; ok {
						i++
					}
				} else if len(s) == 2 && strings.IndexByte(sp.short, s[1]) >= 0 {
					i++
				}
			}
			continue
		}
		return strings.ToLower(s), args[i+1:]
	}
	return "", nil
}

// containsArgFold reports whether any argument contains sub (lower-case),
// ignoring case.
func containsArgFold(args []arg, sub string) bool {
	for i := range args {
		if containsFold(args[i].s, sub) {
			return true
		}
	}
	return false
}
