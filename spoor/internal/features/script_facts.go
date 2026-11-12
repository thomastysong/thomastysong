package features

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/thomastysong/spoor/internal/shellx"
)

// ScriptFacts are the shell features of a written script's content, as a
// shell event carrying that content would get them (shell.* and the net.*
// derived from its URLs and hosts), reduced to what matching a later
// execution needs and bounded for session state. The rule engine keeps
// them per path and exports them with a one-shot hook process's session,
// so they are small, hold no raw content (arguments and URLs keep what the
// analyzer extracted, with credentials redacted by the caller's evidence
// stage only; secrets themselves are summarized as shell.secret_kinds),
// and are validated as hostile input on import (Validate).
type ScriptFacts struct {
	Lang     string              `json:"l"`
	Bools    map[string]bool     `json:"b,omitempty"`
	Nums     map[string]float64  `json:"n,omitempty"`
	Lists    map[string][]string `json:"s,omitempty"`
	Cmds     []ScriptCommand     `json:"c,omitempty"`
	Installs []ScriptInstall     `json:"i,omitempty"`
	// Cut names the features whose value is incomplete (a size cap of the
	// analyzer or of these bounds); they join content.truncated_fields of
	// the event that inherits them.
	Cut []string `json:"x,omitempty"`
}

// ScriptCommand is one shell.cmds entry.
type ScriptCommand struct {
	Name    string   `json:"n"`
	Path    string   `json:"p,omitempty"`
	Args    []string `json:"a,omitempty"`
	Origin  string   `json:"o,omitempty"`
	Dynamic bool     `json:"d,omitempty"`
}

// ScriptInstall is one shell.install_entries entry.
type ScriptInstall struct {
	Manager  string   `json:"m"`
	Packages []string `json:"p,omitempty"`
	Global   bool     `json:"g,omitempty"`
	Exec     bool     `json:"e,omitempty"`
	Flags    []string `json:"f,omitempty"`
}

// Bounds of one ScriptFacts. A session keeps a bounded number of them and
// exports them through a 64 KiB state file, so one script's facts are
// capped by count and by bytes; whatever a cap removes is named in Cut,
// which makes in_list and operator suppressions on it fail closed.
const (
	// MaxScriptBytes bounds the string bytes of one ScriptFacts.
	MaxScriptBytes   = 3 << 10
	maxScriptList    = 64  // entries per list feature
	maxScriptCmds    = 96  // shell.cmds entries
	maxScriptArgs    = 32  // arguments per command, packages and flags per install
	maxScriptString  = 512 // bytes per string
	maxScriptInstall = 16  // shell.install_entries entries
	maxScriptOrigin  = 64  // bytes of a command origin
)

// scriptKey reports the features a ScriptFacts keeps: every shell feature
// except the dialect (the executing event keeps its own), the flattened
// argument list (derived from Cmds when inherited) and the structured
// lists (kept as Cmds and Installs), every network feature, and the two
// content flags that say the analysis is incomplete.
func scriptKey(name string) bool {
	switch name {
	case "shell.dialect", "shell.argv", "shell.cmds", "shell.install_entries":
		return false
	case "content.truncated_scan", "content.analyzer_error":
		return true
	}
	return strings.HasPrefix(name, "shell.") || strings.HasPrefix(name, "net.")
}

// scriptFromFeat builds bounded ScriptFacts from a feature map computed
// over a script's content.
func scriptFromFeat(lang string, f map[string]any) *ScriptFacts {
	s := &ScriptFacts{Lang: lang, Bools: map[string]bool{}, Nums: map[string]float64{}, Lists: map[string][]string{}}
	for k, v := range f {
		if !scriptKey(k) {
			continue
		}
		switch t := v.(type) {
		case bool:
			s.Bools[k] = t
		case float64:
			s.Nums[k] = t
		case []string:
			s.Lists[k] = append([]string(nil), t...)
		}
	}
	if cmds, ok := f["shell.cmds"].([]map[string]any); ok {
		for _, m := range cmds {
			c := ScriptCommand{}
			c.Name, _ = m["name"].(string)
			c.Path, _ = m["path"].(string)
			c.Origin, _ = m["origin"].(string)
			c.Dynamic, _ = m["dynamic"].(bool)
			if a, ok := m["args"].([]string); ok {
				c.Args = append([]string(nil), a...)
			}
			s.Cmds = append(s.Cmds, c)
		}
	}
	if ins, ok := f["shell.install_entries"].([]map[string]any); ok {
		for _, m := range ins {
			in := ScriptInstall{}
			in.Manager, _ = m["manager"].(string)
			in.Global, _ = m["global"].(bool)
			in.Exec, _ = m["exec"].(bool)
			if p, ok := m["packages"].([]string); ok {
				in.Packages = append([]string(nil), p...)
			}
			if fl, ok := m["flags"].([]string); ok {
				in.Flags = append([]string(nil), fl...)
			}
			s.Installs = append(s.Installs, in)
		}
	}
	if cut, ok := f[truncatedKey].([]string); ok {
		for _, k := range cut {
			if strings.HasPrefix(k, "shell.") || strings.HasPrefix(k, "net.") {
				s.addCut(k)
			}
		}
	}
	s.bound()
	return s
}

func (s *ScriptFacts) addCut(k string) {
	for _, x := range s.Cut {
		if x == k {
			return
		}
	}
	s.Cut = append(s.Cut, k)
	if k == "shell.cmds" {
		// The flattened views of the commands are incomplete with them.
		s.addCut("shell.argv")
		s.addCut("shell.commands")
	}
}

// fitString returns v as valid UTF-8 of at most maxScriptString bytes
// (head and tail of a longer value) and whether it changed. Valid UTF-8
// matters for export: JSON rewrites a bad byte as three, so a value would
// not import as it was exported.
func fitString(v string) (string, bool) {
	changed := false
	if !utf8.ValidString(v) {
		v = strings.ToValidUTF8(v, "�")
		changed = true
	}
	if len(v) > maxScriptString {
		v = cutHead(v, maxScriptString/2) + cutTail(v, maxScriptString/2)
		changed = true
	}
	return v, changed
}

// fitList bounds a list to n entries (head and tail) of fitted strings,
// dropping empty and duplicate values, and reports whether it lost
// anything.
func fitList(l []string, n int) ([]string, bool) {
	cut := false
	var u uniqList
	for _, v := range l {
		fv, ch := fitString(v)
		cut = cut || ch
		u.add(fv)
	}
	kept, c := headTailCut(u.list, n)
	return kept, cut || c
}

// inertCommand reports commands whose presence matters to no rule once
// their redirections and paths are recorded elsewhere: they are the first
// to go when a script's facts are over budget.
func inertCommand(name string) bool {
	switch name {
	case "echo", "printf", "true", "false", ":", "cd", "pwd", "set", "export", "unset", "local",
		"readonly", "declare", "typeset", "shift", "sleep", "test", "[", "[[", "exit", "return",
		"wait", "read", "let", "write-host", "write-output", "print", "console.log":
		return true
	}
	return false
}

// bound applies the per-item caps, then the byte budget: duplicate
// commands go first (losslessly: any_command is existential), then inert
// ones, then half of the commands at a time (head and tail kept), then the
// longest list.
func (s *ScriptFacts) bound() {
	if s.Lang != "" {
		s.Lang, _ = fitString(s.Lang)
	}
	for k, l := range s.Lists {
		kept, cut := fitList(l, maxScriptList)
		if len(kept) == 0 {
			delete(s.Lists, k)
		} else {
			s.Lists[k] = kept
		}
		if cut {
			s.addCut(k)
		}
	}
	cmdCut := false
	seen := map[string]bool{}
	cmds := s.Cmds[:0:0]
	for _, c := range s.Cmds {
		var ch bool
		c.Name, ch = fitString(c.Name)
		cmdCut = cmdCut || ch
		c.Path, ch = fitString(c.Path)
		cmdCut = cmdCut || ch
		if len(c.Origin) > maxScriptOrigin || !utf8.ValidString(c.Origin) {
			c.Origin = shellx.OriginTop
			cmdCut = true
		}
		args := make([]string, 0, len(c.Args))
		for _, a := range c.Args {
			fa, ch := fitString(a)
			cmdCut = cmdCut || ch
			args = append(args, fa)
		}
		if kept, c2 := headTailCut(args, maxScriptArgs); c2 {
			args, cmdCut = kept, true
		}
		c.Args = args
		id := c.Name + "\x00" + c.Path + "\x00" + c.Origin + "\x00" + strings.Join(c.Args, "\x00")
		if c.Dynamic {
			id += "\x00d"
		}
		if seen[id] {
			continue
		}
		seen[id] = true
		cmds = append(cmds, c)
	}
	if kept, c := headTailCut(cmds, maxScriptCmds); c {
		cmds, cmdCut = kept, true
	}
	s.Cmds = cmds
	insCut := false
	if kept, c := headTailCut(s.Installs, maxScriptInstall); c {
		s.Installs, insCut = kept, true
	}
	for i := range s.Installs {
		in := &s.Installs[i]
		var ch bool
		in.Manager, ch = fitString(in.Manager)
		insCut = insCut || ch
		var c1, c2 bool
		in.Packages, c1 = fitList(in.Packages, maxScriptArgs)
		in.Flags, c2 = fitList(in.Flags, maxScriptArgs)
		insCut = insCut || c1 || c2
	}
shed:
	for s.size() > MaxScriptBytes {
		switch {
		case s.dropInert():
			cmdCut = true
		case len(s.Cmds) > 1:
			s.Cmds, _ = headTailCut(s.Cmds, len(s.Cmds)/2)
			cmdCut = true
		case s.halveLongestList():
		case len(s.Installs) > 0:
			s.Installs, _ = headTailCut(s.Installs, len(s.Installs)/2)
			insCut = true
		case len(s.Cmds) == 1:
			s.Cmds = nil
			cmdCut = true
		default:
			// Only single-entry lists, keys and scalars remain; the keys
			// are bounded by the registry.
			for k := range s.Lists {
				s.addCut(k)
			}
			s.Lists = map[string][]string{}
			break shed
		}
	}
	if cmdCut {
		s.addCut("shell.cmds")
	}
	if insCut {
		s.addCut("shell.install_entries")
	}
	sort.Strings(s.Cut)
}

func (s *ScriptFacts) dropInert() bool {
	out := s.Cmds[:0:0]
	for _, c := range s.Cmds {
		if !inertCommand(c.Name) {
			out = append(out, c)
		}
	}
	if len(out) == len(s.Cmds) {
		return false
	}
	s.Cmds = out
	return true
}

func (s *ScriptFacts) halveLongestList() bool {
	best, n := "", 1
	for k, l := range s.Lists {
		if len(l) > n || (len(l) == n && n > 1 && k < best) {
			best, n = k, len(l)
		}
	}
	if best == "" {
		return false
	}
	s.Lists[best], _ = headTailCut(s.Lists[best], n/2)
	s.addCut(best)
	return true
}

// size is the string bytes held, plus a small charge per string.
func (s *ScriptFacts) size() int {
	n := len(s.Lang)
	for k, l := range s.Lists {
		n += len(k)
		for _, v := range l {
			n += len(v) + 2
		}
	}
	for k := range s.Bools {
		n += len(k) + 2
	}
	for k := range s.Nums {
		n += len(k) + 8
	}
	for _, c := range s.Cmds {
		n += len(c.Name) + len(c.Path) + len(c.Origin) + 4
		for _, a := range c.Args {
			n += len(a) + 2
		}
	}
	for _, in := range s.Installs {
		n += len(in.Manager) + 4
		for _, p := range in.Packages {
			n += len(p) + 2
		}
		for _, f := range in.Flags {
			n += len(f) + 2
		}
	}
	for _, k := range s.Cut {
		n += len(k) + 2
	}
	return n
}

// Clone returns a deep copy.
func (s *ScriptFacts) Clone() *ScriptFacts {
	if s == nil {
		return nil
	}
	c := &ScriptFacts{Lang: s.Lang, Bools: map[string]bool{}, Nums: map[string]float64{}, Lists: map[string][]string{}}
	for k, v := range s.Bools {
		c.Bools[k] = v
	}
	for k, v := range s.Nums {
		c.Nums[k] = v
	}
	for k, v := range s.Lists {
		c.Lists[k] = append([]string(nil), v...)
	}
	for _, x := range s.Cmds {
		x.Args = append([]string(nil), x.Args...)
		c.Cmds = append(c.Cmds, x)
	}
	for _, x := range s.Installs {
		x.Packages = append([]string(nil), x.Packages...)
		x.Flags = append([]string(nil), x.Flags...)
		c.Installs = append(c.Installs, x)
	}
	c.Cut = append([]string(nil), s.Cut...)
	return c
}

// Merge adds o's facts to s, for an edit that adds a fragment to a file
// whose facts are known: lists are unioned, booleans ORed (shell.parse_ok
// ANDed), numbers take the maximum, commands and installs are appended,
// and the result is bounded again.
func (s *ScriptFacts) Merge(o *ScriptFacts) {
	if s == nil || o == nil {
		return
	}
	if s.Lang == "" {
		s.Lang = o.Lang
	}
	if s.Bools == nil {
		s.Bools = map[string]bool{}
	}
	if s.Nums == nil {
		s.Nums = map[string]float64{}
	}
	if s.Lists == nil {
		s.Lists = map[string][]string{}
	}
	for k, v := range o.Bools {
		cur, ok := s.Bools[k]
		if k == "shell.parse_ok" && ok {
			s.Bools[k] = cur && v
		} else {
			s.Bools[k] = cur || v
		}
	}
	for k, v := range o.Nums {
		if cur, ok := s.Nums[k]; !ok || v > cur {
			s.Nums[k] = v
		}
	}
	for k, l := range o.Lists {
		var u uniqList
		u.addAll(s.Lists[k])
		u.addAll(l)
		s.Lists[k] = u.list
	}
	o2 := o.Clone()
	s.Cmds = append(s.Cmds, o2.Cmds...)
	s.Installs = append(s.Installs, o2.Installs...)
	for _, k := range o.Cut {
		s.addCut(k)
	}
	s.bound()
}

// Validate checks facts that crossed a trust boundary (a session state
// file the monitored user can write): every name must be a feature
// ScriptFacts keeps, of the right type, with values inside the closed
// vocabulary where there is one, and every bound must hold. It accepts
// whatever bound produces.
func (s *ScriptFacts) Validate() error {
	if s == nil {
		return errors.New("features: nil script facts")
	}
	if !contains(ScriptLangs, s.Lang) {
		return fmt.Errorf("features: unknown script language %q", s.Lang)
	}
	check := func(name string, want Type) (FieldInfo, error) {
		fi, ok := Lookup(name)
		if !ok || fi.Origin != OriginFeature || fi.Type != want || !scriptKey(name) {
			return fi, fmt.Errorf("features: %q is not a script %s feature", name, want)
		}
		return fi, nil
	}
	for k := range s.Bools {
		if _, err := check(k, TypeBool); err != nil {
			return err
		}
	}
	for k := range s.Nums {
		if _, err := check(k, TypeNumber); err != nil {
			return err
		}
	}
	for k, l := range s.Lists {
		fi, err := check(k, TypeStrings)
		if err != nil {
			return err
		}
		if len(l) > maxScriptList {
			return fmt.Errorf("features: %q has %d entries", k, len(l))
		}
		for _, v := range l {
			if !okString(v) {
				return fmt.Errorf("features: bad value in %q", k)
			}
			if fi.Vocab != nil && !contains(fi.Vocab, v) {
				return fmt.Errorf("features: %q is outside the vocabulary of %q", v, k)
			}
		}
	}
	if len(s.Cmds) > maxScriptCmds {
		return fmt.Errorf("features: %d commands", len(s.Cmds))
	}
	for _, c := range s.Cmds {
		if !okString(c.Name) || !okString(c.Path) || len(c.Args) > maxScriptArgs || !validOrigin(c.Origin) {
			return errors.New("features: bad command")
		}
		for _, a := range c.Args {
			if !okString(a) {
				return errors.New("features: bad command argument")
			}
		}
	}
	if len(s.Installs) > maxScriptInstall {
		return fmt.Errorf("features: %d installs", len(s.Installs))
	}
	managers := shellx.Vocabulary()["PkgInstall.Manager"]
	for _, in := range s.Installs {
		if !contains(managers, in.Manager) || len(in.Packages) > maxScriptArgs || len(in.Flags) > maxScriptArgs {
			return errors.New("features: bad install")
		}
		for _, v := range append(append([]string(nil), in.Packages...), in.Flags...) {
			if !okString(v) {
				return errors.New("features: bad install value")
			}
		}
	}
	if len(s.Cut) > 2*maxScriptList {
		return errors.New("features: too many truncated fields")
	}
	for _, k := range s.Cut {
		if _, ok := Lookup(k); !ok || !(strings.HasPrefix(k, "shell.") || strings.HasPrefix(k, "net.")) {
			return fmt.Errorf("features: unknown truncated field %q", k)
		}
	}
	if s.size() > MaxScriptBytes {
		return fmt.Errorf("features: script facts of %d bytes", s.size())
	}
	return nil
}

func okString(v string) bool { return len(v) <= maxScriptString && utf8.ValidString(v) }

// validOrigin accepts the shellx origins: the fixed ones and
// "inline:<interpreter>".
func validOrigin(o string) bool {
	if len(o) > maxScriptOrigin || !utf8.ValidString(o) {
		return false
	}
	switch o {
	case "", shellx.OriginTop, shellx.OriginSubshell, shellx.OriginSubstitution, shellx.OriginEval,
		shellx.OriginDecoded, shellx.OriginWrapper:
		return true
	}
	return strings.HasPrefix(o, shellx.OriginInlinePrefix)
}
