package features

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/thomastysong/spoor/internal/classify"
	"github.com/thomastysong/spoor/internal/shellx"
)

// ScriptFacts are the shell features of a written script's content, as a
// shell event carrying that content would get them (shell.* and the net.*
// derived from its URLs and hosts), reduced to what matching a later
// execution needs and bounded for session state. The rule engine keeps
// them per path and exports them with a one-shot hook process's session,
// so they are small, hold no raw content beyond the analyzer's commands,
// arguments and list values, and hold no credential value: every argument
// and value passes through the evidence stage's redaction (classify) and a
// credential is kept as "[REDACTED:<kind>]", with its kind in
// shell.secret_kinds. They are validated as hostile input on import
// (Validate).
type ScriptFacts struct {
	Lang     string              `json:"l"`
	Bools    map[string]bool     `json:"b,omitempty"`
	Nums     map[string]float64  `json:"n,omitempty"`
	Lists    map[string][]string `json:"s,omitempty"`
	Cmds     []ScriptCommand     `json:"c,omitempty"`
	Installs []ScriptInstall     `json:"i,omitempty"`
	// Cut names the features whose value is incomplete (a size cap of the
	// analyzer or of these bounds, the time budget, or a fragment); they
	// join content.truncated_fields of the event that inherits them.
	Cut []string `json:"x,omitempty"`
	// Fragment is set when the facts include an edit analysed apart from
	// the text around it (the file's text was not held): a change that is
	// harmless on its own can complete a dangerous line. An event that
	// inherits them carries shell.inherited_kinds = edit_fragment.
	Fragment bool `json:"g,omitempty"`
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
func scriptFromFeat(lang string, f map[string]any, keep ScriptKeep) *ScriptFacts {
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
	s.bound(keep)
	return s
}

// cutFacts are the facts of a script none of which was analysed because
// the event's time budget ran out first: unknown, which is recorded as
// incomplete, never as clean.
func cutFacts(lang string) *ScriptFacts {
	s := &ScriptFacts{Lang: lang, Bools: map[string]bool{"shell.truncated": true, "content.truncated_scan": true},
		Nums: map[string]float64{}, Lists: map[string][]string{}}
	s.addCut("shell.cmds")
	sort.Strings(s.Cut)
	return s
}

// markFragment records that s are the facts of an edit analysed apart
// from the text around it.
func (s *ScriptFacts) markFragment(keep ScriptKeep) {
	if s == nil {
		return
	}
	s.Fragment = true
	s.addCut("shell.cmds")
	s.bound(keep)
}

// addSecretKinds records credential kinds the facts' text carries in a
// form the analysis does not see (redaction markers of a held text).
func (s *ScriptFacts) addSecretKinds(kinds []string, keep ScriptKeep) {
	if s == nil || len(kinds) == 0 {
		return
	}
	if s.Bools == nil {
		s.Bools = map[string]bool{}
	}
	if s.Lists == nil {
		s.Lists = map[string][]string{}
	}
	s.Bools["shell.has_secret"] = true
	s.Lists["shell.secret_kinds"] = sortedUniq(append(append([]string(nil), s.Lists["shell.secret_kinds"]...), kinds...))
	s.bound(keep)
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
		v = strings.ToValidUTF8(v, "\uFFFD")
		changed = true
	}
	if len(v) > maxScriptString {
		v = cutHead(v, maxScriptString/2) + cutTail(v, maxScriptString/2)
		changed = true
	}
	return v, changed
}

// fitList bounds the list feature name to n entries of fitted strings,
// dropping empty and duplicate values, and reports whether it lost
// anything. Values a rule matches (keep) are kept first; of the rest, the
// head and the tail.
func fitList(name string, l []string, n int, keep ScriptKeep) ([]string, bool) {
	cut := false
	var u uniqList
	for _, v := range l {
		fv, ch := fitString(v)
		cut = cut || ch
		u.add(fv)
	}
	if len(u.list) <= n {
		return u.list, cut
	}
	return pickRanked(u.list, n, valueRanks(name, u.list, keep)), true
}

// valueRanks ranks the values of a list feature: 1 for a value a rule
// matches, 0 for the others.
func valueRanks(name string, l []string, keep ScriptKeep) []int {
	r := make([]int, len(l))
	if keep == nil {
		return r
	}
	for i, v := range l {
		if keep.Value(name, v) {
			r[i] = 1
		}
	}
	return r
}

// cmdRanks orders commands for shedding: one a rule's command predicate
// matches (2) outlasts any other (1), which outlasts a command whose
// presence matters to no rule once its paths are recorded elsewhere (0).
func cmdRanks(cmds []ScriptCommand, keep ScriptKeep) []int {
	r := make([]int, len(cmds))
	for i, c := range cmds {
		switch {
		case keep != nil && keep.Command(c):
			r[i] = 2
		case !inertCommand(c.Name):
			r[i] = 1
		}
	}
	return r
}

// pickRanked returns n entries of l: every entry of the highest ranks
// that fit whole, and the head and the tail of the rank that does not, in
// their original order.
func pickRanked[T any](l []T, n int, rank []int) []T {
	if len(l) <= n {
		return l
	}
	top := 0
	for _, r := range rank {
		top = max(top, r)
	}
	count := make([]int, top+1)
	for _, r := range rank {
		count[r]++
	}
	room, tier := n, top
	for ; tier > 0 && count[tier] < room; tier-- {
		room -= count[tier]
	}
	// Of the boundary tier, keep the first room/2 and the last room -
	// room/2 entries.
	head, tail := room/2, room-room/2
	seen := 0
	out := make([]T, 0, n)
	for i, v := range l {
		switch {
		case rank[i] > tier:
			out = append(out, v)
		case rank[i] == tier:
			if seen < head || seen >= count[tier]-tail {
				out = append(out, v)
			}
			seen++
		}
	}
	return out
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

// bound applies the per-item caps and the byte budget (fit, shed), then
// redacts credentials; a redaction marker can be longer than the value it
// replaces, so the budget is applied again after it.
func (s *ScriptFacts) bound(keep ScriptKeep) {
	s.fit(keep)
	s.shed(keep)
	if s.redact() {
		s.fit(keep)
		s.shed(keep)
	}
	sort.Strings(s.Cut)
}

// fit applies the per-item caps: string length and validity, entries per
// list, arguments per command, commands, installs. Duplicate commands go
// first (losslessly: any_command is existential); the count caps keep
// what a rule matches first.
func (s *ScriptFacts) fit(keep ScriptKeep) {
	if s.Lang != "" {
		s.Lang, _ = fitString(s.Lang)
	}
	for k, l := range s.Lists {
		kept, cut := fitList(k, l, maxScriptList, keep)
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
	if len(cmds) > maxScriptCmds {
		cmds, cmdCut = pickRanked(cmds, maxScriptCmds, cmdRanks(cmds, keep)), true
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
		in.Packages, c1 = fitList("", in.Packages, maxScriptArgs, nil)
		in.Flags, c2 = fitList("", in.Flags, maxScriptArgs, nil)
		insCut = insCut || c1 || c2
	}
	if cmdCut {
		s.addCut("shell.cmds")
	}
	if insCut {
		s.addCut("shell.install_entries")
	}
}

// shed applies the byte budget. What no rule can match goes first, so
// padding a script with ordinary commands, paths or hosts costs the
// commands and values a rule matches nothing: inert commands, then half
// of the other commands no rule matches at a time (head and tail kept),
// then half of the unmatched values of the list with most of them; only
// then half of the matched commands, the longest list, the installs.
func (s *ScriptFacts) shed(keep ScriptKeep) {
	cmdCut, insCut := false, false
	var ranks []int
shed:
	for s.size() > MaxScriptBytes {
		if len(ranks) != len(s.Cmds) {
			ranks = cmdRanks(s.Cmds, keep)
		}
		switch {
		case s.dropRank(&ranks, 0, false):
			cmdCut = true
		case s.dropRank(&ranks, 1, true):
			cmdCut = true
		case keep != nil && s.halveUnmatchedList(keep):
		case s.dropRank(&ranks, 2, true):
			cmdCut = true
		case s.halveLongestList():
		case len(s.Installs) > 0:
			s.Installs, _ = headTailCut(s.Installs, len(s.Installs)/2)
			insCut = true
		case len(s.Cmds) == 1:
			s.Cmds, ranks = nil, nil
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
}

// dropRank removes the commands of rank r: all of them, or with half half
// of them (the head and the tail kept; one command is removed). It reports
// whether any went.
func (s *ScriptFacts) dropRank(ranks *[]int, r int, half bool) bool {
	n := 0
	for _, x := range *ranks {
		if x == r {
			n++
		}
	}
	if n == 0 {
		return false
	}
	keepN := 0
	if half {
		keepN = n / 2
	}
	head, tail := keepN/2, keepN-keepN/2
	cmds := s.Cmds[:0:0]
	rs := (*ranks)[:0:0]
	seen := 0
	for i, c := range s.Cmds {
		if (*ranks)[i] == r {
			keepIt := seen < head || seen >= n-tail
			seen++
			if !keepIt {
				continue
			}
		}
		cmds = append(cmds, c)
		rs = append(rs, (*ranks)[i])
	}
	s.Cmds, *ranks = cmds, rs
	return true
}

// halveUnmatchedList halves the values no rule matches of the list that
// has most of them (head and tail kept; a single one is removed).
func (s *ScriptFacts) halveUnmatchedList(keep ScriptKeep) bool {
	best, most := "", 0
	var bestRanks []int
	for k, l := range s.Lists {
		r := valueRanks(k, l, keep)
		n := 0
		for _, x := range r {
			if x == 0 {
				n++
			}
		}
		if n > most || (n == most && n > 0 && k < best) {
			best, most, bestRanks = k, n, r
		}
	}
	if most == 0 {
		return false
	}
	l := s.Lists[best]
	s.Lists[best] = pickRanked(l, len(l)-most+most/2, bestRanks)
	if len(s.Lists[best]) == 0 {
		delete(s.Lists, best)
	}
	s.addCut(best)
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

// redact replaces credentials in every argument, path and value the
// facts hold (lists with a closed vocabulary hold none) and reports
// whether anything changed.
func (s *ScriptFacts) redact() bool {
	changed := false
	set := func(dst *string, v string) {
		if v != *dst {
			*dst, changed = v, true
		}
	}
	for i := range s.Cmds {
		c := &s.Cmds[i]
		if len(c.Args) > 0 {
			red := redactArgs(c.Name, c.Args)
			for j := range c.Args {
				set(&c.Args[j], red[j])
			}
		}
		if c.Path != "" {
			set(&c.Path, redactValue(c.Path))
		}
	}
	for k, l := range s.Lists {
		if fi, ok := Lookup(k); ok && fi.Vocab != nil {
			continue
		}
		for i := range l {
			set(&l[i], redactValue(l[i]))
		}
	}
	for i := range s.Installs {
		in := &s.Installs[i]
		for j := range in.Packages {
			set(&in.Packages[j], redactValue(in.Packages[j]))
		}
		for j := range in.Flags {
			set(&in.Flags[j], redactValue(in.Flags[j]))
		}
	}
	return changed
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
	c := &ScriptFacts{Lang: s.Lang, Bools: map[string]bool{}, Nums: map[string]float64{}, Lists: map[string][]string{}, Fragment: s.Fragment}
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
// and the result is bounded again (keep orders what is shed, as for
// AnalyzeScript).
func (s *ScriptFacts) Merge(o *ScriptFacts, keep ScriptKeep) {
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
	s.Fragment = s.Fragment || o.Fragment
	s.bound(keep)
}

// Inert reports facts no rule can match: no command, install or list
// value, and no boolean set but shell.parse_ok. A session's bounded script
// memory gives up inert facts first (an inert fragment of a file nothing
// else is known about included: forgetting it loses nothing).
func (s *ScriptFacts) Inert() bool {
	if s == nil {
		return true
	}
	if len(s.Cmds) > 0 || len(s.Installs) > 0 {
		return false
	}
	for k, v := range s.Bools {
		if v && k != "shell.parse_ok" {
			return false
		}
	}
	for _, l := range s.Lists {
		if len(l) > 0 {
			return false
		}
	}
	return true
}

// Notable reports facts that say a script does more than run ordinary
// commands on ordinary files: a download, an interpreter fed code, eval,
// privilege, a semantic category (destructive, persistence, credential
// access, exfiltration ...), a credential, an install, a sensitive path
// class or a risky host class, an incomplete analysis. A session's bounded
// script memory keeps notable facts longest.
func (s *ScriptFacts) Notable() bool {
	if s == nil {
		return false
	}
	if len(s.Installs) > 0 {
		return true
	}
	for _, k := range [...]string{"shell.downloads", "shell.pipe_to_interpreter", "shell.download_and_execute",
		"shell.eval", "shell.sudo", "shell.background", "shell.decoded", "shell.has_secret", "shell.install_exec",
		"shell.dynamic", "shell.truncated", "net.url_has_secret", "net.is_ip"} {
		if s.Bools[k] {
			return true
		}
	}
	for _, k := range [...]string{"shell.obfuscation", "shell.opaque", "shell.destructive", "shell.persistence",
		"shell.defense_evasion", "shell.cred_access", "shell.exfil", "shell.net_tools", "shell.recon",
		"shell.privilege", "shell.git_ops", "shell.secret_kinds", "shell.installs", "shell.inline_langs",
		"shell.interpreters", "shell.executes_paths"} {
		if len(s.Lists[k]) > 0 {
			return true
		}
	}
	if classify.IsSensitiveRead(s.Lists["shell.read_classes"]) || classify.IsSensitiveWrite(s.Lists["shell.write_classes"]) ||
		classify.IsSensitiveWrite(s.Lists["shell.delete_classes"]) {
		return true
	}
	for _, h := range s.Lists["shell.host_classes"] {
		switch h {
		case classify.HostCodeHost, classify.HostPackageRegistry, classify.HostLoopback, classify.HostPrivateIP, classify.HostLLMAPI:
		default:
			return true
		}
	}
	return false
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
