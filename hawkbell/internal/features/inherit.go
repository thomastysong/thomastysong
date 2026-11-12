package features

import (
	"sort"
	"strings"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// The shell.inherited_kinds values.
const (
	// InheritedWrittenScript marks an event that executes a script written
	// earlier in the session: its shell and network features include the
	// script's.
	InheritedWrittenScript = "written_script"
	// InheritedEditFragment marks an event whose inherited facts include
	// an edit analysed apart from the text around it (ScriptFacts.Fragment):
	// they may miss what the edit completes in the line it landed in.
	InheritedEditFragment = "edit_fragment"
)

// InheritedKinds is the vocabulary of shell.inherited_kinds.
var InheritedKinds = []string{InheritedWrittenScript, InheritedEditFragment}

// inheritedKey lists, per event, the scripts already merged into it, so a
// second Inherit of the same script (an event evaluated twice) adds
// nothing.
const inheritedKey = internalPrefix + "inherited"

// maxInherited bounds the scripts merged into one event.
const maxInherited = 16

// Inherit merges the facts of a script that e executes into e's own
// features (computed first with Compute): list features are unioned and
// cut to the usual caps (head and tail), booleans ORed (shell.parse_ok
// ANDed), numbers take the maximum, the script's commands and installs are
// appended to shell.cmds and shell.install_entries (and their names and
// arguments to shell.commands and shell.argv), and incomplete features
// join content.truncated_fields. The event then carries the facts it would
// have had with the script's content on its own command line, within the
// bounds of ScriptFacts: what the bounds shed is what no rule matched when
// the script was written (see ScriptKeep), and is recorded as incomplete,
// so the same rules fire on it. shell.inherited_kinds records that it
// happened ("written_script", and "edit_fragment" for facts that include
// an edit analysed out of context), and output.untrusted is recomputed for
// a shell result whose script downloads or reads third-party content. key
// identifies the script (the caller's path digest): a second Inherit with
// the same key on the same event is a no-op (see Inherited). It returns
// whether anything was merged and never panics.
func Inherit(e *event.Event, s *ScriptFacts, key string) (ok bool) {
	if e == nil || s == nil {
		return false
	}
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	if e.Feat == nil {
		e.Feat = make(map[string]any, 32)
	}
	f := e.Feat
	done, _ := f[inheritedKey].([]string)
	if contains(done, key) || len(done) >= maxInherited {
		return false
	}
	f[inheritedKey] = append(append([]string(nil), done...), key)

	var cut []string
	for k, v := range s.Bools {
		cur, has := f[k].(bool)
		switch {
		case k == "shell.parse_ok" && has:
			f[k] = cur && v
		default:
			f[k] = cur || v
		}
	}
	for k, v := range s.Nums {
		if cur, has := f[k].(float64); !has || v > cur {
			f[k] = v
		}
	}
	for k, l := range s.Lists {
		if unionInto(f, k, l, maxList) {
			cut = append(cut, k)
		}
	}
	cut = append(cut, inheritCommands(f, s.Cmds)...)
	if len(s.Installs) > 0 {
		cur, _ := f["shell.install_entries"].([]map[string]any)
		out := make([]map[string]any, 0, len(cur)+len(s.Installs))
		out = append(out, cur...)
		for _, in := range s.Installs {
			out = append(out, map[string]any{
				"manager":  in.Manager,
				"packages": append([]string{}, in.Packages...),
				"global":   in.Global,
				"exec":     in.Exec,
				"flags":    append([]string{}, in.Flags...),
			})
		}
		if kept, c := headTailCut(out, maxList); c {
			out = kept
			cut = append(cut, "shell.install_entries")
		}
		f["shell.install_entries"] = out
	}
	cut = append(cut, s.Cut...)
	if len(cut) > 0 {
		unionInto(f, truncatedKey, cut, 4*maxList)
		if l, _ := f[truncatedKey].([]string); l != nil {
			sorted := append([]string(nil), l...)
			sort.Strings(sorted)
			f[truncatedKey] = sorted
		}
		for _, k := range cut {
			if strings.HasPrefix(k, "shell.") {
				f["shell.truncated"] = true
				break
			}
		}
	}
	kinds := []string{InheritedWrittenScript}
	if s.Fragment {
		kinds = append(kinds, InheritedEditFragment)
	}
	unionInto(f, "shell.inherited_kinds", kinds, maxList)

	// A shell result is attacker-authorable when the command downloads or
	// reads third-party content; the script may be what does that.
	if e.Tool != nil && e.Tool.Kind == event.ToolShell {
		if u, has := f["output.untrusted"].(bool); has && !u {
			c := &computer{e: e, f: f}
			if src := c.untrustedSource(); src != "" {
				f["output.untrusted"] = true
				f["output.untrusted_source"] = src
			}
		}
	}
	return true
}

// Inherited reports whether the script key was merged into e already, by
// an earlier Inherit on the same event (an event evaluated again keeps its
// features, inherited ones included).
func Inherited(e *event.Event, key string) bool {
	if e == nil || e.Feat == nil {
		return false
	}
	done, _ := e.Feat[inheritedKey].([]string)
	return contains(done, key)
}

// unionInto adds l to the []string feature k (first-seen order, no
// duplicates), cut to n entries, head and tail; it reports a cut.
func unionInto(f map[string]any, k string, l []string, n int) bool {
	if len(l) == 0 {
		return false
	}
	var u uniqList
	cur, _ := f[k].([]string)
	u.addAll(cur)
	u.addAll(l)
	if len(u.list) == 0 {
		return false
	}
	kept, c := headTailCut(u.list, n)
	if !c {
		kept = u.list
	}
	f[k] = kept
	return c
}

// inheritCommands appends the script's commands to shell.cmds and their
// names, arguments and dynamism to shell.commands, shell.argv and
// shell.dynamic, and returns the features it had to cut.
func inheritCommands(f map[string]any, cmds []ScriptCommand) []string {
	if len(cmds) == 0 {
		return nil
	}
	var cut []string
	cur, _ := f["shell.cmds"].([]map[string]any)
	out := make([]map[string]any, 0, len(cur)+len(cmds))
	out = append(out, cur...)
	names := make([]string, 0, len(cmds))
	var argv []string
	dynamic := false
	for _, c := range cmds {
		args := append([]string{}, c.Args...)
		out = append(out, map[string]any{
			"name":    c.Name,
			"path":    c.Path,
			"args":    args,
			"origin":  c.Origin,
			"dynamic": c.Dynamic,
		})
		names = append(names, c.Name)
		argv = append(argv, args...)
		dynamic = dynamic || c.Dynamic
	}
	if kept, c := headTailCut(out, maxCmds); c {
		out = kept
		cut = append(cut, "shell.cmds")
	}
	f["shell.cmds"] = out
	if unionInto(f, "shell.commands", names, maxList) {
		cut = append(cut, "shell.commands")
	}
	if len(argv) > 0 {
		cur, _ := f["shell.argv"].([]string)
		all := make([]string, 0, len(cur)+len(argv))
		all = append(append(all, cur...), argv...)
		if kept, c := headTailCut(all, maxArgv); c {
			all = kept
			cut = append(cut, "shell.argv")
		}
		f["shell.argv"] = all
	}
	if d, _ := f["shell.dynamic"].(bool); dynamic || d {
		f["shell.dynamic"] = true
	}
	return cut
}
