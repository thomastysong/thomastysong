package rules

import (
	"strings"
	"sync"

	"github.com/thomastysong/thomastysong/hawkbell/internal/features"
)

// scriptKeep tells the bounds of a written script's facts what the
// engine's rules can match (features.ScriptKeep), so a script padded with
// ordinary commands keeps the one a rule matches. A command is kept first
// when the inner predicate of some any_command of some rule holds for it
// on its own, or when one of its arguments satisfies a rule's shell.argv
// leaf; a list value when a rule's leaf on that feature holds for a list
// of that value alone. Either way the other conditions of the rule are
// not consulted: a kept command is one the rule could need.
//
// The index is built from the engine's rules on the first script whose
// facts are over their bounds, so a hook process that never meets one does
// not compile the bodies of lazily loaded rules for it.
type scriptKeep struct {
	once   sync.Once
	rules  []*rule
	lists  map[string]*namedList
	byName map[string][]*node // any_command predicates that need one of these names
	other  []*node            // any_command predicates that name no literal command
	argv   []*leaf            // leaves on shell.argv
	values map[string][]*leaf // leaves on other list features
	ctx    *evalCtx
}

func newScriptKeep(rs []*rule, lists map[string]*namedList) *scriptKeep {
	return &scriptKeep{rules: rs, lists: lists}
}

func (k *scriptKeep) build() {
	k.once.Do(func() {
		k.byName = map[string][]*node{}
		k.values = map[string][]*leaf{}
		k.ctx = &evalCtx{lists: k.lists}
		seen := map[*node]bool{}
		for _, r := range k.rules {
			if r.lazy != nil && r.ensure() != nil {
				continue
			}
			for _, n := range []*node{r.when, r.match, r.allow} {
				k.collect(n, seen)
			}
		}
	})
}

// collect records the any_command predicates and the event-scope leaves
// of n.
func (k *scriptKeep) collect(n *node, seen map[*node]bool) {
	if n == nil {
		return
	}
	switch n.kind {
	case nCommand:
		inner := n.kids[0]
		if seen[inner] {
			return
		}
		seen[inner] = true
		if names := commandNames(inner); names != nil {
			for _, nm := range names {
				k.byName[nm] = append(k.byName[nm], inner)
			}
		} else {
			k.other = append(k.other, inner)
		}
	case nInstall:
	case nLeaf:
		l := n.leaf
		switch {
		case l.field == "shell.argv":
			k.argv = append(k.argv, l)
		case strings.HasPrefix(l.field, "shell.") || strings.HasPrefix(l.field, "net."):
			k.values[l.field] = append(k.values[l.field], l)
		}
	default:
		for _, c := range n.kids {
			k.collect(c, seen)
		}
	}
}

// commandNames returns the command names an any_command predicate can
// hold for (a name or name|in leaf it requires), or nil when it does not
// say.
func commandNames(n *node) []string {
	switch n.kind {
	case nLeaf:
		l := n.leaf
		if l.field != "name" || (l.mod != modEq && l.mod != modIn) {
			return nil
		}
		var out []string
		for _, v := range l.vals {
			s, ok := v.(string)
			if !ok {
				return nil
			}
			out = append(out, s)
		}
		return out
	case nAll:
		for _, c := range n.kids {
			if names := commandNames(c); names != nil {
				return names
			}
		}
	case nAny:
		var out []string
		for _, c := range n.kids {
			names := commandNames(c)
			if names == nil {
				return nil
			}
			out = append(out, names...)
		}
		return out
	}
	return nil
}

// Command implements features.ScriptKeep.
func (k *scriptKeep) Command(c features.ScriptCommand) bool {
	k.build()
	args := c.Args
	if args == nil {
		args = []string{}
	}
	m := map[string]any{"name": c.Name, "path": c.Path, "args": args, "origin": c.Origin, "dynamic": c.Dynamic}
	for _, n := range k.byName[c.Name] {
		if n.eval(m, k.ctx) {
			return true
		}
	}
	for _, n := range k.other {
		if n.eval(m, k.ctx) {
			return true
		}
	}
	for _, l := range k.argv {
		if len(args) > 0 && l.eval(args, true, k.ctx) {
			return true
		}
	}
	return false
}

// Value implements features.ScriptKeep.
func (k *scriptKeep) Value(name, v string) bool {
	k.build()
	for _, l := range k.values[name] {
		if l.eval([]string{v}, true, k.ctx) {
			return true
		}
	}
	return false
}
