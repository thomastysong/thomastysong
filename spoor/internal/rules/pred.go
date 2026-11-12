package rules

import (
	"fmt"
	"net/netip"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

type nodeKind uint8

const (
	nAll nodeKind = iota
	nAny
	nNot
	nLeaf
	nCommand // any_command: one parsed command satisfies the inner predicate
	nInstall // any_install: one install entry satisfies the inner predicate
)

// node is one compiled predicate. Trees are immutable after compilation and
// shared by every engine that uses the set.
type node struct {
	kind nodeKind
	kids []*node
	leaf *leaf
	line int
}

// Modifiers.
const (
	modEq            = ""
	modContains      = "contains"
	modIContains     = "icontains"
	modStartsWith    = "startswith"
	modEndsWith      = "endswith"
	modRe            = "re"
	modIn            = "in"
	modContainsAny   = "contains_any"
	modContainsAll   = "contains_all"
	modInList        = "in_list"
	modAnyInList     = "any_in_list"
	modGt            = "gt"
	modGte           = "gte"
	modLt            = "lt"
	modLte           = "lte"
	modExists        = "exists"
	modLenGt         = "len_gt"
	modCIDR          = "cidr"
	modAnyStartsWith = "any_startswith"
	modAnyEndsWith   = "any_endswith"
	modAnyRe         = "any_re"
	modAnyContains   = "any_contains"
)

var knownMods = map[string]bool{
	modEq: true, modContains: true, modIContains: true, modStartsWith: true, modEndsWith: true, modRe: true,
	modIn: true, modContainsAny: true, modContainsAll: true, modInList: true, modAnyInList: true, modGt: true,
	modGte: true, modLt: true, modLte: true, modExists: true, modLenGt: true, modCIDR: true,
	modAnyStartsWith: true, modAnyEndsWith: true, modAnyRe: true, modAnyContains: true,
}

// textMods are the modifiers that match raw text. The linter forbids them
// on target.command: shell rules must use parsed facts (measured on real
// sessions, regexes over command text produced dozens of false hits from
// heredocs and quoted prose that parsed-fact rules did not).
var textMods = map[string]bool{modRe: true, modContains: true, modIContains: true, modStartsWith: true, modEndsWith: true}

// leaf is "field|modifier: value".
type leaf struct {
	field string
	mod   string
	vals  []any     // literals: string, bool or float64
	lower []string  // lower-cased string literals for icontains
	res   []*lazyRE // re, any_re
	list  string    // in_list, any_in_list
	num   float64   // gt, gte, lt, lte, len_gt
	want  bool      // exists
	cidrs []netip.Prefix
	line  int
}

// lazyRE compiles on first use: a hook process loads every rule but
// evaluates few of them, and compiling hundreds of regexes it never runs
// would dominate its start-up time. The syntax is validated at load.
type lazyRE struct {
	src  string
	once sync.Once
	re   *regexp.Regexp
}

func (l *lazyRE) get() *regexp.Regexp {
	l.once.Do(func() {
		l.re, _ = regexp.Compile(l.src)
	})
	return l.re
}

// predScope says which names a predicate may use: the event field view, or
// the keys of one shell.cmds / shell.install_entries entry.
type predScope uint8

const (
	scopeEvent predScope = iota
	scopeCommand
	scopeInstall
)

// compilePred compiles a predicate mapping. Several keys in one mapping are
// a conjunction; all/any take a sequence of mappings; not takes a mapping.
func compilePred(n *yaml.Node, scope predScope) (*node, error) {
	if n == nil || n.Kind == 0 {
		return nil, nil
	}
	if n.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("line %d: a predicate must be a mapping", n.Line)
	}
	if len(n.Content) == 0 {
		return nil, fmt.Errorf("line %d: empty predicate", n.Line)
	}
	var kids []*node
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		kid, err := compileKey(k.Value, v, scope, k.Line)
		if err != nil {
			return nil, err
		}
		kids = append(kids, kid)
	}
	if len(kids) == 1 {
		return kids[0], nil
	}
	return &node{kind: nAll, kids: kids, line: n.Line}, nil
}

func compileKey(key string, v *yaml.Node, scope predScope, line int) (*node, error) {
	switch key {
	case "all", "any":
		if v.Kind != yaml.SequenceNode || len(v.Content) == 0 {
			return nil, fmt.Errorf("line %d: %s needs a non-empty list of predicates", line, key)
		}
		nd := &node{kind: nAll, line: line}
		if key == "any" {
			nd.kind = nAny
		}
		for _, c := range v.Content {
			kid, err := compilePred(c, scope)
			if err != nil {
				return nil, err
			}
			nd.kids = append(nd.kids, kid)
		}
		return nd, nil
	case "not":
		kid, err := compilePred(v, scope)
		if err != nil {
			return nil, err
		}
		if kid == nil {
			return nil, fmt.Errorf("line %d: not needs a predicate", line)
		}
		return &node{kind: nNot, kids: []*node{kid}, line: line}, nil
	case "any_command", "any_install":
		if scope != scopeEvent {
			return nil, fmt.Errorf("line %d: %s cannot be nested", line, key)
		}
		inner := scopeCommand
		kind := nCommand
		if key == "any_install" {
			inner, kind = scopeInstall, nInstall
		}
		kid, err := compilePred(v, inner)
		if err != nil {
			return nil, err
		}
		if kid == nil {
			return nil, fmt.Errorf("line %d: %s needs a predicate", line, key)
		}
		return &node{kind: kind, kids: []*node{kid}, line: line}, nil
	}
	lf, err := compileLeaf(key, v, line)
	if err != nil {
		return nil, err
	}
	return &node{kind: nLeaf, leaf: lf, line: line}, nil
}

func compileLeaf(key string, v *yaml.Node, line int) (*leaf, error) {
	field, mod, _ := strings.Cut(key, "|")
	if strings.Contains(mod, "|") {
		return nil, fmt.Errorf("line %d: %q: one modifier per leaf", line, key)
	}
	if !validFieldName(field) {
		return nil, fmt.Errorf("line %d: %q is not a valid field name", line, field)
	}
	if !knownMods[mod] {
		return nil, fmt.Errorf("line %d: unknown modifier %q", line, mod)
	}
	lf := &leaf{field: field, mod: mod, line: line}
	vals, err := literals(v)
	if err != nil {
		return nil, fmt.Errorf("line %d: %s: %v", line, key, err)
	}
	if len(vals) == 0 {
		return nil, fmt.Errorf("line %d: %s: empty value", line, key)
	}
	if len(vals) > 1000 {
		return nil, fmt.Errorf("line %d: %s: more than 1000 values", line, key)
	}
	switch mod {
	case modEq, modIn, modContainsAny, modContainsAll:
		lf.vals = vals
	case modContains, modIContains, modStartsWith, modEndsWith, modAnyStartsWith, modAnyEndsWith, modAnyContains:
		for _, x := range vals {
			s, ok := x.(string)
			if !ok {
				return nil, fmt.Errorf("line %d: %s takes strings", line, key)
			}
			lf.vals = append(lf.vals, s)
			lf.lower = append(lf.lower, strings.ToLower(s))
		}
	case modRe, modAnyRe:
		for _, x := range vals {
			s, ok := x.(string)
			if !ok {
				return nil, fmt.Errorf("line %d: %s takes regular expressions", line, key)
			}
			if err := validRegex(s); err != nil {
				return nil, fmt.Errorf("line %d: %s: %v", line, key, err)
			}
			lf.res = append(lf.res, &lazyRE{src: s})
		}
	case modInList, modAnyInList:
		s, ok := vals[0].(string)
		if !ok || len(vals) != 1 || !validListName(s) {
			return nil, fmt.Errorf("line %d: %s takes one list name", line, key)
		}
		lf.list = s
	case modGt, modGte, modLt, modLte, modLenGt:
		f, ok := vals[0].(float64)
		if !ok || len(vals) != 1 {
			return nil, fmt.Errorf("line %d: %s takes one number", line, key)
		}
		lf.num = f
	case modExists:
		b, ok := vals[0].(bool)
		if !ok || len(vals) != 1 {
			return nil, fmt.Errorf("line %d: %s takes true or false", line, key)
		}
		lf.want = b
	case modCIDR:
		for _, x := range vals {
			s, ok := x.(string)
			if !ok {
				return nil, fmt.Errorf("line %d: %s takes CIDR strings", line, key)
			}
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("line %d: %s: %v", line, key, err)
			}
			lf.cidrs = append(lf.cidrs, p.Masked())
		}
	}
	return lf, nil
}

func validRegex(s string) error {
	if len(s) > MaxRegexLen {
		return fmt.Errorf("regular expression longer than %d characters", MaxRegexLen)
	}
	if _, err := syntax.Parse(s, syntax.Perl); err != nil {
		return err
	}
	return nil
}

// literals decodes a scalar or a sequence of scalars.
func literals(v *yaml.Node) ([]any, error) {
	switch v.Kind {
	case yaml.ScalarNode:
		x, err := scalar(v)
		if err != nil {
			return nil, err
		}
		return []any{x}, nil
	case yaml.SequenceNode:
		out := make([]any, 0, len(v.Content))
		for _, c := range v.Content {
			if c.Kind != yaml.ScalarNode {
				return nil, fmt.Errorf("lists hold scalars only")
			}
			x, err := scalar(c)
			if err != nil {
				return nil, err
			}
			out = append(out, x)
		}
		return out, nil
	}
	return nil, fmt.Errorf("value must be a scalar or a list of scalars")
}

func scalar(n *yaml.Node) (any, error) {
	switch n.Tag {
	case "!!bool":
		var b bool
		if err := n.Decode(&b); err != nil {
			return nil, err
		}
		return b, nil
	case "!!int", "!!float":
		f, err := strconv.ParseFloat(strings.ReplaceAll(n.Value, "_", ""), 64)
		if err != nil {
			var i int64
			if err2 := n.Decode(&i); err2 != nil {
				return nil, err
			}
			f = float64(i)
		}
		return f, nil
	case "!!null":
		return nil, fmt.Errorf("null is not a value")
	default:
		return n.Value, nil
	}
}

func validFieldName(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-' || c == '*') {
			return false
		}
	}
	return true
}

func validListName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// evalCtx is what predicate evaluation needs beyond the field view.
type evalCtx struct {
	lists       map[string]*namedList
	missingList func(string)
}

// eval evaluates n over fields. A missing field never matches, except
// |exists: false.
func (n *node) eval(fields map[string]any, c *evalCtx) bool {
	switch n.kind {
	case nAll:
		for _, k := range n.kids {
			if !k.eval(fields, c) {
				return false
			}
		}
		return true
	case nAny:
		for _, k := range n.kids {
			if k.eval(fields, c) {
				return true
			}
		}
		return false
	case nNot:
		return !n.kids[0].eval(fields, c)
	case nCommand, nInstall:
		key := "shell.cmds"
		if n.kind == nInstall {
			key = "shell.install_entries"
		}
		items, _ := fields[key].([]map[string]any)
		for _, it := range items {
			if n.kids[0].eval(it, c) {
				return true
			}
		}
		return false
	case nLeaf:
		v, ok := fields[n.leaf.field]
		return n.leaf.eval(v, ok, c)
	}
	return false
}

func (l *leaf) eval(v any, ok bool, c *evalCtx) bool {
	if l.mod == modExists {
		return present(v, ok) == l.want
	}
	if !present(v, ok) {
		return false
	}
	switch l.mod {
	case modEq, modIn:
		return anyElem(v, func(x any) bool {
			for _, want := range l.vals {
				if equal(x, want) {
					return true
				}
			}
			return false
		})
	case modContainsAny, modContainsAll:
		have := asList(v)
		if have == nil {
			return false
		}
		hit := 0
		for _, want := range l.vals {
			found := false
			for _, x := range have {
				if equal(x, want) {
					found = true
					break
				}
			}
			if found {
				hit++
				if l.mod == modContainsAny {
					return true
				}
			} else if l.mod == modContainsAll {
				return false
			}
		}
		return l.mod == modContainsAll && hit == len(l.vals)
	case modContains, modAnyContains:
		return anyString(v, func(s string) bool { return anyOf(l.vals, func(w string) bool { return strings.Contains(s, w) }) })
	case modIContains:
		return anyString(v, func(s string) bool {
			ls := strings.ToLower(s)
			for _, w := range l.lower {
				if strings.Contains(ls, w) {
					return true
				}
			}
			return false
		})
	case modStartsWith, modAnyStartsWith:
		return anyString(v, func(s string) bool { return anyOf(l.vals, func(w string) bool { return strings.HasPrefix(s, w) }) })
	case modEndsWith, modAnyEndsWith:
		return anyString(v, func(s string) bool { return anyOf(l.vals, func(w string) bool { return strings.HasSuffix(s, w) }) })
	case modRe, modAnyRe:
		return anyString(v, func(s string) bool {
			for _, r := range l.res {
				if re := r.get(); re != nil && re.MatchString(s) {
					return true
				}
			}
			return false
		})
	case modInList, modAnyInList:
		lst := c.lists[l.list]
		if lst == nil {
			if c.missingList != nil {
				c.missingList(l.list)
			}
			return false
		}
		switch t := v.(type) {
		case string:
			return lst.match(t)
		case []string:
			if l.mod == modAnyInList {
				for _, s := range t {
					if lst.match(s) {
						return true
					}
				}
				return false
			}
			// in_list on a list: every element must be listed, so one
			// trusted host cannot vouch for an untrusted one in the same
			// command.
			for _, s := range t {
				if !lst.match(s) {
					return false
				}
			}
			return len(t) > 0
		}
		return false
	case modGt, modGte, modLt, modLte:
		f, ok := v.(float64)
		if !ok {
			return false
		}
		switch l.mod {
		case modGt:
			return f > l.num
		case modGte:
			return f >= l.num
		case modLt:
			return f < l.num
		default:
			return f <= l.num
		}
	case modLenGt:
		switch t := v.(type) {
		case string:
			return float64(len(t)) > l.num
		case []string:
			return float64(len(t)) > l.num
		case []map[string]any:
			return float64(len(t)) > l.num
		}
		return false
	case modCIDR:
		return anyString(v, func(s string) bool {
			a, err := netip.ParseAddr(strings.Trim(stripZone(s), "[]"))
			if err != nil {
				return false
			}
			a = a.Unmap()
			for _, p := range l.cidrs {
				if p.Contains(a) {
					return true
				}
			}
			return false
		})
	}
	return false
}

func stripZone(s string) string {
	if i := strings.IndexByte(s, '%'); i >= 0 {
		return s[:i]
	}
	return s
}

// present reports whether a value counts as set: absent keys, empty strings
// and empty lists do not.
func present(v any, ok bool) bool {
	if !ok || v == nil {
		return false
	}
	switch t := v.(type) {
	case string:
		return t != ""
	case []string:
		return len(t) > 0
	case []map[string]any:
		return len(t) > 0
	}
	return true
}

func anyElem(v any, f func(any) bool) bool {
	if l, ok := v.([]string); ok {
		for _, s := range l {
			if f(s) {
				return true
			}
		}
		return false
	}
	return f(v)
}

func anyString(v any, f func(string) bool) bool {
	switch t := v.(type) {
	case string:
		return f(t)
	case []string:
		for _, s := range t {
			if f(s) {
				return true
			}
		}
	}
	return false
}

func anyOf(ws []any, f func(string) bool) bool {
	for _, w := range ws {
		if s, ok := w.(string); ok && f(s) {
			return true
		}
	}
	return false
}

func asList(v any) []any {
	switch t := v.(type) {
	case []string:
		out := make([]any, len(t))
		for i, s := range t {
			out[i] = s
		}
		return out
	case string, bool, float64:
		return []any{t}
	}
	return nil
}

// equal compares a field value with a literal of the same type. Values of
// different types are never equal: the linter reports such rules.
func equal(x, want any) bool {
	switch a := x.(type) {
	case string:
		b, ok := want.(string)
		return ok && a == b
	case bool:
		b, ok := want.(bool)
		return ok && a == b
	case float64:
		b, ok := want.(float64)
		return ok && a == b
	}
	return false
}

// walk visits every leaf of a tree with the scope it is evaluated in.
func (n *node) walk(scope predScope, f func(l *leaf, scope predScope)) {
	if n == nil {
		return
	}
	switch n.kind {
	case nLeaf:
		f(n.leaf, scope)
	case nCommand:
		n.kids[0].walk(scopeCommand, f)
	case nInstall:
		n.kids[0].walk(scopeInstall, f)
	default:
		for _, k := range n.kids {
			k.walk(scope, f)
		}
	}
}

// usesQuantifier reports whether the tree reads shell.cmds or
// shell.install_entries through a quantifier.
func (n *node) quantifies(kind nodeKind) bool {
	if n == nil {
		return false
	}
	if n.kind == kind {
		return true
	}
	for _, k := range n.kids {
		if k.quantifies(kind) {
			return true
		}
	}
	return false
}
