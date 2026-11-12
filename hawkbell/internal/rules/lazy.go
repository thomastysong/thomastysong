package rules

import (
	"fmt"
	"reflect"
	"sync"

	"gopkg.in/yaml.v3"
)

// Lazily compiled rules.
//
// A guard-mode hook is a fresh process per tool call: it loads the whole
// embedded content and then evaluates the handful of rules that can ask or
// block. Compiling every predicate and decoding every description and
// inline test of 140 rules was most of its start-up. Content served from
// packs/embedded.cache was compiled whole when the cache was generated
// (EncodeCache refuses content that does not load), and the cache is used
// only for the exact YAML bytes it was made from, so a rule from the cache
// is compiled in steps:
//
//   - at load, the stub: id, kind, response, flags (require, require_any,
//     set, scope), the when prefilter and its event types: everything Set,
//     GuardSubset and NewEngine read, and what the engine checks before a
//     rule's match;
//   - on first use (the engine evaluating it past its prefilter, Lint,
//     RunTests, Rules), the body: the same decode and compileBody the YAML
//     path runs, from the same node;
//   - the inline tests only when a test run or the linter asks for them.
//
// The stub is taken only for the plain shapes rule content is written in;
// any other shape compiles the rule whole at load. The body must agree
// with the stub (TestLazyRulesMatchEager holds every embedded rule to
// that). A body that fails to compile or disagrees marks the rule invalid:
// it never fires, Lint and RunTests report it and Stats counts the
// evaluations it missed (rules_invalid). Rules from LoadDir, Load and the
// YAML fallback are always compiled whole, so content arriving at run time
// is rejected at load as before.

// lazyBody is the deferred part of a rule from the embedded cache.
type lazyBody struct {
	once sync.Once
	err  error

	tree      *cacheTree // the rule's subtrees not decoded yet
	tests     *yaml.Node // the rule's tests sequence
	testsOnce sync.Once
	testsErr  error
}

var (
	rawRuleType  = reflect.TypeOf(rawRule{})
	rawFlagsType = reflect.TypeOf(rawFlags{})
)

// ensure compiles the body of a lazy rule once; it returns the compile
// error, if any. It must be called before reading any field the stub does
// not set.
func (r *rule) ensure() error {
	l := r.lazy
	if l == nil {
		return nil
	}
	l.once.Do(func() { l.err = r.compileLazy() })
	return l.err
}

// testList returns the rule's inline tests, decoding them on first use for
// a lazy rule.
func (r *rule) testList() ([]rawTest, error) {
	l := r.lazy
	if l == nil {
		return r.tests, nil
	}
	if err := r.ensure(); err != nil {
		return nil, err
	}
	l.testsOnce.Do(func() {
		if err := l.tree.materialize(r.node, true); err != nil {
			l.testsErr = fmt.Errorf("rules: rule %s: %w", r.ID, err)
			return
		}
		var tl []rawTest
		if err := decodeNode(l.tests, &tl); err != nil {
			l.testsErr = fmt.Errorf("rules: rule %s: tests: %w", r.ID, err)
			return
		}
		if err := checkTests(r.ID, tl); err != nil {
			l.testsErr = err
			return
		}
		r.tests = tl
	})
	return r.tests, l.testsErr
}

// stubRule builds the load-time part of a rule from its node, or returns
// nil when the node is not in the plain shape the stub reads (the caller
// then compiles the rule whole, which also reports any error).
func stubRule(rn *yaml.Node, pack, version string, tree *cacheTree) *rule {
	if rn == nil || rn.Kind != yaml.MappingNode {
		return nil
	}
	known := yamlFields(rawRuleType)
	r := &rule{
		Kind: KindActivity, response: ResponseNone, flagScope: ScopeThread,
		pack: pack, packVersion: version, node: rn, lazy: &lazyBody{tree: tree},
	}
	var whenNode *yaml.Node
	var ok bool
	for i := 0; i+1 < len(rn.Content); i += 2 {
		k, v := rn.Content[i], rn.Content[i+1]
		if k.Kind != yaml.ScalarNode {
			return nil
		}
		if _, known := known[k.Value]; !known {
			return nil
		}
		switch k.Value {
		case "id":
			if r.ID, ok = plainString(v); !ok || !validRuleID(r.ID) {
				return nil
			}
		case "kind":
			s, isStr := plainString(v)
			if r.Kind, ok = oneOf(s, KindActivity, KindActivity, KindInventory); !isStr || !ok {
				return nil
			}
		case "response":
			s, isStr := plainString(v)
			if r.response, ok = oneOf(s, ResponseNone, ResponseNone, ResponseAsk, ResponseBlock); !isStr || !ok {
				return nil
			}
		case "flags":
			if !stubFlags(r, v) {
				return nil
			}
		case "when":
			whenNode = v
		case "tests":
			n := tree.childCount(v)
			if v.Kind != yaml.SequenceNode || n == 0 || n > maxTests {
				return nil
			}
			r.lazy.tests = v
			r.testCount = n
		}
	}
	if r.ID == "" || r.lazy.tests == nil {
		return nil
	}
	if whenNode != nil {
		w, err := compilePred(whenNode, scopeEvent)
		if err != nil {
			return nil
		}
		r.when = w
		if w != nil {
			r.whenTypes = typeLiterals(w)
		}
	}
	return r
}

// stubFlags reads flags.require, require_any, set and scope.
func stubFlags(r *rule, v *yaml.Node) bool {
	if v.Kind != yaml.MappingNode {
		return false
	}
	known := yamlFields(rawFlagsType)
	for i := 0; i+1 < len(v.Content); i += 2 {
		k, lv := v.Content[i], v.Content[i+1]
		if k.Kind != yaml.ScalarNode {
			return false
		}
		if _, ok := known[k.Value]; !ok {
			return false
		}
		var dst *[]string
		switch k.Value {
		case "require":
			dst = &r.require
		case "require_any":
			dst = &r.requireAny
		case "set":
			dst = &r.setFlags
		case "scope":
			s, isStr := plainString(lv)
			var ok bool
			if r.flagScope, ok = oneOf(s, ScopeThread, ScopeThread, ScopeSession); !isStr || !ok {
				return false
			}
			continue
		default:
			continue // ttl: the body validates it
		}
		if lv.Kind != yaml.SequenceNode || len(lv.Content) > maxFlagNames {
			return false
		}
		names := make([]string, 0, len(lv.Content))
		for _, c := range lv.Content {
			s, ok := plainString(c)
			if !ok || !validFlagName(s) {
				return false
			}
			names = append(names, s)
		}
		*dst = names
	}
	return true
}

// plainString returns the value of a scalar tagged as a string.
func plainString(n *yaml.Node) (string, bool) {
	if n == nil || n.Kind != yaml.ScalarNode || n.Tag != "!!str" {
		return "", false
	}
	return n.Value, true
}

// compileLazy compiles the body of a lazy rule into r: the rule without
// its tests, decoded and compiled exactly as the YAML path does.
func (r *rule) compileLazy() error {
	rn := r.node
	if err := r.lazy.tree.materialize(rn, false); err != nil {
		return fmt.Errorf("rules: rule %s: %w", r.ID, err)
	}
	body := *rn
	body.Content = make([]*yaml.Node, 0, len(rn.Content))
	for i := 0; i+1 < len(rn.Content); i += 2 {
		if rn.Content[i].Value != "tests" {
			body.Content = append(body.Content, rn.Content[i], rn.Content[i+1])
		}
	}
	var rr rawRule
	if err := decodeNode(&body, &rr); err != nil {
		return fmt.Errorf("rules: pack %s: rule %s: %w", r.pack, r.ID, err)
	}
	c, err := compileBody(&rr, r.pack, r.packVersion)
	if err != nil {
		return err
	}
	if c.ID != r.ID || c.Kind != r.Kind || c.response != r.response ||
		!sameStrings(c.require, r.require) || !sameStrings(c.requireAny, r.requireAny) || !sameStrings(c.setFlags, r.setFlags) ||
		c.flagScope != r.flagScope ||
		(c.when == nil) != (r.when == nil) || !sameStrings(c.whenTypes, r.whenTypes) {
		return fmt.Errorf("rules: rule %s: compiled body disagrees with its load-time stub", r.ID)
	}
	r.Title, r.Description, r.Class = c.Title, c.Description, c.Class
	r.Severity, r.Confidence, r.Maturity, r.Category = c.Severity, c.Confidence, c.Maturity, c.Category
	r.Tags, r.References, r.FalsePositives = c.Tags, c.References, c.FalsePositives
	r.match, r.allow = c.match, c.allow
	r.ttl = c.ttl
	r.threshold, r.emit, r.escalate = c.threshold, c.emit, c.escalate
	r.dedup, r.evidence, r.remedy, r.novelty = c.dedup, c.evidence, c.remedy, c.novelty
	return nil
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
