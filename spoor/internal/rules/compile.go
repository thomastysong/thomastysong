package rules

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/thomastysong/spoor/internal/event"
)

// Rule vocabularies.
const (
	KindActivity  = "activity"
	KindInventory = "inventory"

	ResponseNone  = "none"
	ResponseAsk   = "ask"
	ResponseBlock = "block"

	ScopeThread  = "thread"
	ScopeSession = "session"

	BySession = "session"
	ByUser    = "user"
	ByHost    = "host"
)

const (
	maxTTL       = 30 * 24 * time.Hour
	maxWindow    = 30 * 24 * time.Hour
	maxThreshold = 256
)

var (
	ruleIDRe = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	flagRe   = regexp.MustCompile(`^[a-z0-9][a-z0-9_.:-]{0,63}$`)
)

// rule is one compiled rule. It is immutable after compilation.
type rule struct {
	ID, Title, Description string
	Kind, Class            string
	Severity, Confidence   string
	Maturity, Category     string
	Tags                   []string
	References             []string
	FalsePositives         []string

	when      *node
	whenTypes []string // when.type literals; nil means any type
	match     *node
	allow     *node

	require, requireAny, setFlags []string
	ttl                           time.Duration
	flagScope                     string

	threshold *threshold
	emit      bool
	escalate  bool
	response  string
	dedup     []string
	evidence  []string
	remedy    string
	novelty   *novelty

	tests     []rawTest
	testCount int

	pack, packVersion string
	embedded          bool

	// The canonical JSON of the definition (for Hash) is rendered on first
	// use from the retained node: most hook processes never need it, and
	// rendering is a third of the cost of loading a pack.
	node      *yaml.Node
	canonOnce sync.Once
	canon     []byte
}

func (r *rule) canonical() []byte {
	r.canonOnce.Do(func() {
		if r.canon == nil {
			r.canon = canonical(r.node)
		}
		r.node = nil
	})
	return r.canon
}

type threshold struct {
	count  int
	window time.Duration
	by     string
}

type novelty struct {
	fields []string
	raise  bool
}

func oneOf(v, def string, allowed ...string) (string, bool) {
	if v == "" {
		return def, true
	}
	for _, a := range allowed {
		if v == a {
			return v, true
		}
	}
	return v, false
}

// compileRule validates one rule. Errors here are structural: a rule that
// cannot be evaluated as written. Quality problems are Lint's job.
func compileRule(rr *rawRule, ruleNode *yaml.Node, pack, version string) (*rule, error) {
	r := &rule{
		ID: rr.ID, Title: rr.Title, Description: rr.Description, Category: rr.Category,
		Tags: rr.Tags, References: rr.References, FalsePositives: rr.FalsePositives,
		escalate: rr.Escalate, dedup: rr.Dedup, evidence: rr.Evidence, remedy: rr.Remedy,
		tests: rr.Tests, pack: pack, packVersion: version,
	}
	if !ruleIDRe.MatchString(r.ID) {
		return nil, fmt.Errorf("rule id %q: use letters, digits, '.', '-' and '_' (at most 64)", r.ID)
	}
	fail := func(format string, a ...any) error {
		return fmt.Errorf("rule %s: %s", r.ID, fmt.Sprintf(format, a...))
	}
	var ok bool
	if r.Kind, ok = oneOf(rr.Kind, KindActivity, KindActivity, KindInventory); !ok {
		return nil, fail("kind %q: want activity or inventory", rr.Kind)
	}
	if r.Class, ok = oneOf(rr.Class, event.ClassFinding, event.ClassSignal, event.ClassFinding, event.ClassAlert); !ok {
		return nil, fail("class %q: want signal, finding or alert", rr.Class)
	}
	if rr.Severity == "" {
		return nil, fail("severity is required")
	}
	if r.Severity, ok = oneOf(rr.Severity, "", event.SevInfo, event.SevLow, event.SevMedium, event.SevHigh, event.SevCritical); !ok {
		return nil, fail("severity %q: want info, low, medium, high or critical", rr.Severity)
	}
	if r.Confidence, ok = oneOf(rr.Confidence, "medium", "low", "medium", "high"); !ok {
		return nil, fail("confidence %q: want low, medium or high", rr.Confidence)
	}
	if r.Maturity, ok = oneOf(rr.Maturity, "experimental", "stable", "experimental"); !ok {
		return nil, fail("maturity %q: want stable or experimental", rr.Maturity)
	}
	if r.response, ok = oneOf(rr.Response, ResponseNone, ResponseNone, ResponseAsk, ResponseBlock); !ok {
		return nil, fail("response %q: want none, ask or block", rr.Response)
	}
	r.emit = true
	if rr.Emit != nil {
		r.emit = *rr.Emit
	}

	var err error
	if r.when, err = compilePred(&rr.When, scopeEvent); err != nil {
		return nil, fail("when: %v", err)
	}
	if r.when != nil {
		r.whenTypes = typeLiterals(r.when)
	}
	if rr.Match.Kind == 0 {
		return nil, fail("match is required")
	}
	if r.match, err = compilePred(&rr.Match, scopeEvent); err != nil {
		return nil, fail("match: %v", err)
	}
	if r.allow, err = compilePred(&rr.Allow, scopeEvent); err != nil {
		return nil, fail("allow: %v", err)
	}

	r.flagScope = ScopeThread
	if f := rr.Flags; f != nil {
		for _, set := range [][]string{f.Require, f.RequireAny, f.Set} {
			if len(set) > maxFlagNames {
				return nil, fail("flags: more than %d names in one list", maxFlagNames)
			}
			for _, name := range set {
				if !flagRe.MatchString(name) {
					return nil, fail("flag name %q: use lower-case letters, digits, '_', '.', ':' and '-'", name)
				}
			}
		}
		r.require, r.requireAny, r.setFlags = f.Require, f.RequireAny, f.Set
		if f.TTL != "" {
			if r.ttl, err = parseDuration(f.TTL); err != nil || r.ttl <= 0 || r.ttl > maxTTL {
				return nil, fail("flags.ttl %q: want a positive duration up to 30d", f.TTL)
			}
		}
		if r.flagScope, ok = oneOf(f.Scope, ScopeThread, ScopeThread, ScopeSession); !ok {
			return nil, fail("flags.scope %q: want thread or session", f.Scope)
		}
	}
	if t := rr.Threshold; t != nil {
		th := &threshold{count: t.Count}
		if th.count < 1 || th.count > maxThreshold {
			return nil, fail("threshold.count %d: want 1 to %d", t.Count, maxThreshold)
		}
		if t.Window != "" {
			if th.window, err = parseDuration(t.Window); err != nil || th.window < 0 || th.window > maxWindow {
				return nil, fail("threshold.window %q: want a duration from 0s to 30d", t.Window)
			}
		}
		if th.by, ok = oneOf(t.By, BySession, BySession, ByUser, ByHost); !ok {
			return nil, fail("threshold.by %q: want session, user or host", t.By)
		}
		r.threshold = th
	}
	if nv := rr.Novelty; nv != nil {
		if len(nv.Fields) == 0 {
			return nil, fail("novelty.fields is required")
		}
		r.novelty = &novelty{fields: nv.Fields, raise: nv.Raise}
	}
	for _, list := range [][]string{r.dedup, r.evidence} {
		if len(list) > maxFieldNames {
			return nil, fail("more than %d field names in dedup or evidence", maxFieldNames)
		}
		for _, f := range list {
			if !validFieldName(f) {
				return nil, fail("field name %q is not valid", f)
			}
		}
	}
	if r.novelty != nil {
		for _, f := range r.novelty.fields {
			if !validFieldName(f) {
				return nil, fail("novelty field name %q is not valid", f)
			}
		}
	}
	if len(rr.Tests) == 0 {
		return nil, fail("at least one test is required")
	}
	if len(rr.Tests) > maxTests {
		return nil, fail("more than %d tests", maxTests)
	}
	for i := range rr.Tests {
		t := &rr.Tests[i]
		if t.Name == "" {
			return nil, fail("test %d has no name", i+1)
		}
		if t.Expect != "match" && t.Expect != "no_match" {
			return nil, fail("test %q: expect must be match or no_match", t.Name)
		}
		if (t.Event.Kind == 0) == (len(t.Events) == 0) {
			return nil, fail("test %q: give exactly one of event or events", t.Name)
		}
		if len(t.Events) > 64 {
			return nil, fail("test %q: more than 64 events", t.Name)
		}
		for _, name := range t.Flags {
			if !flagRe.MatchString(name) {
				return nil, fail("test %q: flag name %q is not valid", t.Name, name)
			}
		}
	}
	r.node = ruleNode
	r.testCount = len(rr.Tests)
	return r, nil
}

// typeLiterals returns the event types a when predicate requires, when it
// is (or starts with a conjunction containing) a plain "type" leaf. The
// engine indexes rules by them; any other shape means "any type".
func typeLiterals(n *node) []string {
	var leaves []*leaf
	switch n.kind {
	case nLeaf:
		leaves = []*leaf{n.leaf}
	case nAll:
		for _, k := range n.kids {
			if k.kind == nLeaf {
				leaves = append(leaves, k.leaf)
			}
		}
	}
	for _, l := range leaves {
		if l.field != "type" || (l.mod != modEq && l.mod != modIn) {
			continue
		}
		var out []string
		for _, v := range l.vals {
			if s, ok := v.(string); ok {
				out = append(out, s)
			}
		}
		if len(out) > 0 {
			return out
		}
	}
	return nil
}

// parseDuration accepts Go durations plus a "d" (day) unit.
func parseDuration(s string) (time.Duration, error) {
	if strings.HasSuffix(s, "d") {
		n, err := strconv.ParseFloat(strings.TrimSuffix(s, "d"), 64)
		if err != nil || n < 0 || n > 3650 {
			return 0, fmt.Errorf("bad duration %q", s)
		}
		return time.Duration(n * float64(24*time.Hour)), nil
	}
	return time.ParseDuration(s)
}

// canonical renders a YAML node as JSON with sorted keys, so formatting and
// comments do not change a rule set's hash but content does.
func canonical(n *yaml.Node) []byte {
	if n == nil {
		return nil
	}
	var v any
	if err := n.Decode(&v); err != nil {
		return []byte(n.Value)
	}
	b, err := json.Marshal(jsonable(v))
	if err != nil {
		return nil
	}
	return b
}

// jsonable converts yaml.v3's decoded values (map[string]any with possibly
// non-string keys, time.Time) into JSON-encodable ones.
func jsonable(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[k] = jsonable(x)
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, x := range t {
			out[fmt.Sprint(k)] = jsonable(x)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = jsonable(x)
		}
		return out
	case time.Time:
		return t.UTC().Format(time.RFC3339Nano)
	}
	return v
}
