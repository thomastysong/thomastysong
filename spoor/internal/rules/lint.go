package rules

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/features"
	"github.com/thomastysong/spoor/internal/shellx"
)

// Issue levels. CI should fail on errors; warnings are review prompts.
const (
	LevelError   = "error"
	LevelWarning = "warning"
)

// Issue is one Lint finding.
type Issue struct {
	RuleID string
	Level  string
	Code   string // stable slug: unknown_field, raw_command_match, ...
	Msg    string
}

func (i Issue) String() string {
	return fmt.Sprintf("%s %s [%s]: %s", i.Level, i.RuleID, i.Code, i.Msg)
}

var idStyle = regexp.MustCompile(`^[A-Z][A-Z0-9]*-[A-Z0-9]+-[0-9]{3,}$`)

// Lint checks a set for problems the loader accepts but a reviewer must
// not: missing descriptive fields, names that are not in the feature
// registry or the event field list, literals outside a closed vocabulary,
// type mismatches, unknown lists, regexes without a literal prefix, text
// matching on target.command (shell rules must use parsed facts), tests
// without a negative case (two for class alert), responses on event types
// that cannot be blocked, response: block in an embedded pack, duplicate
// ids, and rules that can have no effect. Issues are sorted by rule id.
func Lint(s *Set) []Issue {
	if s == nil {
		return nil
	}
	issues := append([]Issue(nil), s.issues...)
	setAnywhere := map[string]bool{}
	for _, r := range s.rules {
		for _, f := range r.setFlags {
			setAnywhere[f] = true
		}
	}
	for _, r := range s.rules {
		issues = append(issues, lintRule(s, r, setAnywhere)...)
	}
	sort.SliceStable(issues, func(i, j int) bool { return issues[i].RuleID < issues[j].RuleID })
	return issues
}

func lintRule(s *Set, r *rule, setAnywhere map[string]bool) []Issue {
	var out []Issue
	add := func(level, code, format string, a ...any) {
		out = append(out, Issue{RuleID: r.ID, Level: level, Code: code, Msg: fmt.Sprintf(format, a...)})
	}
	tests, err := r.testList()
	if err != nil {
		add(LevelError, "invalid_rule", "%v", err)
		return out
	}
	if strings.TrimSpace(r.Title) == "" {
		add(LevelError, "missing_field", "title is empty")
	}
	if strings.TrimSpace(r.Description) == "" {
		add(LevelWarning, "missing_field", "description is empty")
	}
	if r.Category == "" {
		add(LevelWarning, "missing_field", "category is empty")
	}
	if len(r.Tags) == 0 {
		add(LevelWarning, "missing_field", "no framework tags")
	}
	if r.emit && r.remedy == "" {
		add(LevelWarning, "missing_field", "remedy is empty")
	}
	if !idStyle.MatchString(r.ID) {
		add(LevelWarning, "id_format", "id does not follow PREFIX-AREA-NNN")
	}

	for _, part := range []struct {
		name string
		n    *node
	}{{"when", r.when}, {"match", r.match}, {"allow", r.allow}} {
		part.n.walk(scopeEvent, func(l *leaf, scope predScope) {
			for _, is := range lintLeaf(s, l, scope) {
				add(is.Level, is.Code, "%s (line %d): %s", part.name, l.line, is.Msg)
			}
		})
	}
	for _, list := range []struct {
		name   string
		fields []string
	}{{"dedup", r.dedup}, {"evidence", r.evidence}, {"novelty", noveltyFields(r)}} {
		for _, f := range list.fields {
			if fi, ok := features.Lookup(f); !ok {
				add(LevelError, "unknown_field", "%s: unknown field %q", list.name, f)
			} else if fi.Type == features.TypeObjects {
				add(LevelError, "type_mismatch", "%s: %q is structured; name a flat field", list.name, f)
			}
		}
	}

	neg, pos := 0, 0
	for _, t := range tests {
		if t.Expect == "no_match" {
			neg++
		} else {
			pos++
		}
	}
	switch {
	case r.Class == event.ClassAlert && neg < 2:
		add(LevelError, "test_negative", "class alert needs at least two no_match tests (has %d)", neg)
	case neg == 0:
		add(LevelWarning, "test_negative", "no no_match test")
	}
	if pos == 0 {
		add(LevelWarning, "test_positive", "no match test")
	}

	if r.response != ResponseNone {
		switch {
		case r.Kind == KindInventory:
			add(LevelError, "response_not_blockable", "inventory rules cannot ask or block")
		case r.whenTypes == nil:
			add(LevelWarning, "response_not_blockable", "response applies only to tool.pre and prompt.submit; add a when.type prefilter")
		default:
			ok := false
			for _, t := range r.whenTypes {
				ok = ok || blockable(t)
			}
			if !ok {
				add(LevelError, "response_not_blockable", "response %s on event types %v, none of which can be blocked", r.response, r.whenTypes)
			}
		}
		if r.response == ResponseBlock && r.embedded {
			add(LevelError, "embedded_block", "response: block is not allowed in an embedded pack (guard mode is opt-in; ship block rules in a bundle)")
		}
	}
	if r.Kind == KindInventory && (len(r.require) > 0 || len(r.requireAny) > 0 || len(r.setFlags) > 0) {
		add(LevelError, "inventory_flags", "inventory rules have no session and cannot use flags")
	}
	if !r.emit && len(r.setFlags) == 0 {
		add(LevelError, "no_effect", "emit is false and no flags are set: the rule can have no effect")
	}
	for _, f := range append(append([]string(nil), r.require...), r.requireAny...) {
		if !setAnywhere[f] {
			add(LevelWarning, "unknown_flag", "flag %q is required but no rule in the set sets it", f)
		}
	}
	return out
}

func noveltyFields(r *rule) []string {
	if r.novelty == nil {
		return nil
	}
	return r.novelty.fields
}

// lintLeaf checks one leaf against the registry.
func lintLeaf(s *Set, l *leaf, scope predScope) []Issue {
	var out []Issue
	add := func(level, code, format string, a ...any) {
		out = append(out, Issue{Level: level, Code: code, Msg: fmt.Sprintf(format, a...)})
	}
	var typ features.Type
	var vocab []string
	switch scope {
	case scopeCommand:
		t, ok := features.CommandKeys[l.field]
		if !ok {
			add(LevelError, "unknown_field", "any_command has no key %q", l.field)
			return out
		}
		typ = t
		if l.field == "origin" {
			vocab = shellx.Vocabulary()["Command.Origin"]
		}
	case scopeInstall:
		t, ok := features.InstallKeys[l.field]
		if !ok {
			add(LevelError, "unknown_field", "any_install has no key %q", l.field)
			return out
		}
		typ = t
		if l.field == "manager" {
			vocab = shellx.Vocabulary()["PkgInstall.Manager"]
		}
	default:
		fi, ok := features.Lookup(l.field)
		if !ok {
			add(LevelError, "unknown_field", "unknown field %q", l.field)
			return out
		}
		typ, vocab = fi.Type, fi.Vocab
	}

	if l.field == "target.command" && textMods[l.mod] {
		add(LevelError, "raw_command_match", "|%s on target.command: match parsed facts (shell.*, any_command) instead of command text", l.mod)
	}
	if typ == features.TypeObjects && l.mod != modExists && l.mod != modLenGt {
		add(LevelError, "type_mismatch", "%q is structured; use any_command / any_install", l.field)
		return out
	}

	isText := typ == features.TypeString || typ == features.TypeStrings
	switch l.mod {
	case modEq, modIn, modContainsAny, modContainsAll:
		for _, v := range l.vals {
			if !literalFits(typ, v) {
				add(LevelError, "type_mismatch", "%q is %s; literal %v (%T) can never match", l.field, typ, v, v)
				break
			}
		}
	case modContains, modIContains, modStartsWith, modEndsWith, modRe, modAnyStartsWith,
		modAnyEndsWith, modAnyRe, modAnyContains, modInList, modAnyInList, modCIDR:
		if !isText {
			add(LevelError, "type_mismatch", "|%s needs a string field; %q is %s", l.mod, l.field, typ)
		}
	case modGt, modGte, modLt, modLte:
		if typ != features.TypeNumber {
			add(LevelError, "type_mismatch", "|%s needs a number field; %q is %s", l.mod, l.field, typ)
		}
	case modLenGt:
		if typ == features.TypeBool || typ == features.TypeNumber {
			add(LevelError, "type_mismatch", "|len_gt needs a string or list field; %q is %s", l.field, typ)
		}
	}
	if (l.mod == modInList || l.mod == modAnyInList) && s.lists[l.list] == nil {
		add(LevelError, "unknown_list", "list %q is not defined in lists.yaml", l.list)
	}
	if len(vocab) > 0 && (l.mod == modEq || l.mod == modIn || l.mod == modContainsAny || l.mod == modContainsAll) {
		for _, v := range l.vals {
			sv, ok := v.(string)
			if !ok || inVocab(vocab, sv) {
				continue
			}
			add(LevelError, "unknown_value", "%q can never be %q (closed vocabulary)", l.field, sv)
		}
	}
	for _, r := range l.res {
		re, err := regexp.Compile(r.src)
		if err != nil {
			add(LevelError, "bad_regex", "%v", err)
			continue
		}
		if p, _ := re.LiteralPrefix(); p == "" {
			add(LevelWarning, "regex_no_prefix", "regex %q has no literal prefix; every value is scanned in full", r.src)
		}
	}
	return out
}

func literalFits(t features.Type, v any) bool {
	switch v.(type) {
	case string:
		return t == features.TypeString || t == features.TypeStrings
	case bool:
		return t == features.TypeBool
	case float64:
		return t == features.TypeNumber
	}
	return false
}

func inVocab(vocab []string, v string) bool {
	for _, x := range vocab {
		if x == v {
			return true
		}
		// Command.Origin has the open family "inline:<interp>".
		if strings.HasSuffix(x, "<interp>") && strings.HasPrefix(v, strings.TrimSuffix(x, "<interp>")) {
			return true
		}
	}
	return false
}
