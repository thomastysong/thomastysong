package bench

import (
	"encoding/json"
	"fmt"
	"reflect"
	"sort"
)

// RenamedRun is the report, made before the rename (see RewriteOldName),
// that a regenerated report was compared with and found equal to. The
// hand review appended to a report may have been written for that run;
// the generated header then says so.
type RenamedRun struct {
	Date      string `json:"date"`
	RulesHash string `json:"rules_hash"`
}

// renamedIgnored are the fields CompareRenamed leaves out: they differ
// because of the rename or say when and how the report was made.
var renamedIgnored = map[string]bool{
	"date":                      true,
	"rules_hash":                true, // the rule text names the sensor
	"corpus":                    true,
	"renamed_from":              true,
	"rules[].samples[].summary": true, // evidence holds the name, cut to a length
}

// renamedIDPrefix is the part of a sampled event id that CompareRenamed
// compares: the 48-bit time prefix. The rest is keyed with the name.
const renamedIDPrefix = len("01a1ce88-def9")

const maxRenamedDiffs = 20

// CompareRenamed compares the JSON report of a benchmark made before the
// rename (before) with the JSON report of the same benchmark made now
// (now): scenario reports or replay reports. Every string in the old report
// is read through RewriteOldName first. The fields in renamedIgnored are
// left out, and a sampled event id is compared up to its time prefix. It
// returns the old run's date and packs hash and, when the reports differ,
// up to 20 differences.
func CompareRenamed(before, now []byte) (*RenamedRun, []string, error) {
	var a, b any
	if err := json.Unmarshal(before, &a); err != nil {
		return nil, nil, fmt.Errorf("report before the rename: %w", err)
	}
	if err := json.Unmarshal(now, &b); err != nil {
		return nil, nil, fmt.Errorf("report: %w", err)
	}
	top, ok := a.(map[string]any)
	if !ok {
		return nil, nil, fmt.Errorf("report before the rename: not a JSON object")
	}
	run := &RenamedRun{}
	run.Date, _ = top["date"].(string)
	run.RulesHash, _ = top["rules_hash"].(string)
	a = renamedNormalize(rewriteOldNameJSON(a), "")
	b = renamedNormalize(b, "")
	var diffs []string
	renamedDiff(a, b, "", &diffs)
	return run, diffs, nil
}

// rewriteOldNameJSON applies RewriteOldName to every key and string value.
func rewriteOldNameJSON(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			out[RewriteOldNameString(k)] = rewriteOldNameJSON(e)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = rewriteOldNameJSON(e)
		}
		return out
	case string:
		return RewriteOldNameString(x)
	}
	return v
}

func renamedNormalize(v any, path string) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			p := k
			if path != "" {
				p = path + "." + k
			}
			if renamedIgnored[p] {
				continue
			}
			if s, ok := e.(string); ok && p == "rules[].samples[].event_id" && len(s) > renamedIDPrefix {
				e = s[:renamedIDPrefix]
			}
			out[k] = renamedNormalize(e, p)
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, e := range x {
			out[i] = renamedNormalize(e, path+"[]")
		}
		return out
	}
	return v
}

func renamedDiff(a, b any, at string, diffs *[]string) {
	if len(*diffs) >= maxRenamedDiffs || reflect.DeepEqual(a, b) {
		return
	}
	add := func(format string, args ...any) {
		if len(*diffs) < maxRenamedDiffs {
			*diffs = append(*diffs, at+": "+fmt.Sprintf(format, args...))
		}
	}
	switch x := a.(type) {
	case map[string]any:
		y, ok := b.(map[string]any)
		if !ok {
			add("object before, %T now", b)
			return
		}
		keys := map[string]bool{}
		for k := range x {
			keys[k] = true
		}
		for k := range y {
			keys[k] = true
		}
		sorted := make([]string, 0, len(keys))
		for k := range keys {
			sorted = append(sorted, k)
		}
		sort.Strings(sorted)
		for _, k := range sorted {
			p := k
			if at != "" {
				p = at + "." + k
			}
			xv, xok := x[k]
			yv, yok := y[k]
			switch {
			case !yok:
				if len(*diffs) < maxRenamedDiffs {
					*diffs = append(*diffs, p+": only before the rename")
				}
			case !xok:
				if len(*diffs) < maxRenamedDiffs {
					*diffs = append(*diffs, p+": only now")
				}
			default:
				renamedDiff(xv, yv, p, diffs)
			}
		}
	case []any:
		y, ok := b.([]any)
		if !ok {
			add("array before, %T now", b)
			return
		}
		if len(x) != len(y) {
			add("%d elements before the rename, %d now", len(x), len(y))
			return
		}
		for i := range x {
			// Name an element by its id (a rule) when it has one.
			el := fmt.Sprintf("%s[%d]", at, i)
			if m, ok := x[i].(map[string]any); ok {
				if id, ok := m["id"].(string); ok && id != "" {
					el = fmt.Sprintf("%s[%s]", at, id)
				}
			}
			renamedDiff(x[i], y[i], el, diffs)
		}
	default:
		add("%s before the rename, %s now", renamedClip(a), renamedClip(b))
	}
}

func renamedClip(v any) string {
	s := fmt.Sprint(v)
	if len(s) > 80 {
		s = s[:80] + "..."
	}
	return fmt.Sprintf("%q", s)
}
