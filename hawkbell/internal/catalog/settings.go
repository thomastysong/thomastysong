package catalog

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// Limits for evaluating a setting against a parsed config document. The
// document is a user-writable (often project-writable) file.
const (
	maxKeySegments = 16
	maxWildcardFan = 256
)

// Eval applies the setting's Key, Op and Value to a decoded document and
// reports whether the risky condition holds.
//
// doc is the result of decoding the file into generic Go values
// (map[string]any, []any, scalars) or, for format "env", a map[string]string
// of the process environment.
//
// Comparison rules:
//   - Scalars are compared by their text form: true/false for booleans,
//     shortest decimal for numbers.
//   - exists hits when the key is present, whatever its value.
//   - eq hits when a value at the key equals Value; in hits when it equals
//     one of the comma-separated items of Value.
//   - ne is the negation of eq, so it also hits when the key is absent:
//     "the lock is not set" is the finding.
//   - contains hits when a string value contains Value, a list has an
//     element equal to Value, or a map has the key Value.
//   - A "*" segment matches every key or list element at that level; the
//     setting hits if any of the matched values does.
//
// actual is safe to emit: it is "present", "absent", a boolean or number, or
// text taken from the catalog itself. Free-form strings from the file are
// reported as "(other value)", because a config value can be a credential.
func (s Setting) Eval(doc any) (hit bool, actual string) {
	defer func() {
		if r := recover(); r != nil {
			hit, actual = false, ""
		}
	}()
	segs, err := splitKey(s.Key)
	if err != nil {
		return false, ""
	}
	var vals []any
	if env, ok := doc.(map[string]string); ok {
		if v, ok := env[s.Key]; ok {
			vals = []any{v}
		}
	} else {
		budget := maxWildcardFan
		vals = lookup(doc, segs, &budget)
	}
	found := len(vals) > 0
	switch s.Op {
	case "exists":
		if found {
			return true, "present"
		}
		return false, "absent"
	case "eq", "in":
		want := []string{s.Value}
		if s.Op == "in" {
			want = splitList(s.Value)
		}
		for _, v := range vals {
			if t, ok := scalarText(v); ok {
				for _, w := range want {
					if t == w {
						return true, w
					}
				}
			}
		}
		return false, describe(vals)
	case "ne":
		for _, v := range vals {
			if t, ok := scalarText(v); ok && t == s.Value {
				return false, s.Value
			}
		}
		return true, describe(vals)
	case "contains":
		for _, v := range vals {
			switch t := v.(type) {
			case string:
				if strings.Contains(t, s.Value) {
					return true, s.Value
				}
			case []any:
				for _, el := range t {
					if et, ok := scalarText(el); ok && et == s.Value {
						return true, s.Value
					}
				}
			case []string:
				for _, el := range t {
					if el == s.Value {
						return true, s.Value
					}
				}
			case map[string]any:
				if _, ok := t[s.Value]; ok {
					return true, s.Value
				}
			}
		}
		return false, describe(vals)
	}
	return false, ""
}

// describe summarizes what was found without echoing free-form strings.
func describe(vals []any) string {
	if len(vals) == 0 {
		return "absent"
	}
	switch v := vals[0].(type) {
	case bool, int, int64, uint64, float64:
		t, _ := scalarText(v)
		return t
	case nil:
		return "null"
	}
	return "(other value)"
}

func scalarText(v any) (string, bool) {
	switch t := v.(type) {
	case string:
		return t, true
	case bool:
		return strconv.FormatBool(t), true
	case int:
		return strconv.Itoa(t), true
	case int64:
		return strconv.FormatInt(t, 10), true
	case uint64:
		return strconv.FormatUint(t, 10), true
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64), true
	}
	return "", false
}

func splitList(s string) []string {
	parts := strings.Split(s, ",")
	out := parts[:0]
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// lookup walks the document along the key segments. budget bounds the total
// number of nodes a wildcard may fan out to.
func lookup(doc any, segs []string, budget *int) []any {
	if len(segs) == 0 {
		return []any{doc}
	}
	if *budget <= 0 {
		return nil
	}
	seg, rest := segs[0], segs[1:]
	var out []any
	switch t := doc.(type) {
	case map[string]any:
		if seg == "*" {
			for _, v := range t {
				*budget--
				if *budget < 0 {
					break
				}
				out = append(out, lookup(v, rest, budget)...)
			}
			return out
		}
		if v, ok := t[seg]; ok {
			return lookup(v, rest, budget)
		}
	case map[any]any: // some YAML decoders
		if seg == "*" {
			for _, v := range t {
				*budget--
				if *budget < 0 {
					break
				}
				out = append(out, lookup(v, rest, budget)...)
			}
			return out
		}
		if v, ok := t[seg]; ok {
			return lookup(v, rest, budget)
		}
	case []any:
		if seg == "*" {
			for _, v := range t {
				*budget--
				if *budget < 0 {
					break
				}
				out = append(out, lookup(v, rest, budget)...)
			}
			return out
		}
		if i, err := strconv.Atoi(seg); err == nil && i >= 0 && i < len(t) {
			return lookup(t[i], rest, budget)
		}
	}
	return nil
}

// splitKey splits a dotted key. A segment that itself contains dots is
// written in double quotes: projects."/home/a.b".trust_level.
func splitKey(key string) ([]string, error) {
	if key == "" {
		return nil, errors.New("empty key")
	}
	var segs []string
	for i := 0; i < len(key); {
		var seg string
		if key[i] == '"' {
			j := strings.IndexByte(key[i+1:], '"')
			if j < 0 {
				return nil, errors.New("unterminated quote in key")
			}
			seg = key[i+1 : i+1+j]
			i += j + 2
			if i < len(key) {
				if key[i] != '.' {
					return nil, errors.New("expected . after quoted key segment")
				}
				i++
				if i == len(key) {
					return nil, errors.New("key ends with a dot")
				}
			}
		} else {
			j := strings.IndexByte(key[i:], '.')
			if j < 0 {
				seg = key[i:]
				i = len(key)
			} else {
				seg = key[i : i+j]
				i += j + 1
				if i == len(key) {
					return nil, errors.New("key ends with a dot")
				}
			}
			if seg == "" {
				return nil, errors.New("empty key segment")
			}
		}
		segs = append(segs, seg)
		if len(segs) > maxKeySegments {
			return nil, fmt.Errorf("key has more than %d segments", maxKeySegments)
		}
	}
	return segs, nil
}

// RiskyArgs returns the product's risky flags that are present in a command
// line, in catalog order and catalog spelling (never the raw argument, which
// may carry a secret). A "--flag value" entry matches both "--flag value" and
// "--flag=value". Scanning stops at "--", after which arguments are operands.
func (p Product) RiskyArgs(args []string) []string {
	if len(p.RiskyFlags) == 0 || len(args) == 0 {
		return nil
	}
	if len(args) > 4096 {
		args = args[:4096]
	}
	for i, a := range args {
		if a == "--" {
			args = args[:i]
			break
		}
	}
	var out []string
	for _, rf := range p.RiskyFlags {
		flag, value, hasValue := strings.Cut(rf, " ")
		for i, a := range args {
			if hasValue {
				if (a == flag && i+1 < len(args) && args[i+1] == value) || a == flag+"="+value {
					out = append(out, rf)
					break
				}
				continue
			}
			if a == flag {
				out = append(out, rf)
				break
			}
			if v, ok := strings.CutPrefix(a, flag+"="); ok && !isFalse(v) {
				out = append(out, rf)
				break
			}
		}
	}
	return out
}

func isFalse(v string) bool {
	switch strings.ToLower(v) {
	case "false", "0", "no", "off":
		return true
	}
	return false
}
