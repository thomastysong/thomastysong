package rules

import (
	"encoding/json"
	"sort"

	"gopkg.in/yaml.v3"
)

// canonical renders a YAML node as JSON with sorted keys, so formatting and
// comments do not change a rule set's hash but content does.
//
// The definition is canonicalRef: decode the node the way yaml.v3 decodes
// into interface{}, convert, json.Marshal. That is a third of the cost of
// loading a pack, so the common shapes of rule content (string-keyed
// mappings, sequences, strings, true/false, null, small decimal integers)
// are rendered directly to the same bytes; any other shape (another key
// type, a YAML 1.1 spelling, a float, a timestamp) falls back to the
// reference for that scalar or for the whole node. TestCanonicalFastPath
// and FuzzCanonical hold the two to byte equality.
func canonical(n *yaml.Node) []byte {
	if n == nil {
		return nil
	}
	if b, ok := appendCanonical(make([]byte, 0, 1024), n, 0); ok {
		return b
	}
	return canonicalRef(n)
}

// canonicalRef is the reference rendering.
func canonicalRef(n *yaml.Node) []byte {
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

// appendCanonical appends the canonical JSON of n to b; ok is false when n
// has a shape the fast path does not render (the caller then uses the
// reference for the whole node, so no partial output is ever used).
func appendCanonical(b []byte, n *yaml.Node, depth int) ([]byte, bool) {
	if depth > maxYAMLDepth+2 {
		return b, false
	}
	switch n.Kind {
	case yaml.ScalarNode:
		return appendScalar(b, n)
	case yaml.SequenceNode:
		if n.Tag != "!!seq" {
			return b, false
		}
		b = append(b, '[')
		for i, c := range n.Content {
			if i > 0 {
				b = append(b, ',')
			}
			var ok bool
			if b, ok = appendCanonical(b, c, depth+1); !ok {
				return b, false
			}
		}
		return append(b, ']'), true
	case yaml.MappingNode:
		if n.Tag != "!!map" || len(n.Content)%2 != 0 {
			return b, false
		}
		k := len(n.Content) / 2
		var small [32]int
		order := small[:0]
		if k > len(small) {
			order = make([]int, 0, k)
		}
		for i := 0; i < k; i++ {
			key := n.Content[2*i]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				return b, false // decoded into a map[interface{}]interface{}
			}
			order = append(order, 2*i)
		}
		sort.Slice(order, func(x, y int) bool { return n.Content[order[x]].Value < n.Content[order[y]].Value })
		for i := 1; i < len(order); i++ {
			if n.Content[order[i]].Value == n.Content[order[i-1]].Value {
				return b, false // duplicate keys: the reference keeps the last
			}
		}
		b = append(b, '{')
		for i, at := range order {
			if i > 0 {
				b = append(b, ',')
			}
			b = appendJSONString(b, n.Content[at].Value)
			b = append(b, ':')
			var ok bool
			if b, ok = appendCanonical(b, n.Content[at+1], depth+1); !ok {
				return b, false
			}
		}
		return append(b, '}'), true
	}
	return b, false
}

// appendScalar renders one scalar. Strings, the two YAML 1.2 booleans,
// null and plain decimal integers are written directly; anything else is
// decoded on its own exactly as the reference decodes it.
func appendScalar(b []byte, n *yaml.Node) ([]byte, bool) {
	switch n.Tag {
	case "!!str":
		return appendJSONString(b, n.Value), true
	case "!!bool":
		if n.Value == "true" || n.Value == "false" {
			return append(b, n.Value...), true
		}
	case "!!null":
		switch n.Value {
		case "", "~", "null", "Null", "NULL":
			return append(b, "null"...), true
		}
	case "!!int":
		if plainDecimal(n.Value) {
			return append(b, n.Value...), true
		}
	}
	var v any
	if err := n.Decode(&v); err != nil {
		return b, false
	}
	j, err := json.Marshal(jsonable(v))
	if err != nil {
		return b, false
	}
	return append(b, j...), true
}

// plainDecimal reports a decimal integer that yaml.v3 decodes to an int
// with the same digits: no sign on zero, no leading zeros (octal), no
// underscores, at most 18 digits.
func plainDecimal(s string) bool {
	if s == "0" {
		return true
	}
	if len(s) > 0 && s[0] == '-' {
		s = s[1:]
	}
	if len(s) == 0 || len(s) > 18 || s[0] == '0' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// appendJSONString appends s as encoding/json writes it (HTML-safe
// escaping). Strings of plain printable ASCII are copied; anything else
// goes through encoding/json itself.
func appendJSONString(b []byte, s string) []byte {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < 0x20 || c >= 0x7f || c == '"' || c == '\\' || c == '<' || c == '>' || c == '&' {
			j, err := json.Marshal(s)
			if err != nil {
				break
			}
			return append(b, j...)
		}
	}
	b = append(b, '"')
	b = append(b, s...)
	return append(b, '"')
}
