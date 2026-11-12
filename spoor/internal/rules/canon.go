package rules

import (
	"encoding/json"
	"unicode/utf8"

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
		// Insertion sort: mappings are small, and sort.Slice would move
		// order to the heap.
		for i := 1; i < len(order); i++ {
			for j := i; j > 0 && n.Content[order[j]].Value < n.Content[order[j-1]].Value; j-- {
				order[j], order[j-1] = order[j-1], order[j]
			}
		}
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
// escaping). The escapes it writes itself have been stable in
// encoding/json since Go 1: \" \\ \u003c \u003e \u0026 \u2028 \u2029;
// control bytes, DEL and invalid UTF-8 go through encoding/json.
func appendJSONString(b []byte, s string) []byte {
	mark := len(b)
	b = append(b, '"')
	start := 0
	for i := 0; i < len(s); {
		c := s[i]
		if jsonPlain[c] {
			i++
			continue
		}
		if c < utf8.RuneSelf {
			if c < 0x20 || c == 0x7f {
				return appendJSONStringRef(b[:mark], s)
			}
			var esc string
			switch c {
			case '"':
				esc = `\"`
			case '\\':
				esc = `\\`
			case '<':
				esc = `\u003c`
			case '>':
				esc = `\u003e`
			case '&':
				esc = `\u0026`
			default:
				i++
				continue
			}
			b = append(b, s[start:i]...)
			b = append(b, esc...)
			i++
			start = i
			continue
		}
		r, size := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && size == 1 {
			return appendJSONStringRef(b[:mark], s)
		}
		if r == '\u2028' || r == '\u2029' {
			b = append(b, s[start:i]...)
			b = append(b, `\u202`...)
			b = append(b, "0123456789abcdef"[r&0xF])
			start = i + size
		}
		i += size
	}
	b = append(b, s[start:]...)
	return append(b, '"')
}

// jsonPlain marks the bytes encoding/json copies as they are: printable
// ASCII other than '"', '\\', '<', '>' and '&'.
var jsonPlain = func() (t [256]bool) {
	for c := 0x20; c < 0x7f; c++ {
		t[c] = true
	}
	for _, c := range `"\<>&` {
		t[c] = false
	}
	return t
}()

func appendJSONStringRef(b []byte, s string) []byte {
	j, _ := json.Marshal(s) // a string always marshals
	return append(b, j...)
}
