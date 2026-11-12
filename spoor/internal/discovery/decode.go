package discovery

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

// Decoder limits. Config files are user-writable and often repository
// supplied; recursive parsers must not see unbounded nesting (a stack
// overflow in Go is fatal, not a recoverable panic).
const (
	maxNesting  = 64
	maxYAMLSize = 2 << 20
	maxNodes    = 200_000
)

var errNesting = errors.New("document nested too deeply")

// syntaxOf picks a parser from a file name.
func syntaxOf(name string) string {
	n := strings.ToLower(name)
	switch {
	case strings.HasSuffix(n, ".toml"):
		return "toml"
	case strings.HasSuffix(n, ".yaml"), strings.HasSuffix(n, ".yml"):
		return "yaml"
	case strings.HasSuffix(n, ".plist"):
		return "plist"
	}
	return "json"
}

// decodeDoc parses a config file into generic values: map[string]any,
// []any, string, float64/int64, bool, nil. JSON accepts comments and
// trailing commas (JSONC), since VS Code family and Claude settings allow
// them in practice. It never panics.
func decodeDoc(data []byte, syntax string) (doc any, err error) {
	defer func() {
		if r := recover(); r != nil {
			doc, err = nil, errors.New("internal error while decoding")
		}
	}()
	data = bytes.TrimPrefix(data, []byte("\xef\xbb\xbf"))
	if len(bytes.TrimSpace(data)) == 0 {
		return nil, nil
	}
	if nestingDepth(data, syntax) > maxNesting {
		return nil, errNesting
	}
	switch syntax {
	case "toml":
		var m map[string]any
		if _, err := toml.Decode(string(data), &m); err != nil {
			return nil, errors.New("malformed toml")
		}
		return normalize(m, 0), nil
	case "yaml":
		if len(data) > maxYAMLSize {
			return nil, errTooLarge
		}
		var n yaml.Node
		if err := yaml.Unmarshal(data, &n); err != nil {
			return nil, errors.New("malformed yaml")
		}
		count := 0
		if !yamlSafe(&n, 0, &count) {
			return nil, errors.New("yaml aliases or excessive nesting refused")
		}
		var v any
		if err := n.Decode(&v); err != nil {
			return nil, errors.New("malformed yaml")
		}
		return normalize(v, 0), nil
	case "plist":
		return parsePlist(data)
	default:
		clean := stripJSONC(data)
		dec := json.NewDecoder(bytes.NewReader(clean))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			return nil, errors.New("malformed json")
		}
		return normalize(v, 0), nil
	}
}

// yamlSafe rejects aliases (billion-laughs expansion) and deep trees.
func yamlSafe(n *yaml.Node, depth int, count *int) bool {
	*count++
	if depth > maxNesting || *count > maxNodes {
		return false
	}
	if n.Kind == yaml.AliasNode || n.Anchor != "" {
		return false
	}
	for _, c := range n.Content {
		if !yamlSafe(c, depth+1, count) {
			return false
		}
	}
	return true
}

// normalize converts decoder-specific shapes into the generic set and
// stringifies non-string map keys.
func normalize(v any, depth int) any {
	if depth > maxNesting {
		return nil
	}
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			t[k] = normalize(x, depth+1)
		}
		return t
	case map[any]any:
		m := make(map[string]any, len(t))
		for k, x := range t {
			m[fmt.Sprint(k)] = normalize(x, depth+1)
		}
		return m
	case []map[string]any:
		out := make([]any, len(t))
		for i, x := range t {
			out[i] = normalize(x, depth+1)
		}
		return out
	case []any:
		for i, x := range t {
			t[i] = normalize(x, depth+1)
		}
		return t
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return i
		}
		f, _ := t.Float64()
		return f
	case int:
		return int64(t)
	}
	return v
}

// nestingDepth measures bracket nesting outside strings. For YAML it also
// counts indentation levels coarsely (every two spaces), which bounds block
// nesting as well as flow nesting.
func nestingDepth(data []byte, syntax string) int {
	depth, max := 0, 0
	inStr := byte(0)
	esc := false
	for _, c := range data {
		if inStr != 0 {
			if esc {
				esc = false
			} else if c == '\\' && inStr == '"' {
				esc = true
			} else if c == inStr {
				inStr = 0
			} else if c == '\n' && syntax != "json" {
				inStr = 0
			}
			continue
		}
		switch c {
		case '"':
			inStr = '"'
		case '\'':
			if syntax != "json" {
				inStr = '\''
			}
		case '[', '{':
			depth++
			if depth > max {
				max = depth
			}
		case ']', '}':
			if depth > 0 {
				depth--
			}
		}
	}
	if syntax == "yaml" {
		indent := 0
		lineStart := true
		for _, c := range data {
			switch {
			case c == '\n':
				lineStart, indent = true, 0
			case lineStart && (c == ' ' || c == '-'):
				indent++
				if indent/2 > max {
					max = indent / 2
				}
			default:
				lineStart = false
			}
		}
	}
	return max
}

// stripJSONC removes // and /* */ comments and trailing commas outside
// strings, keeping byte offsets irrelevant (the result is only decoded).
func stripJSONC(data []byte) []byte {
	if !bytes.Contains(data, []byte("//")) && !bytes.Contains(data, []byte("/*")) && !bytes.Contains(data, []byte(",")) {
		return data
	}
	out := make([]byte, 0, len(data))
	inStr, esc := false, false
	for i := 0; i < len(data); i++ {
		c := data[i]
		if inStr {
			out = append(out, c)
			if esc {
				esc = false
			} else if c == '\\' {
				esc = true
			} else if c == '"' {
				inStr = false
			}
			continue
		}
		switch {
		case c == '"':
			inStr = true
			out = append(out, c)
		case c == '/' && i+1 < len(data) && data[i+1] == '/':
			for i < len(data) && data[i] != '\n' {
				i++
			}
			if i < len(data) {
				out = append(out, '\n')
			}
		case c == '/' && i+1 < len(data) && data[i+1] == '*':
			i += 2
			for i+1 < len(data) && !(data[i] == '*' && data[i+1] == '/') {
				i++
			}
			i++
		case c == ',':
			// Drop a comma followed only by whitespace/comments and a closer.
			j := i + 1
			for j < len(data) {
				if data[j] == ' ' || data[j] == '\t' || data[j] == '\n' || data[j] == '\r' {
					j++
					continue
				}
				if data[j] == '/' && j+1 < len(data) && data[j+1] == '/' {
					for j < len(data) && data[j] != '\n' {
						j++
					}
					continue
				}
				if data[j] == '/' && j+1 < len(data) && data[j+1] == '*' {
					j += 2
					for j+1 < len(data) && !(data[j] == '*' && data[j+1] == '/') {
						j++
					}
					j += 2
					continue
				}
				break
			}
			if j < len(data) && (data[j] == '}' || data[j] == ']') {
				continue
			}
			out = append(out, c)
		default:
			out = append(out, c)
		}
	}
	return out
}

// Generic accessors over decoded documents.

func asMap(v any) (map[string]any, bool) {
	m, ok := v.(map[string]any)
	return m, ok
}

func asList(v any) []any {
	switch t := v.(type) {
	case []any:
		return t
	case nil:
		return nil
	}
	return []any{v}
}

func asString(v any) (string, bool) {
	s, ok := v.(string)
	return s, ok
}

func asBool(v any) (bool, bool) {
	switch t := v.(type) {
	case bool:
		return t, true
	case string:
		switch strings.ToLower(strings.TrimSpace(t)) {
		case "true":
			return true, true
		case "false":
			return false, true
		}
	}
	return false, false
}

// getPath walks a dotted path of plain keys.
func getPath(doc any, keys ...string) (any, bool) {
	cur := doc
	for _, k := range keys {
		m, ok := asMap(cur)
		if !ok {
			return nil, false
		}
		cur, ok = m[k]
		if !ok {
			return nil, false
		}
	}
	return cur, true
}

func getString(doc any, keys ...string) string {
	v, ok := getPath(doc, keys...)
	if !ok {
		return ""
	}
	s, _ := asString(v)
	return s
}
