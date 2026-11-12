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
// overflow in Go is fatal, not a recoverable panic), and no decoder may
// turn a small file into a large tree.
const (
	maxNesting = 64
	// maxTOMLKeyParts bounds the parts of one dotted TOML key or table
	// header: the TOML decoder's memory is quadratic in it.
	maxTOMLKeyParts = 32
	// maxDocValues bounds the values in one JSON or TOML document. A
	// decoded value costs 50-100 bytes, so 20 MiB of "[],[],..." would
	// otherwise cost about a gigabyte; a multi-megabyte ~/.claude.json
	// holds a few hundred thousand values.
	maxDocValues = 2_000_000
	maxYAMLSize  = 2 << 20
	// maxYAMLNodes and maxYAMLBytes bound a YAML document as it is once
	// aliases are followed (values, and scalar bytes); maxYAMLDepth bounds
	// its height. Agent configs and workflows are far below all three.
	maxYAMLNodes = 200_000
	maxYAMLBytes = 8 << 20
	maxYAMLDepth = 512
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
// them in practice. It never panics, and every syntax is measured before
// a recursive decoder sees it.
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
	switch syntax {
	case "toml":
		if reason := tomlGuard(data); reason != "" {
			return nil, errors.New("toml " + reason)
		}
		var m map[string]any
		if _, err := toml.Decode(string(data), &m); err != nil {
			return nil, errors.New("malformed toml")
		}
		return normalize(m, 0), nil
	case "yaml":
		return decodeYAML(data)
	case "plist":
		return parsePlist(data)
	default:
		clean := stripJSONC(data)
		if reason := jsonGuard(clean); reason != "" {
			return nil, errors.New("json " + reason)
		}
		dec := json.NewDecoder(bytes.NewReader(clean))
		dec.UseNumber()
		var v any
		if err := dec.Decode(&v); err != nil {
			return nil, errors.New("malformed json")
		}
		return normalize(v, 0), nil
	}
}

func decodeYAML(data []byte) (any, error) {
	if len(data) > maxYAMLSize {
		return nil, errTooLarge
	}
	// A yaml.Node costs about 200 bytes, so the size of the tree is bounded
	// before it is built: every YAML value is introduced by a line start or
	// one of a few indicator bytes, and counting those bounds the node count
	// from above. (yaml.v3 itself limits flow and indentation depth to
	// 10,000 while parsing.)
	indicators := 0
	for _, c := range data {
		switch c {
		case '\n', ',', ':', '[', '{', '-', '?':
			indicators++
		}
	}
	if indicators > maxYAMLNodes {
		return nil, errors.New("yaml has too many values")
	}
	// Parsing into a Node tree keeps aliases as pointers, so the document
	// can be measured before anything is expanded.
	var n yaml.Node
	if err := yaml.Unmarshal(data, &n); err != nil {
		return nil, errors.New("malformed yaml")
	}
	if reason := yamlGuard(&n); reason != "" {
		return nil, errors.New("yaml " + reason)
	}
	var v any
	if err := n.Decode(&v); err != nil {
		return nil, errors.New("malformed yaml")
	}
	return normalize(v, 0), nil
}

type yamlMeasure struct{ size, height, bytes int }

// yamlGuard measures a document as it will be once aliases are followed,
// and returns "" when it may be decoded or the reason it may not.
// Anchors and aliases are ordinary YAML (GitHub Actions accepts them in
// workflows), so they are measured, not refused: what is bounded is the
// expansion. One budget applies to the number of values, the scalar bytes
// and the height of the expanded tree, which covers both the "billion
// laughs" fan-out and anchors that wrap an alias to the previous anchor
// (a nesting of tens of thousands of levels for the recursive decoder).
// The walk never descends into an alias target: targets precede their
// aliases, so their measure is already known.
// Ported from internal/mcpconf (yamlGuard), which this package may not
// change.
func yamlGuard(doc *yaml.Node) string {
	memo := make(map[*yaml.Node]yamlMeasure)
	open := make(map[*yaml.Node]bool)
	bad := ""
	var walk func(n *yaml.Node, depth int) yamlMeasure
	walk = func(n *yaml.Node, depth int) yamlMeasure {
		if n == nil || bad != "" {
			return yamlMeasure{}
		}
		if depth > maxYAMLDepth {
			bad = "too deeply nested"
			return yamlMeasure{}
		}
		if n.Kind == yaml.AliasNode {
			m, ok := memo[n.Alias]
			if !ok || open[n.Alias] {
				bad = "malformed" // alias to an enclosing or unknown node
				return yamlMeasure{}
			}
			return m
		}
		if n.Anchor != "" {
			open[n] = true
		}
		m := yamlMeasure{size: 1, bytes: len(n.Value)}
		for _, c := range n.Content {
			cm := walk(c, depth+1)
			m.size += cm.size
			m.bytes += cm.bytes
			if cm.height+1 > m.height {
				m.height = cm.height + 1
			}
			switch {
			case m.size > maxYAMLNodes || m.bytes > maxYAMLBytes:
				bad = "has too many values"
			case m.height > maxYAMLDepth:
				bad = "too deeply nested"
			}
			if bad != "" {
				return yamlMeasure{}
			}
		}
		if n.Anchor != "" {
			delete(open, n)
			memo[n] = m
		}
		return m
	}
	walk(doc, 0)
	return bad
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

// jsonGuard measures comment-free JSON (the output of stripJSONC) before
// it is decoded: nesting depth and the number of values. encoding/json
// has its own depth limit (10,000); this one is far lower, and the value
// count bounds the decoded tree's memory.
func jsonGuard(clean []byte) string {
	depth, values := 0, 0
	inStr, esc := false, false
	for _, c := range clean {
		if inStr {
			switch {
			case esc:
				esc = false
			case c == '\\':
				esc = true
			case c == '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '[', '{':
			depth++
			values++
			if depth > maxNesting {
				return "too deeply nested"
			}
		case ']', '}':
			if depth > 0 {
				depth--
			}
		case ',':
			values++
		}
		if values > maxDocValues {
			return "has too many values"
		}
	}
	return ""
}

// tomlGuard returns "" when the TOML decoder can be trusted with text, or
// the reason it cannot.
//
// The decoder (BurntSushi/toml) has two failure modes that no recover can
// catch. It recurses once per nesting level without a limit, so a few MiB
// of "[" overflow the stack and kill the process; and its memory use is
// quadratic in the number of parts of a dotted key, so an 8 KiB key of
// 4000 parts allocates over 600 MiB. Both are measured here first, by a
// scanner that follows TOML's string and comment rules exactly (a
// multi-line string may hold newlines and up to two quotes before its
// delimiter, a literal string has no escapes). Exactness matters in one
// direction only: wherever this scanner believes it is inside a string, a
// comment or a value, the real lexer must either agree or have already
// rejected the file.
// Ported from internal/mcpconf (tomlGuard), which this package may not
// change.
func tomlGuard(text []byte) string {
	var (
		stack  [maxNesting]byte
		depth  int
		keyPos = true // reading a key: line start at top level, or inside an inline table
		header bool   // inside a [table] or [[array-of-tables]] header
		dots   int
		values int
	)
	n := len(text)
	for i := 0; i < n; i++ {
		c := text[i]
		switch c {
		case '#':
			for i < n && text[i] != '\n' {
				i++
			}
			i-- // let the newline be seen
		case '"', '\'':
			i = skipTOMLString(text, i)
		case '\n':
			if depth == 0 {
				keyPos, header, dots = true, false, 0
			}
		case '=':
			if keyPos && !header {
				keyPos = false
				values++
			}
		case '.':
			if keyPos {
				dots++
				if dots >= maxTOMLKeyParts {
					return "key has too many parts"
				}
			}
		case '[', '{':
			if c == '[' && keyPos && depth == 0 {
				header = true
				continue
			}
			if header {
				continue
			}
			if depth >= maxNesting {
				return "too deeply nested"
			}
			stack[depth] = c
			depth++
			values++
			if c == '{' {
				keyPos, dots = true, 0
			}
		case ']', '}':
			if header {
				continue
			}
			if depth > 0 {
				depth--
			}
			keyPos = false
		case ',':
			values++
			if depth > 0 && stack[depth-1] == '{' {
				keyPos, dots = true, 0
			}
		}
		if values > maxDocValues {
			return "has too many values"
		}
	}
	return ""
}

// skipTOMLString returns the index of the last byte of the string that opens
// at text[i]. An unterminated single-line string ends at its newline: the
// decoder rejects the file at that point, so what follows is never parsed.
func skipTOMLString(text []byte, i int) int {
	q := text[i]
	n := len(text)
	basic := q == '"' // only basic strings have backslash escapes
	if i+2 < n && text[i+1] == q && text[i+2] == q {
		j := i + 3
		for j < n {
			c := text[j]
			if basic && c == '\\' {
				j += 2
				continue
			}
			if c == q && j+2 < n && text[j+1] == q && text[j+2] == q {
				j += 2
				// Up to two more quotes directly before the delimiter are
				// content ("""a""""" is `a""`), so a run of up to five closes.
				for k := 0; k < 2 && j+1 < n && text[j+1] == q; k++ {
					j++
				}
				return j
			}
			j++
		}
		return n
	}
	j := i + 1
	for j < n {
		c := text[j]
		if c == '\n' {
			return j - 1 // the caller still has to see the newline
		}
		if basic && c == '\\' {
			j += 2
			continue
		}
		if c == q {
			return j
		}
		j++
	}
	return n
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
