package mcpconf

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"
)

type syntax string

const (
	synJSON syntax = "json"
	synTOML syntax = "toml"
	synYAML syntax = "yaml"
)

// maxTOMLNesting bounds arrays and inline tables in TOML input. Real configs
// nest three or four levels. See tomlNestingOK for why the bound exists.
const maxTOMLNesting = 64

// toUTF8 returns text in UTF-8 without a byte-order mark.
//
// UTF-16 matters in practice: Windows PowerShell 5 writes UTF-16LE when an
// admin redirects JSON into managed-mcp.json. Invalid UTF-8 is replaced
// rather than rejected because JavaScript agents read files leniently
// (U+FFFD substitution); rejecting would let one stray byte hide every server
// in a file the agent itself loads without complaint.
func toUTF8(data []byte) []byte {
	switch {
	case bytes.HasPrefix(data, []byte{0xEF, 0xBB, 0xBF}):
		data = data[3:]
	case len(data) >= 2 && data[0] == 0xFF && data[1] == 0xFE:
		return utf16ToUTF8(data[2:], false)
	case len(data) >= 2 && data[0] == 0xFE && data[1] == 0xFF:
		return utf16ToUTF8(data[2:], true)
	case len(data) >= 4 && data[0] != 0 && data[1] == 0 && data[2] != 0 && data[3] == 0:
		return utf16ToUTF8(data, false) // BOM-less UTF-16LE: ASCII interleaved with NULs
	case len(data) >= 4 && data[0] == 0 && data[1] != 0 && data[2] == 0 && data[3] != 0:
		return utf16ToUTF8(data, true)
	}
	if !utf8.Valid(data) {
		data = bytes.ToValidUTF8(data, []byte("�"))
	}
	return data
}

func utf16ToUTF8(b []byte, bigEndian bool) []byte {
	out := make([]byte, 0, len(b)/2+8)
	unit := func(i int) rune {
		if bigEndian {
			return rune(b[i])<<8 | rune(b[i+1])
		}
		return rune(b[i]) | rune(b[i+1])<<8
	}
	for i := 0; i+1 < len(b); i += 2 {
		r := unit(i)
		if utf16.IsSurrogate(r) {
			if i+3 < len(b) {
				if d := utf16.DecodeRune(r, unit(i+2)); d != utf8.RuneError {
					out = utf8.AppendRune(out, d)
					i += 2
					continue
				}
			}
			r = utf8.RuneError
		}
		out = utf8.AppendRune(out, r)
	}
	return out
}

func firstSignificant(text []byte) byte {
	for _, c := range text {
		switch c {
		case ' ', '\t', '\r', '\n':
		default:
			return c
		}
	}
	return 0
}

// pathExt is filepath.Ext that also understands backslash separators, because
// a Linux collector can be handed a Windows path (offline images, tests).
func pathExt(path string) string {
	base := path
	if i := strings.LastIndexAny(base, `/\`); i >= 0 {
		base = base[i+1:]
	}
	if i := strings.LastIndexByte(base, '.'); i >= 0 {
		return strings.ToLower(base[i:])
	}
	return ""
}

var (
	reTOMLHeader = regexp.MustCompile(`^\[\[?\s*[A-Za-z0-9_\-."' ]+\s*\]\]?\s*(#.*)?$`)
	reTOMLAssign = regexp.MustCompile(`^[A-Za-z0-9_\-."']+\s*=\s*\S`)
	reYAMLLine   = regexp.MustCompile(`line (\d+)`)
)

// looksLikeTOML inspects the head of a file whose name gives no hint.
func looksLikeTOML(text []byte) bool {
	head := text
	if len(head) > 64<<10 {
		head = head[:64<<10]
	}
	lines := 0
	for len(head) > 0 && lines < 400 {
		line := head
		if i := bytes.IndexByte(head, '\n'); i >= 0 {
			line, head = head[:i], head[i+1:]
		} else {
			head = nil
		}
		lines++
		line = bytes.TrimSpace(line)
		if len(line) == 0 || line[0] == '#' {
			continue
		}
		if reTOMLHeader.Match(line) || reTOMLAssign.Match(line) {
			return true
		}
	}
	return false
}

// syntaxCandidates orders the syntaxes worth trying. Content decides first
// ("{" is JSON in every dialect read here), then the file extension, then the
// dialect the caller asked for.
func syntaxCandidates(path string, text []byte, f Format) []syntax {
	first := firstSignificant(text)
	ext := pathExt(path)
	if first == '{' || first == '/' {
		if ext == ".yaml" || ext == ".yml" {
			return []syntax{synJSON, synYAML}
		}
		return []syntax{synJSON}
	}
	switch ext {
	case ".json", ".jsonc", ".json5", ".code-workspace":
		return []syntax{synJSON}
	case ".toml":
		return []syntax{synTOML}
	case ".yaml", ".yml":
		return []syntax{synYAML}
	}
	switch f {
	case FormatCodexTOML:
		return []syntax{synTOML}
	case FormatContinue, FormatGoose:
		return []syntax{synYAML}
	case FormatAuto:
		if looksLikeTOML(text) {
			return []syntax{synTOML, synYAML}
		}
		if first == '[' {
			return []syntax{synJSON, synTOML, synYAML}
		}
		return []syntax{synYAML, synTOML}
	default:
		return []syntax{synJSON}
	}
}

func decode(path string, text []byte, f Format) (any, error) {
	var first error
	for _, syn := range syntaxCandidates(path, text, f) {
		var (
			v   any
			err error
		)
		switch syn {
		case synJSON:
			v, err = decodeJSON(text)
		case synTOML:
			v, err = decodeTOML(text)
		default:
			v, err = decodeYAML(text)
		}
		if err == nil {
			return v, nil
		}
		if first == nil {
			first = err
		}
	}
	return nil, first
}

func decodeJSON(text []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(jsoncToJSON(text)))
	// Numbers keep their written form ("8080", not 8080.000000) because
	// they end up as argv and env strings.
	dec.UseNumber()
	var v any
	if err := dec.Decode(&v); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, nil // nothing but comments
		}
		line := 0
		var se *json.SyntaxError
		if errors.As(err, &se) {
			end := int(se.Offset)
			if end > len(text) {
				end = len(text)
			}
			if end >= 0 {
				line = 1 + bytes.Count(text[:end], []byte{'\n'})
			}
		}
		return nil, &SyntaxError{Syntax: string(synJSON), Line: line, Reason: "malformed"}
	}
	return v, nil
}

func decodeTOML(text []byte) (any, error) {
	if !tomlNestingOK(text) {
		return nil, &SyntaxError{Syntax: string(synTOML), Reason: "too deeply nested"}
	}
	var m map[string]any
	if err := toml.Unmarshal(text, &m); err != nil {
		line := 0
		var pe toml.ParseError
		if errors.As(err, &pe) {
			line = pe.Position.Line
		}
		return nil, &SyntaxError{Syntax: string(synTOML), Line: line, Reason: "malformed"}
	}
	return m, nil
}

func decodeYAML(text []byte) (any, error) {
	// yaml.v3 bounds nesting (10000) and alias expansion itself.
	var v any
	if err := yaml.Unmarshal(text, &v); err != nil {
		line := 0
		if m := reYAMLLine.FindStringSubmatch(err.Error()); m != nil {
			line, _ = strconv.Atoi(m[1])
		}
		return nil, &SyntaxError{Syntax: string(synYAML), Line: line, Reason: "malformed"}
	}
	return v, nil
}

// tomlNestingOK reports whether no array or inline table nests deeper than
// maxTOMLNesting.
//
// The TOML decoder recurses once per nesting level without a limit, and a Go
// stack overflow is a fatal error that recover cannot catch: a 3 MiB file of
// "[" would kill the sensor. So depth is measured here first, with a scanner
// that follows TOML's string and comment rules exactly. Exactness matters in
// one direction only: whenever this scanner believes it is inside a string or
// comment, the real lexer must either agree or have already failed.
func tomlNestingOK(text []byte) bool {
	depth := 0
	n := len(text)
	for i := 0; i < n; i++ {
		switch text[i] {
		case '#':
			for i < n && text[i] != '\n' {
				i++
			}
		case '"', '\'':
			i = skipTOMLString(text, i)
		case '[', '{':
			depth++
			if depth > maxTOMLNesting {
				return false
			}
		case ']', '}':
			if depth > 0 {
				depth--
			}
		}
	}
	return true
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
			return j
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

// ---- generic tree access ----
//
// The three decoders produce differently typed trees (yaml: map[any]any for
// non-string keys, toml: []map[string]any for arrays of tables). The readers
// below convert at the point of use instead of normalising the whole tree, so
// no code in this package recurses over attacker-shaped data.

func asMap(v any) (map[string]any, bool) {
	switch m := v.(type) {
	case map[string]any:
		return m, true
	case map[any]any:
		out := make(map[string]any, len(m))
		for k, val := range m {
			if ks, ok := scalarString(k); ok && k != nil {
				out[ks] = val
			}
		}
		return out, true
	}
	return nil, false
}

func asList(v any) ([]any, bool) {
	switch l := v.(type) {
	case []any:
		return l, true
	case []map[string]any:
		out := make([]any, len(l))
		for i := range l {
			out[i] = l[i]
		}
		return out, true
	case []string:
		out := make([]any, len(l))
		for i := range l {
			out[i] = l[i]
		}
		return out, true
	}
	return nil, false
}

// scalarString renders a scalar as the string a process would receive. nil
// renders as "" (VS Code allows null env values).
func scalarString(v any) (string, bool) {
	switch t := v.(type) {
	case nil:
		return "", true
	case string:
		return t, true
	case json.Number:
		return t.String(), true
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
	case time.Time:
		return t.Format(time.RFC3339), true
	}
	return "", false
}

func scalarStrings(l []any) []string {
	out := make([]string, 0, len(l))
	for _, v := range l {
		if v == nil {
			continue
		}
		if s, ok := scalarString(v); ok {
			out = append(out, s)
		}
	}
	return out
}

func sortedKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
