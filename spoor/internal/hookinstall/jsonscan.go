package hookinstall

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
)

// The JSON files this package edits belong to somebody else (an agent, a
// user, another administrator). Re-encoding them would reorder keys, respell
// numbers and reflow the layout, so they are parsed into a tree that keeps
// the byte offsets of every value and are then edited by splicing text.

type nodeKind uint8

const (
	kindObject nodeKind = iota + 1
	kindArray
	kindString
	kindNumber
	kindBool
	kindNull
)

// node is one JSON value. Its text is src[start:end]; for containers
// src[start] is the opening and src[end-1] the closing bracket.
type node struct {
	kind       nodeKind
	start, end int
	members    []member // kindObject, in file order
	elems      []*node  // kindArray
	str        string   // kindString, decoded
	num        float64  // kindNumber
	b          bool     // kindBool
}

type member struct {
	key      string
	keyStart int // offset of the opening quote of the key
	val      *node
}

// jsonDoc is a parsed file.
type jsonDoc struct {
	src  []byte
	root *node
	// comments and trailingCommas record JSONC features. Such a file is only
	// rewritten when the caller forces it.
	comments       bool
	trailingCommas bool
}

const (
	maxJSONDepth = 64
	maxJSONNodes = 200000
)

// errJSON never quotes file content: it may be shown to a different user
// than the one who owns the file.
type errJSON struct {
	off int
	msg string
}

func (e *errJSON) Error() string { return fmt.Sprintf("invalid JSON at byte %d: %s", e.off, e.msg) }

var errNotObject = errors.New("top level is not a JSON object")

type jsonParser struct {
	src   []byte
	pos   int
	doc   *jsonDoc
	nodes int
}

// parseJSON accepts strict JSON plus the two JSONC extensions agents
// tolerate in their settings files (comments and trailing commas), and
// records whether either was used. The top level must be an object.
func parseJSON(src []byte) (d *jsonDoc, err error) {
	// The input is another program's file; a parser bug must surface as an
	// error for that one file, not as a crash of the installer.
	defer func() {
		if r := recover(); r != nil {
			d, err = nil, &errJSON{0, "internal parser error"}
		}
	}()
	p := &jsonParser{src: src, doc: &jsonDoc{src: src}}
	// A UTF-8 byte order mark is common in files saved on Windows.
	if len(src) >= 3 && src[0] == 0xef && src[1] == 0xbb && src[2] == 0xbf {
		p.pos = 3
	}
	if err := p.skip(); err != nil {
		return nil, err
	}
	if p.pos >= len(src) {
		return nil, &errJSON{p.pos, "empty document"}
	}
	root, err := p.value(0)
	if err != nil {
		return nil, err
	}
	if err := p.skip(); err != nil {
		return nil, err
	}
	if p.pos != len(src) {
		return nil, &errJSON{p.pos, "content after the top-level value"}
	}
	if root.kind != kindObject {
		return nil, errNotObject
	}
	p.doc.root = root
	return p.doc, nil
}

// skip consumes whitespace and comments.
func (p *jsonParser) skip() error {
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		switch {
		case c == ' ' || c == '\t' || c == '\n' || c == '\r':
			p.pos++
		case c == '/' && p.pos+1 < len(p.src) && p.src[p.pos+1] == '/':
			p.doc.comments = true
			p.pos += 2
			for p.pos < len(p.src) && p.src[p.pos] != '\n' {
				p.pos++
			}
		case c == '/' && p.pos+1 < len(p.src) && p.src[p.pos+1] == '*':
			p.doc.comments = true
			start := p.pos
			p.pos += 2
			for {
				if p.pos+1 >= len(p.src) {
					return &errJSON{start, "unterminated comment"}
				}
				if p.src[p.pos] == '*' && p.src[p.pos+1] == '/' {
					p.pos += 2
					break
				}
				p.pos++
			}
		default:
			return nil
		}
	}
	return nil
}

func (p *jsonParser) value(depth int) (*node, error) {
	if depth > maxJSONDepth {
		return nil, &errJSON{p.pos, "nested too deeply"}
	}
	p.nodes++
	if p.nodes > maxJSONNodes {
		return nil, &errJSON{p.pos, "too many values"}
	}
	if p.pos >= len(p.src) {
		return nil, &errJSON{p.pos, "unexpected end"}
	}
	switch c := p.src[p.pos]; {
	case c == '{':
		return p.object(depth)
	case c == '[':
		return p.array(depth)
	case c == '"':
		start := p.pos
		s, err := p.str()
		if err != nil {
			return nil, err
		}
		return &node{kind: kindString, start: start, end: p.pos, str: s}, nil
	case c == '-' || (c >= '0' && c <= '9'):
		return p.number()
	case c == 't':
		return p.literal("true", &node{kind: kindBool, b: true})
	case c == 'f':
		return p.literal("false", &node{kind: kindBool})
	case c == 'n':
		return p.literal("null", &node{kind: kindNull})
	}
	return nil, &errJSON{p.pos, "unexpected character"}
}

func (p *jsonParser) literal(word string, n *node) (*node, error) {
	if len(p.src)-p.pos < len(word) || string(p.src[p.pos:p.pos+len(word)]) != word {
		return nil, &errJSON{p.pos, "unexpected character"}
	}
	n.start = p.pos
	p.pos += len(word)
	n.end = p.pos
	return n, nil
}

func (p *jsonParser) number() (*node, error) {
	start := p.pos
	for p.pos < len(p.src) {
		c := p.src[p.pos]
		if (c >= '0' && c <= '9') || c == '-' || c == '+' || c == '.' || c == 'e' || c == 'E' {
			p.pos++
			continue
		}
		break
	}
	raw := p.src[start:p.pos]
	// encoding/json is the arbiter of what a number is ("01" and "1." are
	// not), so the tree never holds a literal a strict reader would reject.
	if !json.Valid(raw) {
		return nil, &errJSON{start, "malformed number"}
	}
	f, err := strconv.ParseFloat(string(raw), 64)
	if err != nil {
		// Out of float64 range: keep the node, the value is never compared.
		f = 0
	}
	return &node{kind: kindNumber, start: start, end: p.pos, num: f}, nil
}

// str parses the string starting at p.pos and leaves p.pos after it.
func (p *jsonParser) str() (string, error) {
	start := p.pos
	p.pos++
	for {
		if p.pos >= len(p.src) {
			return "", &errJSON{start, "unterminated string"}
		}
		c := p.src[p.pos]
		switch {
		case c == '"':
			p.pos++
			var s string
			if err := json.Unmarshal(p.src[start:p.pos], &s); err != nil {
				return "", &errJSON{start, "malformed string"}
			}
			return s, nil
		case c == '\\':
			p.pos += 2
		case c < 0x20:
			return "", &errJSON{p.pos, "control character in string"}
		default:
			p.pos++
		}
	}
}

func (p *jsonParser) object(depth int) (*node, error) {
	n := &node{kind: kindObject, start: p.pos}
	p.pos++
	for {
		if err := p.skip(); err != nil {
			return nil, err
		}
		if p.pos >= len(p.src) {
			return nil, &errJSON{n.start, "unterminated object"}
		}
		if p.src[p.pos] == '}' {
			p.pos++
			n.end = p.pos
			return n, nil
		}
		if p.src[p.pos] != '"' {
			return nil, &errJSON{p.pos, "expected a key"}
		}
		keyStart := p.pos
		key, err := p.str()
		if err != nil {
			return nil, err
		}
		if err := p.skip(); err != nil {
			return nil, err
		}
		if p.pos >= len(p.src) || p.src[p.pos] != ':' {
			return nil, &errJSON{p.pos, "expected ':'"}
		}
		p.pos++
		if err := p.skip(); err != nil {
			return nil, err
		}
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		n.members = append(n.members, member{key: key, keyStart: keyStart, val: v})
		done, err := p.separator('}')
		if err != nil {
			return nil, err
		}
		if done {
			n.end = p.pos
			return n, nil
		}
	}
}

func (p *jsonParser) array(depth int) (*node, error) {
	n := &node{kind: kindArray, start: p.pos}
	p.pos++
	for {
		if err := p.skip(); err != nil {
			return nil, err
		}
		if p.pos >= len(p.src) {
			return nil, &errJSON{n.start, "unterminated array"}
		}
		if p.src[p.pos] == ']' {
			p.pos++
			n.end = p.pos
			return n, nil
		}
		v, err := p.value(depth + 1)
		if err != nil {
			return nil, err
		}
		n.elems = append(n.elems, v)
		done, err := p.separator(']')
		if err != nil {
			return nil, err
		}
		if done {
			n.end = p.pos
			return n, nil
		}
	}
}

// separator consumes what follows a member or element: a comma, the closing
// bracket, or a comma directly followed by the closing bracket (JSONC).
func (p *jsonParser) separator(closer byte) (done bool, err error) {
	if err := p.skip(); err != nil {
		return false, err
	}
	if p.pos >= len(p.src) {
		return false, &errJSON{p.pos, "unexpected end"}
	}
	switch p.src[p.pos] {
	case closer:
		p.pos++
		return true, nil
	case ',':
		p.pos++
		if err := p.skip(); err != nil {
			return false, err
		}
		if p.pos < len(p.src) && p.src[p.pos] == closer {
			p.doc.trailingCommas = true
			p.pos++
			return true, nil
		}
		return false, nil
	}
	return false, &errJSON{p.pos, "expected ',' or a closing bracket"}
}

// member returns the value of key and its index. When a key is repeated the
// last one wins, as it does in the agents' own parsers.
func (n *node) member(key string) (int, *node) {
	if n == nil || n.kind != kindObject {
		return -1, nil
	}
	for i := len(n.members) - 1; i >= 0; i-- {
		if n.members[i].key == key {
			return i, n.members[i].val
		}
	}
	return -1, nil
}

// text returns the string value of a member, or "" when it is absent or not
// a string.
func (n *node) text(key string) string {
	if _, v := n.member(key); v != nil && v.kind == kindString {
		return v.str
	}
	return ""
}

// strings returns the string elements of an array member.
func (n *node) strings(key string) []string {
	_, v := n.member(key)
	if v == nil || v.kind != kindArray {
		return nil
	}
	out := make([]string, 0, len(v.elems))
	for _, e := range v.elems {
		if e.kind == kindString {
			out = append(out, e.str)
		}
	}
	return out
}

// children is the number of members or elements.
func (n *node) children() int {
	if n.kind == kindObject {
		return len(n.members)
	}
	return len(n.elems)
}

// span is the byte range of child i, including its key for object members.
func (n *node) span(i int) (start, end int) {
	if n.kind == kindObject {
		return n.members[i].keyStart, n.members[i].val.end
	}
	return n.elems[i].start, n.elems[i].end
}

// value converts the node into plain Go values (map, slice, string, float64,
// bool, nil) for comparison with what this package would write.
func (n *node) value() any {
	switch n.kind {
	case kindObject:
		m := make(map[string]any, len(n.members))
		for _, mem := range n.members {
			m[mem.key] = mem.val.value()
		}
		return m
	case kindArray:
		l := make([]any, len(n.elems))
		for i, e := range n.elems {
			l[i] = e.value()
		}
		return l
	case kindString:
		return n.str
	case kindNumber:
		return n.num
	case kindBool:
		return n.b
	}
	return nil
}
