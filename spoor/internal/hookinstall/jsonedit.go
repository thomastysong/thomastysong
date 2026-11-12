package hookinstall

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
)

// jobj is a JSON object with a fixed key order, so generated files are
// stable and read in the order a person expects (type, command, timeout).
type jobj []jfield

type jfield struct {
	k string
	v any // string | int | bool | jobj | jarr
}

type jarr []any

// plain converts a generated value into the representation node.value()
// yields, so the two can be compared with reflect.DeepEqual.
func plain(v any) any {
	switch t := v.(type) {
	case jobj:
		m := make(map[string]any, len(t))
		for _, f := range t {
			m[f.k] = plain(f.v)
		}
		return m
	case jarr:
		l := make([]any, len(t))
		for i, e := range t {
			l[i] = plain(e)
		}
		return l
	case int:
		return float64(t)
	}
	return v
}

type renderMode uint8

const (
	modePretty renderMode = iota // one member per line
	modeSpaced                   // one line, a space after ':' and ','
	modeTight                    // one line, no spaces (minified files)
)

// jstyle is the layout of the file being edited.
type jstyle struct {
	unit  string // one indentation step
	nl    string
	tight bool // the document is minified
}

var defaultStyle = jstyle{unit: "  ", nl: "\n"}

func quoteJSON(s string) string {
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	// "&" is part of every PowerShell command this package writes; the
	// default HTML escaping would turn it into & and make the files
	// needlessly hard to review.
	e.SetEscapeHTML(false)
	if err := e.Encode(s); err != nil {
		return `""`
	}
	return strings.TrimRight(b.String(), "\n")
}

// render writes v. indent is the indentation of the line the value starts
// on; it is only used in modePretty.
func render(v any, st jstyle, indent string, m renderMode) string {
	var b strings.Builder
	renderTo(&b, v, st, indent, m)
	return b.String()
}

func renderTo(b *strings.Builder, v any, st jstyle, indent string, m renderMode) {
	switch t := v.(type) {
	case jobj:
		if len(t) == 0 {
			b.WriteString("{}")
			return
		}
		b.WriteByte('{')
		for i, f := range t {
			writeSep(b, st, indent+st.unit, m, i == 0)
			b.WriteString(quoteJSON(f.k))
			b.WriteByte(':')
			if m != modeTight {
				b.WriteByte(' ')
			}
			renderTo(b, f.v, st, indent+st.unit, m)
		}
		writeClose(b, st, indent, m)
		b.WriteByte('}')
	case jarr:
		if len(t) == 0 {
			b.WriteString("[]")
			return
		}
		em := m
		if m == modePretty && scalarsOnly(t) {
			// ["hook", "--agent", "claude-code"] reads better on one line.
			em = modeSpaced
		}
		b.WriteByte('[')
		for i, e := range t {
			writeSep(b, st, indent+st.unit, em, i == 0)
			renderTo(b, e, st, indent+st.unit, em)
		}
		writeClose(b, st, indent, em)
		b.WriteByte(']')
	case string:
		b.WriteString(quoteJSON(t))
	case int:
		b.WriteString(strconv.Itoa(t))
	case bool:
		b.WriteString(strconv.FormatBool(t))
	default:
		b.WriteString("null")
	}
}

func writeSep(b *strings.Builder, st jstyle, indent string, m renderMode, first bool) {
	switch m {
	case modePretty:
		if !first {
			b.WriteByte(',')
		}
		b.WriteString(st.nl)
		b.WriteString(indent)
	case modeSpaced:
		if !first {
			b.WriteString(", ")
		}
	default:
		if !first {
			b.WriteByte(',')
		}
	}
}

func writeClose(b *strings.Builder, st jstyle, indent string, m renderMode) {
	if m == modePretty {
		b.WriteString(st.nl)
		b.WriteString(indent)
	}
}

func scalarsOnly(a jarr) bool {
	for _, e := range a {
		switch e.(type) {
		case jobj, jarr:
			return false
		}
	}
	return true
}

// style detects the layout of the document so inserted text matches it.
func (d *jsonDoc) style() jstyle {
	st := defaultStyle
	if bytes.Contains(d.src, []byte("\r\n")) {
		st.nl = "\r\n"
	}
	st.tight = bytes.IndexByte(d.src[d.root.start:d.root.end], '\n') < 0
	if d.root.children() > 0 {
		first, _ := d.root.span(0)
		if d.startsLine(first) {
			if ind := d.lineIndent(first); ind != "" {
				st.unit = ind
			}
		}
	}
	return st
}

// lineIndent returns the leading blanks of the line that holds pos.
func (d *jsonDoc) lineIndent(pos int) string {
	ls := bytes.LastIndexByte(d.src[:pos], '\n') + 1
	i := ls
	for i < len(d.src) && (d.src[i] == ' ' || d.src[i] == '\t') {
		i++
	}
	if i > pos {
		i = pos
	}
	return string(d.src[ls:i])
}

// startsLine reports whether only blanks precede pos on its line.
func (d *jsonDoc) startsLine(pos int) bool {
	for i := pos - 1; i >= 0; i-- {
		switch d.src[i] {
		case ' ', '\t':
		case '\n':
			return true
		default:
			return false
		}
	}
	// The first line of the file: only true for a value that is not the root.
	return false
}

func (d *jsonDoc) splice(from, to int, text string) []byte {
	out := make([]byte, 0, len(d.src)+len(text)-(to-from))
	out = append(out, d.src[:from]...)
	out = append(out, text...)
	return append(out, d.src[to:]...)
}

// insert adds one child at the end of container c. text renders the child
// for the indentation and mode the surrounding layout calls for. The
// insertion point is directly after the last existing child, so removing the
// same bytes again restores the file exactly (see drop).
func (d *jsonDoc) insert(c *node, text func(indent string, m renderMode) string) []byte {
	st := d.style()
	n := c.children()
	if n == 0 {
		inner := string(d.src[c.start+1 : c.end-1])
		if hasComment([]byte(inner)) {
			// An empty container that holds only a comment (JSONC, edited
			// under Force): the comment stays in front of the new child
			// and the blanks that closed the container keep closing it, so
			// dropping the child again gives the same bytes back.
			p := lastNonBlank(inner)
			pre, trail := inner[:p], inner[p:]
			if st.tight {
				return d.splice(c.start+1, c.end-1, pre+text("", modeTight)+trail)
			}
			closing := d.lineIndent(c.start)
			child := closing + st.unit
			if !strings.Contains(trail, "\n") {
				trail = st.nl + closing
			}
			return d.splice(c.start+1, c.end-1, pre+st.nl+child+text(child, modePretty)+trail)
		}
		if st.tight {
			return d.splice(c.start+1, c.end-1, text("", modeTight))
		}
		closing := d.lineIndent(c.start)
		child := closing + st.unit
		return d.splice(c.start+1, c.end-1, st.nl+child+text(child, modePretty)+st.nl+closing)
	}
	lastStart, lastEnd := c.span(n - 1)
	if bytes.IndexByte(d.src[lastEnd:c.end-1], '\n') >= 0 {
		child := d.lineIndent(c.start) + st.unit
		if d.startsLine(lastStart) {
			child = d.lineIndent(lastStart)
		}
		return d.splice(lastEnd, lastEnd, ","+st.nl+child+text(child, modePretty))
	}
	if st.tight {
		return d.splice(lastEnd, lastEnd, ","+text("", modeTight))
	}
	return d.splice(lastEnd, lastEnd, ", "+text("", modeSpaced))
}

// addMember appends "key": v to an object.
func (d *jsonDoc) addMember(obj *node, key string, v any) []byte {
	st := d.style()
	return d.insert(obj, func(indent string, m renderMode) string {
		sep := ": "
		if m == modeTight {
			sep = ":"
		}
		return quoteJSON(key) + sep + render(v, st, indent, m)
	})
}

// addElem appends v to an array.
func (d *jsonDoc) addElem(arr *node, v any) []byte {
	st := d.style()
	return d.insert(arr, func(indent string, m renderMode) string {
		return render(v, st, indent, m)
	})
}

// drop removes child i of container c together with the separator that
// insert would have written in front of it, so dropping what insert added
// gives the original bytes back. Comments in the separators (JSONC, only
// edited under Force) stay where they are: a comment after the previous
// member's comma belongs to that member, one before the next member to
// that member, and one inside a container that loses its last child stays
// inside it.
func (d *jsonDoc) drop(c *node, i int) []byte {
	m := d.model(c, nil)
	m.drop(i)
	return d.splice(c.start, c.end, m.render())
}

// holdsComment reports whether a comment sits in the separators of c
// itself (not inside one of its children).
func (d *jsonDoc) holdsComment(c *node) bool {
	return d.model(c, nil).holdsComment()
}

// cmodel is a container as a sequence of separators and children, so that
// several children can be removed with the rules of drop without parsing
// the document again after each one. segs has one more element than kids:
// segs[0] runs from the opening bracket to the first child, segs[k] from
// child k-1 to child k, the last one to the closing bracket. An object
// member's text starts at its key.
type cmodel struct {
	open, close byte
	segs        []string
	kids        []string
}

// model builds the model of c. repl, when set, supplies new text for
// children that were edited themselves.
func (d *jsonDoc) model(c *node, repl map[int]string) *cmodel {
	n := c.children()
	m := &cmodel{open: d.src[c.start], close: d.src[c.end-1], kids: make([]string, n), segs: make([]string, n+1)}
	prev := c.start + 1
	for k := 0; k < n; k++ {
		s, e := c.span(k)
		m.segs[k] = string(d.src[prev:s])
		if t, ok := repl[k]; ok {
			m.kids[k] = t
		} else {
			m.kids[k] = string(d.src[s:e])
		}
		prev = e
	}
	m.segs[n] = string(d.src[prev : c.end-1])
	return m
}

func (m *cmodel) render() string {
	var b strings.Builder
	b.WriteByte(m.open)
	for k, kid := range m.kids {
		b.WriteString(m.segs[k])
		b.WriteString(kid)
	}
	b.WriteString(m.segs[len(m.kids)])
	b.WriteByte(m.close)
	return b.String()
}

func (m *cmodel) holdsComment() bool {
	for _, s := range m.segs {
		if hasComment([]byte(s)) {
			return true
		}
	}
	return false
}

// drop removes child i with the separator insert writes in front of a
// child (see jsonDoc.drop).
func (m *cmodel) drop(i int) {
	n := len(m.kids)
	if n == 1 {
		if m.holdsComment() {
			// Keep the comments; take the child and the blanks in front of
			// it, and the comma of a trailing-comma document after it.
			first := m.segs[0]
			last := m.segs[1]
			if c := separatorComma([]byte(last)); c >= 0 {
				last = last[:c] + last[c+1:]
			}
			m.segs = []string{first[:lastNonBlank(first)] + last}
		} else {
			m.segs = []string{""}
		}
		m.kids = nil
		return
	}
	before := ""
	if i > 0 {
		before = m.segs[i]
	}
	if i < n-1 {
		after := m.segs[i+1]
		if hasComment([]byte(after)) || hasComment([]byte(before)) {
			if comma := separatorComma([]byte(after)); comma >= 0 {
				// Remove the child, its own comma and the blanks after
				// it; comments on either side stay.
				j := comma + 1
				for j < len(after) && isBlank(after[j]) {
					j++
				}
				merged := m.segs[i] + after[j:]
				m.segs = append(append(m.segs[:i:i], merged), m.segs[i+2:]...)
				m.kids = append(m.kids[:i:i], m.kids[i+1:]...)
				return
			}
		}
		if i > 0 {
			// The separator in front of the child goes with it.
			m.segs = append(m.segs[:i:i], m.segs[i+1:]...)
		} else {
			// The first child takes the separator after it.
			m.segs = append(m.segs[:1:1], m.segs[2:]...)
		}
		m.kids = append(m.kids[:i:i], m.kids[i+1:]...)
		return
	}
	// The last child: insert put ",<newline><indent>" in front of it.
	if hasComment([]byte(before)) {
		comma := separatorComma([]byte(before))
		nl := strings.LastIndexByte(before, '\n')
		if comma >= 0 && nl > comma && blank([]byte(before[nl+1:])) {
			m.segs = append(m.segs[:i:i], before[:comma]+before[comma+1:nl]+m.segs[n])
			m.kids = m.kids[:i:i]
			return
		}
	}
	m.segs = append(m.segs[:i:i], m.segs[n])
	m.kids = m.kids[:i:i]
}

// lastNonBlank returns the length of s without its trailing blanks.
func lastNonBlank(s string) int {
	p := len(s)
	for p > 0 && isBlank(s[p-1]) {
		p--
	}
	return p
}

func isBlank(c byte) bool { return c == ' ' || c == '\t' || c == '\r' || c == '\n' }

// hasComment reports whether a separator region holds a comment. Regions
// between two values contain no strings, so a plain search is exact.
func hasComment(region []byte) bool {
	return bytes.Contains(region, []byte("//")) || bytes.Contains(region, []byte("/*"))
}

// separatorComma finds the comma of a separator region, skipping comments.
func separatorComma(region []byte) int {
	for i := 0; i < len(region); i++ {
		switch {
		case region[i] == ',':
			return i
		case region[i] == '/' && i+1 < len(region) && region[i+1] == '/':
			for i < len(region) && region[i] != '\n' {
				i++
			}
		case region[i] == '/' && i+1 < len(region) && region[i+1] == '*':
			k := bytes.Index(region[i+2:], []byte("*/"))
			if k < 0 {
				return -1
			}
			i += k + 3
		}
	}
	return -1
}

func blank(b []byte) bool {
	for _, c := range b {
		if c != ' ' && c != '\t' && c != '\r' {
			return false
		}
	}
	return true
}
