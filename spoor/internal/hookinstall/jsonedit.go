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
// gives the original bytes back. Comments in the separator (JSONC, only
// edited under Force) stay where they are: a comment after the previous
// member's comma belongs to that member, one before the next member to
// that member.
func (d *jsonDoc) drop(c *node, i int) []byte {
	n := c.children()
	start, end := c.span(i)
	if n == 1 {
		return d.splice(c.start+1, c.end-1, "")
	}
	var before []byte // separator in front of the child, if any
	prevEnd := -1
	if i > 0 {
		_, prevEnd = c.span(i - 1)
		before = d.src[prevEnd:start]
	}
	if i < n-1 {
		nextStart, _ := c.span(i + 1)
		after := d.src[end:nextStart]
		if hasComment(after) || hasComment(before) {
			// Remove the child, its own comma and the blanks after it;
			// comments on either side stay.
			if comma := separatorComma(after); comma >= 0 {
				j := end + comma + 1
				for j < nextStart && isBlank(d.src[j]) {
					j++
				}
				return d.splice(start, j, "")
			}
		}
		if i > 0 {
			return d.splice(prevEnd, end, "")
		}
		return d.splice(start, nextStart, "")
	}
	// The last child: insert put ",<newline><indent>" in front of it.
	if hasComment(before) {
		comma := separatorComma(before)
		nl := bytes.LastIndexByte(before, '\n')
		if comma >= 0 && nl > comma && blank(before[nl+1:]) {
			out := make([]byte, 0, len(d.src))
			out = append(out, d.src[:prevEnd+comma]...)
			out = append(out, d.src[prevEnd+comma+1:prevEnd+nl]...)
			return append(out, d.src[end:]...)
		}
	}
	return d.splice(prevEnd, end, "")
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
