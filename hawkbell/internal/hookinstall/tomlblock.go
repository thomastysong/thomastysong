package hookinstall

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/BurntSushi/toml"
)

// Codex reads its managed hooks from the [hooks] table of requirements.toml,
// a file that also carries the organisation's other requirements. hawkbell
// therefore owns only a marked block inside it. The block consists of
// [[hooks.<Event>]] array-of-tables headers and nothing else: a "[hooks]"
// header would collide with one the administrator already wrote, and
// hooks.managed_dir must never be set from here (conflicting values across
// requirement layers make Codex fail closed).

const (
	hooksBegin = "# BEGIN " + sensorName
	hooksEnd   = "# END " + sensorName
	otelBegin  = "# BEGIN " + sensorName + " otel"
	otelEnd    = "# END " + sensorName + " otel"
)

var errMarkers = errors.New("the hawkbell markers are unbalanced or repeated")

// block locates a marked block. start and end cover whole lines, from the
// first byte of the BEGIN line to the end of the END line including its
// line break.
type block struct {
	found      bool
	start, end int
}

func findBlock(src []byte, begin, endMark string) (block, error) {
	var b block
	open := false
	pos := 0
	for pos <= len(src) {
		nl := bytes.IndexByte(src[pos:], '\n')
		lineEnd, next := len(src), len(src)+1
		if nl >= 0 {
			lineEnd, next = pos+nl, pos+nl+1
		}
		line := strings.TrimRight(string(src[pos:lineEnd]), " \t\r")
		switch line {
		case begin:
			if open || b.found {
				return block{}, errMarkers
			}
			open = true
			b.start = pos
		case endMark:
			if !open {
				return block{}, errMarkers
			}
			open = false
			b.found = true
			b.end = next
			if b.end > len(src) {
				b.end = len(src)
			}
		}
		pos = next
	}
	if open {
		return block{}, errMarkers
	}
	return b, nil
}

// tomlString writes a TOML basic string. Literal strings ('...') cannot
// carry the apostrophes the PowerShell quoting uses.
func tomlString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r == '"':
			b.WriteString(`\"`)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\u%04X`, r)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

// hooksBlock renders the marked block for requirements.toml. Field names
// match the JSON handler ("type", "command", "commandWindows", "timeout",
// "async"): Codex deserialises both through the same HookHandlerConfig.
// VERIFIED: codex-rs/config/src/config_requirements.rs tests
// (deserialize_managed_hooks_requirements), read 2026-11-11.
func hooksBlock(want []entry, nl string) string {
	var b strings.Builder
	b.WriteString(hooksBegin + nl)
	b.WriteString("# Written by " + sensorName + "; changes inside this block are overwritten." + nl)
	for i, w := range want {
		if i > 0 {
			b.WriteString(nl)
		}
		b.WriteString("[[hooks." + w.event + "]]" + nl)
		if w.matcher != "" {
			b.WriteString("matcher = " + tomlString(w.matcher) + nl)
		}
		b.WriteString(nl)
		b.WriteString("[[hooks." + w.event + ".hooks]]" + nl)
		for _, f := range w.handler {
			switch v := f.v.(type) {
			case string:
				b.WriteString(f.k + " = " + tomlString(v) + nl)
			case int:
				b.WriteString(f.k + " = " + strconv.Itoa(v) + nl)
			case bool:
				b.WriteString(f.k + " = " + strconv.FormatBool(v) + nl)
			}
		}
	}
	b.WriteString(hooksEnd + nl)
	return b.String()
}

// otelBlock renders the opt-in [otel] table for a Codex config.toml.
// VERIFIED: codex-rs/otel/README.md ("exporter = { otlp-http = { endpoint,
// protocol = "json" } }") and OtelExporterKind in config.schema.json.
func otelBlock(ep otelEndpoint, nl string) string {
	return otelBegin + nl +
		"# Written by " + sensorName + "; changes inside this block are overwritten." + nl +
		"[otel]" + nl +
		"exporter = { otlp-http = { endpoint = " + tomlString(ep.logs) + `, protocol = "json" } }` + nl +
		otelEnd + nl
}

func newline(src []byte) string {
	if bytes.Contains(src, []byte("\r\n")) {
		return "\r\n"
	}
	return "\n"
}

// putBlock replaces the marked block, or appends it after exactly one
// line break: that ends an unterminated last line, or leaves one blank
// line after a terminated one. cutBlock relies on there being one.
func putBlock(src []byte, b block, text, nl string) []byte {
	if b.found {
		out := make([]byte, 0, len(src)+len(text))
		out = append(out, src[:b.start]...)
		out = append(out, text...)
		return append(out, src[b.end:]...)
	}
	out := append([]byte(nil), src...)
	if len(out) > 0 {
		out = append(out, nl...)
	}
	return append(out, text...)
}

// cutBlock removes the marked block and the line break putBlock put in
// front of it: the blank line before the block, or, for a block at the end
// of the file, the break that ended the previous line, so a file that had
// no final newline gets its exact bytes back.
func cutBlock(src []byte, b block) []byte {
	start := b.start
	atEnd := b.end == len(src)
	for _, sep := range []string{"\r\n", "\n"} {
		head := src[:start]
		if bytes.HasSuffix(head, []byte(sep+sep)) || (atEnd && bytes.HasSuffix(head, []byte(sep))) {
			start -= len(sep)
			break
		}
	}
	out := make([]byte, 0, len(src))
	out = append(out, src[:start]...)
	return append(out, src[b.end:]...)
}

// keysAfter reports whether a bare "key = value" line follows the block
// before the next table header. TOML would make such a key part of the last
// table of the block, that is, of a hook handler.
func keysAfter(src []byte, b block) bool {
	for _, raw := range strings.Split(string(src[b.end:]), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		return !strings.HasPrefix(line, "[")
	}
	return false
}

// tomlHandler is one hook handler found in a TOML document.
type tomlHandler struct {
	event    string
	hawkbell bool
	sensor   string
	binary   string
}

// tomlDoc is what this package needs to know about a TOML file.
type tomlDoc struct {
	handlers []tomlHandler
	// managedOnly is allow_managed_hooks_only at the top level.
	managedOnly bool
	hasOTel     bool
}

// TOML input bounds. The decoder's time and memory grow with the size of a
// document times its nesting (a 24 KB file of nested inline tables made
// it allocate 4 GiB; 128 KiB at nesting 16 costs about 100 MiB and 0.2 s),
// and the files it reads include the user's own ~/.codex/config.toml, read
// by a root installer. Codex configuration and requirements files are a
// few kilobytes with nesting of three or four.
const (
	maxTOMLSize  = 128 << 10
	maxTOMLDepth = 16
)

var (
	errTOMLSize  = errors.New("larger than 128 KiB, which hawkbell does not parse")
	errTOMLDepth = errors.New("nested more than 16 levels deep, which hawkbell does not parse")
)

// tomlBounds refuses a document the decoder should not see. Nesting counts
// every level a value sits under: open brackets and braces, the parts of a
// dotted key, and the parts of the table header it falls under. Strings and
// comments are skipped the way the TOML lexer skips them.
func tomlBounds(src []byte) error {
	if len(src) > maxTOMLSize {
		return errTOMLSize
	}
	var stack []int // nesting each open bracket added
	open := 0       // sum of stack
	table := 0      // parts of the current table header
	run := 0        // dots in the key or header being read
	keyDots := 0    // dots of the key whose value is being read
	inHeader := false
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch c {
		case '#':
			for i < len(src) && src[i] != '\n' {
				i++
			}
			i--
			continue
		case '"', '\'':
			n := quoteRun(src, i, c)
			multi := n >= 3
			i += 1
			if multi {
				i += 2
			}
			for i < len(src) {
				if c == '"' && src[i] == '\\' {
					i += 2
					continue
				}
				if src[i] == c {
					if !multi {
						break
					}
					if k := quoteRun(src, i, c); k >= 3 {
						i += k - 1
						break
					}
				}
				if !multi && src[i] == '\n' {
					break
				}
				i++
			}
			continue
		case '.':
			run++
		case '=':
			keyDots, run = run, 0
		case '[', '{':
			if open == 0 && c == '[' && !inHeader && keyDots == 0 && run == 0 && lineStart(src, i) {
				// A table header: what follows it sits under its path.
				inHeader = true
				table = 0
			}
			lvl := 1 + keyDots
			stack = append(stack, lvl)
			open += lvl
			keyDots, run = 0, 0
		case ']', '}':
			if len(stack) > 0 {
				open -= stack[len(stack)-1]
				stack = stack[:len(stack)-1]
			}
			if inHeader && open == 0 {
				table = run + 1
				inHeader = false
			}
			if !inHeader {
				run = 0
			}
		case ',', '\n':
			if !inHeader {
				run, keyDots = 0, 0
			}
		}
		depth := open + run
		if !inHeader {
			depth += table
		}
		if depth > maxTOMLDepth {
			return errTOMLDepth
		}
	}
	return nil
}

// quoteRun counts the quote characters c starting at i.
func quoteRun(src []byte, i int, c byte) int {
	n := 0
	for i+n < len(src) && src[i+n] == c {
		n++
	}
	return n
}

// lineStart reports whether only blanks precede position i on its line.
func lineStart(src []byte, i int) bool {
	for j := i - 1; j >= 0; j-- {
		switch src[j] {
		case ' ', '\t':
		case '\n':
			return true
		default:
			return false
		}
	}
	return true
}

// parseTOML decodes a Codex configuration or requirements file. The decoder
// is also the validity check for every file this package is about to write.
func parseTOML(src []byte) (td tomlDoc, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("TOML parser failed")
		}
	}()
	if err := tomlBounds(src); err != nil {
		return td, err
	}
	var m map[string]any
	if _, err := toml.Decode(string(src), &m); err != nil {
		// The library's message quotes the offending line; keep the class.
		return td, errors.New("not valid TOML")
	}
	if v, ok := m["allow_managed_hooks_only"].(bool); ok {
		td.managedOnly = v
	}
	_, td.hasOTel = m["otel"]
	hooks, _ := m["hooks"].(map[string]any)
	events := make([]string, 0, len(hooks))
	for ev := range hooks {
		events = append(events, ev)
	}
	sort.Strings(events)
	for _, ev := range events {
		for _, g := range tableList(hooks[ev]) {
			for _, h := range tableList(g["hooks"]) {
				if len(td.handlers) >= maxHandlers {
					return td, nil
				}
				var lines []string
				for _, k := range []string{"command", "commandWindows"} {
					if s, ok := h[k].(string); ok && s != "" {
						lines = append(lines, s)
					}
				}
				th := tomlHandler{event: ev}
				th.hawkbell, th.sensor = classify(lines)
				if th.hawkbell && len(lines) > 0 {
					th.binary = binaryOf(lines[0])
				}
				td.handlers = append(td.handlers, th)
			}
		}
	}
	return td, nil
}

// tableList accepts both shapes the TOML library produces for an array of
// tables.
func tableList(v any) []map[string]any {
	switch t := v.(type) {
	case []map[string]any:
		return t
	case []any:
		out := make([]map[string]any, 0, len(t))
		for _, e := range t {
			if m, ok := e.(map[string]any); ok {
				out = append(out, m)
			}
		}
		return out
	}
	return nil
}

func (td tomlDoc) counts() (hawkbell, foreign int, sensors []string) {
	seen := map[string]bool{}
	for _, h := range td.handlers {
		if h.hawkbell {
			hawkbell++
			continue
		}
		foreign++
		if h.sensor != "" && !seen[h.sensor] {
			seen[h.sensor] = true
			sensors = append(sensors, h.sensor)
		}
	}
	sort.Strings(sensors)
	return hawkbell, foreign, sensors
}

func (td tomlDoc) binary() string {
	for _, h := range td.handlers {
		if h.hawkbell && h.binary != "" {
			return h.binary
		}
	}
	return ""
}

// blockHash fingerprints the block text with line endings normalised.
func blockHash(text []byte) string {
	sum := sha256.Sum256(bytes.ReplaceAll(text, []byte("\r\n"), []byte("\n")))
	return hex.EncodeToString(sum[:])
}

func sameText(a, b []byte) bool {
	return bytes.Equal(bytes.ReplaceAll(a, []byte("\r\n"), []byte("\n")), bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")))
}
