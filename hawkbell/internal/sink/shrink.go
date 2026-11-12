package sink

import (
	"fmt"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// LabelCommandLen records the length in bytes of a command the shrinker
// cut, so the cut is visible and its size known.
//
// No digest of the full command is kept. An unkeyed one is a guessing
// oracle: a log reader hashes candidate commands until one matches and so
// recovers the cut tail, secrets included (the privacy red team recovered
// 4 of 6 prompts from a 1,600-entry dictionary that way). A digest keyed per
// process would only correlate cuts made by one writer process, and the
// hook's writer lives for one event, so nothing downstream could use it;
// event.Dedupe and Tool.UseID already join the records of one action.
const LabelCommandLen = "target.command.len"

// maxNumericMap is the most entries a map of numbers may keep in an event
// that is being shrunk.
const maxNumericMap = 256

// minCommandKeep is the shortest command head the shrinker leaves before it
// moves on to other fields: the start of a command line is the part that
// identifies it.
const minCommandKeep = 256

// fitLine encodes e as one line of at most max bytes.
//
// A line longer than the reader's buffer is worse than a shortened one:
// Fluent Bit's tail input skips it entirely (or, without skip_long_lines,
// stops reading the file). So an oversize event is shrunk, in the order of
// least forensic loss, and the cut fields are named in Truncated:
//
//  1. tool.input and tool.output are dropped (their hashes and lengths stay).
//  2. target.command loses its tail; the full command's length is kept in
//     Labels (LabelCommandLen), never a digest of it.
//  3. every remaining string, list and map is capped, in three passes with
//     tighter limits each time.
//  4. as a last resort only identity fields survive, sanitized and clipped,
//     with Truncated ["*"] and the command's length in Labels.
//
// A cut string ends in the event contract's "[TRUNCATED:<n>B]" marker (see
// event.Event.Truncated), except target.command, whose full length is in
// Labels instead.
//
// The caller's event is never modified.
func fitLine(e *event.Event, f string, max int) ([]byte, error) {
	return fit(e, max, func(x *event.Event) ([]byte, error) { return encodeLine(x, f) })
}

// shrinkPasses are the limits of step 3: longest string in bytes, most
// elements per list or map.
var shrinkPasses = [...]struct{ str, list int }{{4096, 64}, {1024, 32}, {256, 16}}

// fit is fitLine for any encoding: enc is called on progressively smaller
// copies of e until its output is at most max bytes.
func fit(e *event.Event, max int, enc func(*event.Event) ([]byte, error)) ([]byte, error) {
	var (
		line []byte
		err  error
	)
	// The common case is one encode and a length check. That encode is
	// skipped only when the usual large fields already prove the event is
	// oversize, so a multi-megabyte tool call is never serialized whole
	// just to learn that it is too big.
	if rawSize(e) <= max {
		if line, err = enc(e); err != nil {
			return nil, err
		}
		if len(line) <= max {
			return line, nil
		}
	}
	c := cloneWithoutInput(e)
	fits := func() bool {
		line, err = enc(c)
		return err == nil && len(line) <= max
	}
	mark := func(names ...string) {
		for _, n := range names {
			c.Truncated = appendOnce(c.Truncated, n)
		}
	}

	// Step 1: tool input and output.
	if e.Tool != nil {
		if e.Tool.Input != nil {
			mark("tool.input")
		}
		if c.Tool.Output != "" {
			c.Tool.Output = ""
			mark("tool.output")
		}
	}

	// No single value can be kept whole if it alone exceeds the limit, so
	// capping every string at max loses nothing that could have been kept.
	// Doing it before the next encode bounds the cost of all the encodes
	// below: a hostile event is never re-encoded at its full size.
	var full string
	if c.Target != nil {
		full = c.Target.Command
	}
	cmdCut := false
	capAll := func(maxStr, maxList int) bool {
		names := capStrings(c, maxStr, maxList)
		for _, n := range names {
			cmdCut = cmdCut || n == "target.command"
		}
		if cmdCut {
			// Re-added after every pass so capping Labels cannot drop them.
			c.Labels = withCommandLabels(c.Labels, full)
		}
		mark(names...)
		return len(names) > 0
	}
	capAll(max, 1<<16)
	if fits() {
		return line, nil
	}
	if err != nil {
		return nil, err
	}

	// Step 2: the tail of the command.
	if len(full) > minCommandKeep {
		held, heldTrunc, heldLabels := c.Target.Command, c.Truncated, c.Labels
		c.Truncated = appendOnce(append([]string(nil), heldTrunc...), "target.command")
		c.Labels = withCommandLabels(heldLabels, full)
		keep := len(full) / 2
		if keep > max/2 {
			keep = max / 2
		}
		for {
			if keep < minCommandKeep {
				keep = minCommandKeep
			}
			c.Target.Command = clipString(full, keep)
			if fits() {
				return line, nil
			}
			if keep == minCommandKeep {
				break
			}
			keep /= 2
		}
		// Even the shortest command head did not fit, so the bulk is in
		// other fields. Put the command back and let the general passes
		// spread the cut instead of sacrificing the command for nothing.
		c.Target.Command, c.Truncated, c.Labels = held, heldTrunc, heldLabels
	}

	// Step 3: everything else an agent or a config file can make large.
	for _, p := range shrinkPasses {
		if capAll(p.str, p.list) && fits() {
			return line, nil
		}
	}

	// Step 4: identity only.
	c = skeleton(c, len(full))
	if fits() {
		return line, nil
	}
	if err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("event %s is %d bytes after shrinking, limit %d", safeString(e.ID, 64), len(line), max)
}

// rawSize is a cheap lower bound of the encoded size: the bytes of the
// fields that are large in practice. JSON escaping only ever adds to it.
func rawSize(e *event.Event) int {
	n := 0
	if e.Tool != nil {
		n += len(e.Tool.Output)
	}
	if e.Target != nil {
		n += len(e.Target.Command) + len(e.Target.Path) + len(e.Target.URL) + len(e.Target.Query)
	}
	if e.Prompt != nil {
		n += len(e.Prompt.Text)
	}
	if e.Outcome != nil {
		n += len(e.Outcome.Error)
	}
	return n
}

// withCommandLabels returns a copy of labels that records the length of
// the full command (see LabelCommandLen for why nothing else).
func withCommandLabels(labels map[string]string, full string) map[string]string {
	out := make(map[string]string, len(labels)+1)
	for k, v := range labels {
		out[k] = v
	}
	out[LabelCommandLen] = strconv.Itoa(len(full))
	return out
}

// cloneWithoutInput deep-copies e except Tool.Input, which is dropped first:
// it is the field most likely to be huge or deeply nested, and copying it
// only to discard it would be the most expensive part of the shrink.
func cloneWithoutInput(e *event.Event) *event.Event {
	tmp := *e
	if e.Tool != nil {
		t := *e.Tool
		t.Input = nil
		tmp.Tool = &t
	}
	return tmp.Clone()
}

var eventPkgPath = reflect.TypeOf(event.Event{}).PkgPath()

// capStrings limits every serialized string, string list and string map
// reachable from the event: strings to maxStr bytes, lists and maps to
// maxList entries. It returns the JSON paths of the fields it cut.
//
// It walks the struct by reflection so a field added to the event later is
// covered without anyone remembering to list it here. Lists and maps are
// replaced by cut copies rather than edited in place, so nothing shared
// with the caller's event is ever written to.
func capStrings(c *event.Event, maxStr, maxList int) []string {
	w := capWalker{maxStr: maxStr, maxList: maxList}
	w.walk(reflect.ValueOf(c).Elem(), "")
	return w.cut
}

type capWalker struct {
	maxStr, maxList int
	cut             []string
}

func (w *capWalker) note(path string) { w.cut = appendOnce(w.cut, path) }

func (w *capWalker) walk(v reflect.Value, path string) {
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			w.walk(v.Elem(), path)
		}
	case reflect.Struct:
		t := v.Type()
		if t.PkgPath() != eventPkgPath {
			return // time.Time and anything else we do not own
		}
		for i := 0; i < t.NumField(); i++ {
			f := t.Field(i)
			if !f.IsExported() {
				continue
			}
			name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
			switch name {
			case "-":
				continue // local-only, never serialized
			case "":
				if f.Anonymous {
					w.walk(v.Field(i), path)
					continue
				}
				name = f.Name
			}
			sub := name
			if path != "" {
				sub = path + "." + name
			}
			w.walk(v.Field(i), sub)
		}
	case reflect.String:
		if v.Len() > w.maxStr && v.CanSet() {
			if path == "target.command" {
				v.SetString(clipString(v.String(), w.maxStr)) // its length goes to Labels
			} else {
				v.SetString(cutString(v.String(), w.maxStr))
			}
			w.note(path)
		}
	case reflect.Slice:
		w.slice(v, path)
	case reflect.Map:
		w.stringMap(v, path)
	}
}

func (w *capWalker) slice(v reflect.Value, path string) {
	n := v.Len()
	if n == 0 || !v.CanSet() {
		return
	}
	kind := v.Type().Elem().Kind()
	if kind != reflect.String && kind != reflect.Struct {
		return
	}
	keep := n
	if keep > w.maxList {
		keep = w.maxList
		w.note(path)
	}
	cp := reflect.MakeSlice(v.Type(), keep, keep)
	reflect.Copy(cp, v)
	v.Set(cp)
	for i := 0; i < keep; i++ {
		w.walk(v.Index(i), path)
	}
}

// stringMap caps maps with string keys and string values (labels, detail,
// evidence). Which entries go when there are too many is decided by key
// order so the result is deterministic. Other maps are left to their own
// rules: counters are numbers, and Tool.Input has already been dropped.
func (w *capWalker) stringMap(v reflect.Value, path string) {
	t := v.Type()
	if v.Len() == 0 || !v.CanSet() || t.Key().Kind() != reflect.String {
		return
	}
	if t.Elem().Kind() != reflect.String {
		// A numeric map (health counters) costs a few bytes per entry, so
		// it is only dropped when it is absurdly large.
		if v.Len() > maxNumericMap && t.Elem().Kind() != reflect.Interface {
			v.Set(reflect.Zero(t))
			w.note(path)
		}
		return
	}
	keys := v.MapKeys()
	sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
	out := reflect.MakeMapWithSize(t, min(len(keys), w.maxList))
	changed := false
	for _, k := range keys {
		if out.Len() >= w.maxList || k.Len() > 256 {
			changed = true
			continue
		}
		val := v.MapIndex(k)
		if val.Len() > w.maxStr {
			val = reflect.ValueOf(cutString(val.String(), w.maxStr)).Convert(t.Elem())
			changed = true
		}
		out.SetMapIndex(k, val)
	}
	if changed {
		v.Set(out)
		w.note(path)
	}
}

// skeleton returns an event with identity fields only. Strings are reduced
// to a conservative printable subset and clipped so the encoded size has a
// fixed upper bound no matter what the input held (JSON escaping can expand
// a hostile byte sixfold). cmdLen is the length of the event's command,
// which the skeleton drops; it is kept in Labels like any command cut.
func skeleton(c *event.Event, cmdLen int) *event.Event {
	const n = 64
	s := &event.Event{
		V: c.V, ID: skelString(c.ID, n), TS: c.TS, Seq: c.Seq,
		Kind: event.Kind(skelString(string(c.Kind), 16)), Type: skelString(c.Type, n),
		Source: event.Source(skelString(string(c.Source), 16)), Fidelity: event.Fidelity(skelString(string(c.Fidelity), 16)),
		Privacy:   skelString(c.Privacy, 16),
		Truncated: []string{"*"},
	}
	if cmdLen > 0 {
		s.Labels = map[string]string{LabelCommandLen: strconv.Itoa(cmdLen)}
	}
	if h := c.Host; h != nil {
		s.Host = &event.Host{ID: skelString(h.ID, n), Name: skelString(h.Name, n), OS: skelString(h.OS, 16), Arch: skelString(h.Arch, 16)}
	}
	if u := c.User; u != nil {
		s.User = &event.User{Name: skelString(u.Name, n), ID: skelString(u.ID, n)}
	}
	if a := c.Agent; a != nil {
		s.Agent = &event.Agent{ID: skelString(a.ID, n), Version: skelString(a.Version, 32), PID: a.PID}
	}
	if x := c.Session; x != nil {
		s.Session = &event.Session{ID: skelString(x.ID, n)}
	}
	if t := c.Tool; t != nil {
		s.Tool = &event.Tool{
			Name: skelString(t.Name, n), Kind: event.ToolKind(skelString(string(t.Kind), 16)), UseID: skelString(t.UseID, n),
			InputSHA256: skelString(t.InputSHA256, n), OutputSHA256: skelString(t.OutputSHA256, n), OutputLen: t.OutputLen,
		}
	}
	if d := c.Detection; d != nil {
		s.Detection = &event.Detection{
			RuleID: skelString(d.RuleID, n), Title: skelString(d.Title, n), Severity: skelString(d.Severity, 16),
			Confidence: skelString(d.Confidence, 16), Response: skelString(d.Response, 16), Enforced: d.Enforced,
			DedupKey: skelString(d.DedupKey, n), Count: d.Count,
		}
	}
	if k := c.Check; k != nil {
		s.Check = &event.Check{ID: skelString(k.ID, n), Status: skelString(k.Status, 16), Severity: skelString(k.Severity, 16)}
	}
	if a := c.Asset; a != nil {
		s.Asset = &event.Asset{ID: skelString(a.ID, n), Kind: event.AssetKind(skelString(string(a.Kind), 32)), Name: skelString(a.Name, n)}
	}
	if h := c.Health; h != nil {
		s.Health = &event.Health{SensorVersion: skelString(h.SensorVersion, 32), Mode: skelString(h.Mode, 16), Reason: skelString(h.Reason, n)}
	}
	return s
}

// safeString keeps letters, digits and a few separators, replaces every
// other byte with '_' and clips to n bytes. Nothing it returns needs JSON
// escaping.
func safeString(s string, n int) string {
	if len(s) > n {
		s = s[:n]
	}
	clean := true
	for i := 0; i < len(s); i++ {
		if !safeByte(s[i]) {
			clean = false
			break
		}
	}
	if clean {
		return s
	}
	b := []byte(s)
	for i, c := range b {
		if !safeByte(c) {
			b[i] = '_'
		}
	}
	return string(b)
}

func safeByte(c byte) bool {
	switch {
	case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		return true
	}
	switch c {
	case ' ', '.', '_', '-', ':', '/', '@', '+', '=', ',', '(', ')', '[', ']':
		return true
	}
	return false
}

// skelString is safeString for the skeleton: a value it clips ends in a
// truncMarker. The marker alone may exceed n for the 16-byte enum fields,
// which only a hostile event fills, so the skeleton's bound grows by at
// most one marker per field.
func skelString(s string, n int) string {
	if len(s) <= n {
		return safeString(s, n)
	}
	room := max(n-len(truncMarker(len(s))), 0)
	return safeString(s[:room], room) + truncMarker(len(s)-room)
}

// truncMarker is the event contract's cut marker: how many bytes were cut,
// and no digest of them (an unkeyed one would let a reader confirm guesses
// about the missing text).
func truncMarker(n int) string { return "[TRUNCATED:" + strconv.Itoa(n) + "B]" }

// cutString cuts s to at most n bytes, rune-safe, ending in a truncMarker.
// n is at least the shortest shrink pass (256 bytes), so the marker fits.
//
// The marker counts every byte of the original value that is now missing.
// A value can arrive already cut (by package privacy, or by an earlier
// pass here, which ends it in a marker), so the bytes a marker that falls
// in the cut part stood for are added to the count. The cut never splits
// a marker: a "[TRUNCATED:" or "[REDACTED" marker is kept whole or dropped
// whole.
func cutString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	spans := markerSpans(s)
	// missing is how many bytes of the original value s[from:] stands for.
	missing := func(from int) int {
		m := len(s) - from
		for _, sp := range spans {
			if sp.start >= from && sp.count >= 0 {
				m += sp.count - (sp.end - sp.start)
			}
		}
		return m
	}
	room := n - len(truncMarker(missing(0))) // the widest marker this cut can need
	if room < 0 {
		return clipString(s, n)
	}
	h := len(clipString(s, room))
	for _, sp := range spans {
		if h > sp.start && h < sp.end {
			h = sp.start
			break
		}
	}
	return s[:h] + truncMarker(missing(h))
}

// maxMarkerLen bounds what is read as one marker, so a hostile value full
// of '[' costs linear time.
const maxMarkerLen = 160

// markerSpan is one "[TRUNCATED:<n>B]" marker (count n) or "[REDACTED..]"
// marker (count -1) in a string.
type markerSpan struct{ start, end, count int }

func markerSpans(s string) []markerSpan {
	var out []markerSpan
	for off := 0; off < len(s); {
		i := strings.IndexByte(s[off:], '[')
		if i < 0 {
			break
		}
		i += off
		j := strings.IndexByte(s[i:min(len(s), i+maxMarkerLen)], ']')
		if j < 0 {
			off = i + 1
			continue
		}
		body := s[i : i+j+1]
		count := -1
		if digits, ok := strings.CutPrefix(body, "[TRUNCATED:"); ok {
			digits, ok = strings.CutSuffix(digits, "B]")
			c, err := strconv.Atoi(digits)
			// 12 digits bound the sum of every count in a value well
			// inside an int.
			if !ok || err != nil || c < 0 || len(digits) > 12 {
				off = i + 1
				continue
			}
			count = c
		} else if !strings.HasPrefix(body, "[REDACTED") {
			off = i + 1
			continue
		}
		out = append(out, markerSpan{start: i, end: i + j + 1, count: count})
		off = i + j + 1
	}
	return out
}

// clipString cuts s to at most n bytes without splitting a UTF-8 sequence.
func clipString(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && !utf8.RuneStart(s[n]) {
		n--
	}
	return s[:n]
}

func appendOnce(list []string, s string) []string {
	for _, x := range list {
		if x == s {
			return list
		}
	}
	return append(list, s)
}
