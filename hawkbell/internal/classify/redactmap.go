package classify

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"unicode/utf8"
)

const (
	// maxMapDepth is the deepest container RedactMap copies; the top-level
	// map is depth 1.
	maxMapDepth = 12
	// maxMapNodes bounds the work for one call. Tool inputs are small; a map
	// with more values than this is hostile or a bug, and the remainder is
	// replaced rather than walked.
	maxMapNodes = 200000
	// maxMapKey is the longest key kept verbatim.
	maxMapKey = 256

	depthMarker = "[TRUNCATED:depth]"
	nodesMarker = "[TRUNCATED:nodes]"
)

// RedactMap returns a deep copy of m (typically a decoded tool input) that is
// safe to emit:
//
//   - every string passes through Redact;
//   - a string value under a secret-like key (password, token, secret,
//     authorization, api_key, cookie ...) is replaced whole, and so is every
//     string below such a key when its value is a container;
//   - a list made only of strings is treated as an argument vector
//     (RedactArgs), so {"args": ["--token", "x"]} is covered;
//   - strings longer than maxString bytes are cut to a head and a tail around
//     a "[TRUNCATED:<n>B]" marker (maxString <= 0 disables the cut). The cut
//     is applied after redaction, so a secret can never straddle it;
//   - containers nested deeper than 12 levels are replaced by a marker.
//
// truncated lists the dotted paths ("command", "edits[0].new_string") of every
// value that was cut or dropped, sorted, so truncation is never silent. The
// input is not modified. Values of types that JSON decoding cannot produce
// are replaced by "[UNSUPPORTED:<type>]" rather than copied blindly.
func RedactMap(m map[string]any, maxString int) (out map[string]any, truncated []string) {
	defer func() {
		if recover() != nil {
			out, truncated = map[string]any{"_redaction": failClosed}, []string{"*"}
		}
	}()
	if m == nil {
		return nil, nil
	}
	w := &mapWalker{max: maxString, budget: maxMapNodes}
	out = w.object(m, "", 1, false)
	sort.Strings(w.truncated)
	return out, w.truncated
}

type mapWalker struct {
	max       int
	budget    int
	truncated []string
}

func (w *mapWalker) note(path string) {
	if path == "" {
		path = "."
	}
	// The list itself is bounded: one entry per cut, and cuts are bounded by
	// the node budget.
	w.truncated = append(w.truncated, path)
}

func joinPath(parent, key string) string {
	if parent == "" {
		return key
	}
	return parent + "." + key
}

func (w *mapWalker) object(m map[string]any, path string, depth int, force bool) map[string]any {
	out := make(map[string]any, len(m))
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys) // deterministic output and truncation order
	for _, k := range keys {
		outKey := w.key(k)
		p := joinPath(path, outKey)
		out[outKey] = w.value(m[k], p, depth, force || secretName(k) != nameNone)
	}
	return out
}

// key returns the key to emit. Keys are data too: a map keyed by token would
// otherwise leak through its keys.
func (w *mapWalker) key(k string) string {
	if len(k) >= 16 {
		k, _ = Redact(k)
	}
	if len(k) > maxMapKey {
		k, _ = truncateMiddle(k, maxMapKey)
	}
	return k
}

func (w *mapWalker) value(v any, path string, depth int, force bool) any {
	w.budget--
	if w.budget < 0 {
		if w.budget == -1 {
			w.note(path)
		}
		return nodesMarker
	}
	switch t := v.(type) {
	case nil:
		return nil
	case string:
		return w.str(t, path, force)
	case bool, float64, float32, int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64, json.Number:
		return t
	case map[string]any:
		if depth >= maxMapDepth {
			w.note(path)
			return depthMarker
		}
		return w.object(t, path, depth+1, force)
	case []any:
		if depth >= maxMapDepth {
			w.note(path)
			return depthMarker
		}
		return w.list(t, path, depth+1, force)
	case []string:
		if depth >= maxMapDepth {
			w.note(path)
			return depthMarker
		}
		items := make([]any, len(t))
		for i, s := range t {
			items[i] = s
		}
		res := w.list(items, path, depth+1, force)
		out := make([]string, len(res))
		for i, r := range res {
			out[i], _ = r.(string)
		}
		return out
	case map[string]string:
		if depth >= maxMapDepth {
			w.note(path)
			return depthMarker
		}
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		out := make(map[string]string, len(t))
		for _, k := range keys {
			w.budget--
			if w.budget < 0 {
				break
			}
			outKey := w.key(k)
			out[outKey] = w.str(t[k], joinPath(path, outKey), force || secretName(k) != nameNone)
		}
		return out
	case []map[string]any:
		items := make([]any, len(t))
		for i, m := range t {
			items[i] = m
		}
		return w.value(items, path, depth, force)
	case []byte:
		// Raw bytes would be emitted as base64, which no pattern can scan.
		return "[BYTES:" + strconv.Itoa(len(t)) + "]"
	case error:
		return w.str(t.Error(), path, force)
	case fmt.Stringer:
		return w.str(t.String(), path, force)
	}
	return fmt.Sprintf("[UNSUPPORTED:%T]", v)
}

func (w *mapWalker) list(items []any, path string, depth int, force bool) []any {
	out := make([]any, len(items))
	allStrings := len(items) > 0
	for _, it := range items {
		if _, ok := it.(string); !ok {
			allStrings = false
			break
		}
	}
	if allStrings && !force {
		// An argument vector: flag-aware redaction sees what Redact alone
		// cannot ("--password", "hunter2" as separate elements).
		args := make([]string, len(items))
		for i, it := range items {
			args[i] = it.(string)
		}
		for i, r := range RedactArgs(args) {
			w.budget--
			if w.budget < 0 {
				out[i] = nodesMarker
				continue
			}
			out[i] = w.cut(r, path+"["+strconv.Itoa(i)+"]")
		}
		return out
	}
	for i, it := range items {
		out[i] = w.value(it, path+"["+strconv.Itoa(i)+"]", depth, force)
	}
	return out
}

func (w *mapWalker) str(s, path string, force bool) string {
	if force {
		if keepAsWritten(s) {
			// A reference or template is kept, but what Redact finds in it
			// on its own ("[<token>]") is not.
			r, _ := Redact(s)
			return w.cut(r, path)
		}
		return markAroundMarkers(KindSensitiveKey, s)
	}
	r, _ := Redact(s)
	return w.cut(r, path)
}

func (w *mapWalker) cut(s, path string) string {
	r, cut := truncateMiddle(s, w.max)
	if cut {
		w.note(path)
	}
	return r
}

// truncateMiddle keeps the first and last max/2 bytes of s around a marker
// that states how many bytes were removed. Cuts fall on rune boundaries so
// the result stays valid UTF-8 when the input was.
func truncateMiddle(s string, max int) (string, bool) {
	if max <= 0 || len(s) <= max {
		return s, false
	}
	head := (max + 1) / 2
	tail := max - head
	h := head
	for h > 0 && !utf8.RuneStart(s[h]) {
		h--
	}
	t := len(s) - tail
	for t < len(s) && !utf8.RuneStart(s[t]) {
		t++
	}
	if t < h {
		t = h
	}
	return s[:h] + truncationMarker(t-h) + s[t:], true
}
