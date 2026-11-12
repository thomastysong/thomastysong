package hookinstall

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
)

// handlerRef is one hook handler found in a JSON hook file.
type handlerRef struct {
	event  string
	evIdx  int   // index of the event member in the "hooks" object
	grpIdx int   // index of the group (or flat entry) in the event array
	hIdx   int   // index in the group's "hooks" array; -1 for flat formats
	evArr  *node // the event array
	group  *node // element of the event array
	inner  *node // the group's "hooks" array; nil for flat formats
	node   *node // the handler object
	lines  []string
	spoor  bool
	sensor string
}

// hookScan is the hook content of one document.
type hookScan struct {
	hooksIdx int // index of the "hooks" member in the root, -1 when absent
	hooks    *node
	handlers []handlerRef
	// malformed is set when "hooks" exists but is not an object: nothing
	// can be merged into it.
	malformed string
}

// maxHandlers bounds how many handlers of one file are examined.
const maxHandlers = 4096

// scanHooks walks {"hooks": {"<event>": [...]}} in either layout. Shapes it
// does not understand are skipped: they belong to someone else and are left
// exactly as they are.
func scanHooks(d *jsonDoc, kind fileKind) hookScan {
	sc := hookScan{hooksIdx: -1}
	i, hooks := d.root.member("hooks")
	if hooks == nil {
		return sc
	}
	sc.hooksIdx, sc.hooks = i, hooks
	if hooks.kind != kindObject {
		sc.malformed = `"hooks" is not an object`
		return sc
	}
	for ei, ev := range hooks.members {
		if ev.val.kind != kindArray {
			continue
		}
		for gi, g := range ev.val.elems {
			if g.kind != kindObject {
				continue
			}
			if kind == kindFlat {
				sc.add(handlerRef{event: ev.key, evIdx: ei, grpIdx: gi, hIdx: -1, evArr: ev.val, group: g, node: g})
				continue
			}
			_, inner := g.member("hooks")
			if inner == nil || inner.kind != kindArray {
				continue
			}
			for hi, h := range inner.elems {
				if h.kind != kindObject {
					continue
				}
				sc.add(handlerRef{event: ev.key, evIdx: ei, grpIdx: gi, hIdx: hi, evArr: ev.val, group: g, inner: inner, node: h})
			}
		}
	}
	return sc
}

func (sc *hookScan) add(h handlerRef) {
	if len(sc.handlers) >= maxHandlers {
		return
	}
	h.lines = commandLines(h.node)
	h.spoor, h.sensor = classify(h.lines)
	sc.handlers = append(sc.handlers, h)
}

// commandLines collects every command a handler can run, in all the field
// spellings the five agents use: exec form ("command"/"exec" plus "args")
// and the per-shell strings.
func commandLines(h *node) []string {
	var out []string
	args := h.strings("args")
	for _, k := range []string{"command", "exec"} {
		if c := h.text(k); c != "" {
			if len(args) > 0 {
				c += " " + strings.Join(args, " ")
			}
			out = append(out, c)
		}
	}
	for _, k := range []string{"bash", "powershell", "commandWindows", "windows", "linux", "osx"} {
		if c := h.text(k); c != "" {
			out = append(out, c)
		}
	}
	return out
}

func (sc hookScan) spoorHandlers() []handlerRef {
	var out []handlerRef
	for _, h := range sc.handlers {
		if h.spoor {
			out = append(out, h)
		}
	}
	return out
}

// foreign counts handlers that are not spoor's and names the other sensors
// among them.
func (sc hookScan) foreign() (n int, sensors []string) {
	seen := map[string]bool{}
	for _, h := range sc.handlers {
		if h.spoor {
			continue
		}
		n++
		if h.sensor != "" && !seen[h.sensor] {
			seen[h.sensor] = true
			sensors = append(sensors, h.sensor)
		}
	}
	sort.Strings(sensors)
	return n, sensors
}

// binary returns the executable of the first spoor handler, so a caller
// that does not know the installed path can still compare everything else.
func (sc hookScan) binary() string {
	for _, h := range sc.spoorHandlers() {
		if c := h.node.text("command"); c != "" && len(h.node.strings("args")) > 0 {
			return c
		}
		for _, l := range h.lines {
			if b := binaryOf(l); b != "" {
				return b
			}
		}
	}
	return ""
}

type contentState uint8

const (
	contentNone     contentState = iota // no spoor entry
	contentOK                           // exactly the wanted entries
	contentModified                     // spoor entries that differ from the wanted ones
)

// compare checks the spoor entries of a file against the wanted set. The
// whole array element is compared (for grouped formats that includes the
// matcher), because a matcher added to our group silently narrows what the
// sensor sees.
func (sc hookScan) compare(want []entry, kind fileKind) (contentState, string) {
	mine := sc.spoorHandlers()
	if len(mine) == 0 {
		return contentNone, ""
	}
	byEvent := map[string][]handlerRef{}
	for _, h := range mine {
		byEvent[h.event] = append(byEvent[h.event], h)
	}
	var diffs []string
	wanted := map[string]bool{}
	for _, w := range want {
		wanted[w.event] = true
		got := byEvent[w.event]
		switch {
		case len(got) == 0:
			diffs = append(diffs, w.event+" is not registered")
		case len(got) > 1:
			diffs = append(diffs, w.event+" is registered more than once")
		case !reflect.DeepEqual(plain(w.element(kind)), got[0].group.value()):
			diffs = append(diffs, w.event+" differs")
		}
	}
	for ev := range byEvent {
		if !wanted[ev] {
			diffs = append(diffs, "unexpected entry under "+safeName(ev))
		}
	}
	if len(diffs) == 0 {
		return contentOK, ""
	}
	sort.Strings(diffs)
	if len(diffs) > 6 {
		diffs = append(diffs[:6], fmt.Sprintf("and %d more", len(diffs)-6))
	}
	return contentModified, strings.Join(diffs, ", ")
}

// hash fingerprints the spoor entries of a file. The canonical form is
// encoding/json of event name to the list of handler values, so it does not
// depend on layout or on anything else in the file.
func (sc hookScan) hash() string {
	mine := sc.spoorHandlers()
	if len(mine) == 0 {
		return ""
	}
	m := map[string][]any{}
	for _, h := range mine {
		v := map[string]any{"handler": h.node.value()}
		if h.inner != nil {
			if _, mt := h.group.member("matcher"); mt != nil {
				v["matcher"] = mt.value()
			}
		}
		m[h.event] = append(m[h.event], v)
	}
	b, err := json.Marshal(m)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// safeName makes a key from somebody else's file printable.
func safeName(s string) string {
	if len(s) > 40 {
		s = s[:40]
	}
	var b strings.Builder
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r > 0x7e {
			b.WriteByte('?')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// maxEdits bounds the parse-edit loop: every pass removes or adds one entry.
const maxEdits = maxHandlers + 64

var errTooManyEdits = errors.New("too many hook entries to edit")

// removeSpoor deletes every spoor handler from the document. A container
// that only held spoor entries goes with them (the group, then the event
// array, then "hooks" itself), so a file that had no hooks before install
// has none after uninstall.
func removeSpoor(src []byte, kind fileKind) ([]byte, int, error) {
	removed := 0
	for i := 0; i < maxEdits; i++ {
		d, err := parseJSON(src)
		if err != nil {
			return nil, removed, err
		}
		sc := scanHooks(d, kind)
		mine := sc.spoorHandlers()
		if len(mine) == 0 {
			return src, removed, nil
		}
		h := mine[0]
		switch {
		case h.inner != nil && len(h.inner.elems) > 1:
			src = d.drop(h.inner, h.hIdx)
		case len(h.evArr.elems) > 1:
			src = d.drop(h.evArr, h.grpIdx)
		case len(sc.hooks.members) > 1:
			src = d.drop(sc.hooks, h.evIdx)
		default:
			src = d.drop(d.root, sc.hooksIdx)
		}
		removed++
	}
	return nil, removed, errTooManyEdits
}

// addEntries appends the wanted registrations, creating "hooks" and the
// event arrays where they are missing.
func addEntries(src []byte, want []entry, kind fileKind) ([]byte, error) {
	for _, w := range want {
		d, err := parseJSON(src)
		if err != nil {
			return nil, err
		}
		_, hooks := d.root.member("hooks")
		if hooks == nil {
			src = d.addMember(d.root, "hooks", jobj{{w.event, jarr{w.element(kind)}}})
			continue
		}
		if hooks.kind != kindObject {
			return nil, errors.New(`"hooks" is not an object`)
		}
		_, arr := hooks.member(w.event)
		if arr == nil {
			src = d.addMember(hooks, w.event, jarr{w.element(kind)})
			continue
		}
		if arr.kind != kindArray {
			return nil, fmt.Errorf("hooks.%s is not an array", w.event)
		}
		src = d.addElem(arr, w.element(kind))
	}
	return src, nil
}

// newDocument renders a file that holds nothing but spoor's registrations
// (and, when asked for, the native telemetry settings).
func newDocument(want []entry, kind fileKind, extra jobj) []byte {
	root := jobj{}
	if kind == kindFlat {
		// "version": 1 is required by Copilot CLI ("a bad version rejects
		// the entire file") and written by every Cursor installer seen.
		root = append(root, jfield{"version", 1})
	}
	hooks := jobj{}
	for _, w := range want {
		hooks = append(hooks, jfield{w.event, jarr{w.element(kind)}})
	}
	root = append(root, jfield{"hooks", hooks})
	root = append(root, extra...)
	return []byte(render(root, defaultStyle, "", modePretty) + "\n")
}

// ensureVersion adds "version": 1 to a flat-format file that lacks it.
func ensureVersion(src []byte) ([]byte, string, error) {
	d, err := parseJSON(src)
	if err != nil {
		return nil, "", err
	}
	_, v := d.root.member("version")
	if v == nil {
		return d.addMember(d.root, "version", 1), "", nil
	}
	if v.kind != kindNumber || v.num != 1 {
		return src, `the file declares a "version" other than 1; the agent may reject it`, nil
	}
	return src, "", nil
}

// onlySpoorLeft reports whether a document holds nothing a user could miss
// once the spoor entries are gone: an empty object, or only the "version"
// marker of the flat formats.
func onlySpoorLeft(src []byte, kind fileKind) bool {
	d, err := parseJSON(src)
	if err != nil {
		return false
	}
	for _, m := range d.root.members {
		if kind == kindFlat && m.key == "version" {
			continue
		}
		return false
	}
	return true
}
