package privacy

import (
	"crypto/sha256"
	"sort"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/thomastysong/spoor/internal/shellx"
)

// Command memo.
//
// Structural redaction of one command line (parse with shellx, lex, run
// every view through argument-vector rules, search for recovered secrets)
// is most of what Emit costs on a shell record, and the same text is
// redacted again and again: the hook's pre and post records of one call
// and the transcript twin all carry it, the engine renders a session's
// last records once more as detection context, the full profile redacts
// target.command and tool.input.command, and agents rerun the same build,
// test and git commands all session long.
//
// redactCommand is a pure function of (command text, dialect hint): its
// inputs are the text and tables compiled into the binary (classify's
// patterns and flag tables, shellx's tables, this package's rules), and
// its result still carries classify's unkeyed fingerprints, which each
// caller rewrites with its own key afterwards. So the result for a text
// can be reused for the identical text, whatever Policy asks. If those
// tables ever become updatable at run time (a content bundle), the update
// must call resetCommandMemo.
//
// Why not reuse features' parse: Event.Feat holds what rules need from
// shellx (command names and argument vectors, list facts, flags such as
// shell.decoded), not the inline-code and decoded payload texts the
// redactor re-lexes, and it does not record which text it was computed
// from (the engine rewrites target.command after Compute when a record
// carries a flowed credential). A reuse whose "same text" cannot be
// verified, and that lacks views the canaries depend on, would trade a
// leak risk for about a third of one redaction; the memo is exact by
// construction and also removes the rest of the work for repeats.
//
// What an entry holds. The memo is keyed by SHA-256 of the hint and the
// text and keeps neither. An entry writes the result as pieces of the text
// it was computed from (offset and length) and stores only the result's
// bytes that it does not match in that text: in practice the markers
// redaction put in and what a rewrite composed (the skeleton, a space for
// a control character). A line with nothing to redact is one piece and no
// bytes, and a line cut at maxCommandScan with nothing to redact is one
// piece and its truncation marker, however long it is; neither leaves any
// of its text in the memo once its records are gone. Every stored byte is
// a byte of the redacted result, so a value the redactor removed is never
// stored. On reuse the caller's own text, which has the same key and is
// checked to have the same length, supplies the pieces. A form is stored
// only if it reproduces the result exactly. The memo is bounded in entries
// and bytes and evicts the least recently used entry. Failure results (the
// failure marker) are not stored.

const (
	// memoMaxEntries bounds the number of remembered command lines.
	memoMaxEntries = 4096
	// memoMaxBytes bounds what the entries hold (their stored bytes and
	// pieces, plus a per-entry overhead estimate). Most entries hold a
	// piece or two and no bytes, so the entry count is the binding bound.
	memoMaxBytes = 4 << 20
	// memoMaxValue is the most one entry may hold besides its overhead:
	// one result that is mostly rewritten text must not evict the working
	// set of ordinary commands. It fits the largest scanned head
	// (maxCommandScan) rewritten in full, with room for markers longer
	// than what they replaced, so any line can be remembered.
	memoMaxValue = maxCommandScan + maxCommandScan/4
	// memoEntryOverhead approximates what one entry costs besides its
	// form (key, list links, map slot).
	memoEntryOverhead = 128
	// memoPieceSize is the size of one memoPiece.
	memoPieceSize = 24
	// memoMaxSearches bounds the failed substring searches made while
	// writing one result against its text; past it the encoder only
	// extends matches in place, so encoding stays linear in the result.
	memoMaxSearches = 64
)

type memoKey [sha256.Size]byte

// memoPiece is one piece of a remembered result: n bytes of the command
// text from off, or, when lit, n bytes of the form's own bytes from off.
type memoPiece struct {
	off, n int
	lit    bool
}

// memoForm is a redaction result written against the text it came from.
// It is immutable once stored, so readers use it outside the lock.
type memoForm struct {
	pieces []memoPiece
	lit    string // the result's bytes not matched in the text
	inLen  int    // length of the text
	outLen int    // length of the result
}

// size is what the form holds besides the entry overhead.
func (f memoForm) size() int { return len(f.lit) + len(f.pieces)*memoPieceSize }

// decode rebuilds the result from in, the text the form was computed from.
func (f memoForm) decode(in string) string {
	if len(f.pieces) == 1 && !f.pieces[0].lit {
		p := f.pieces[0]
		return in[p.off : p.off+p.n]
	}
	var b strings.Builder
	b.Grow(f.outLen)
	for _, p := range f.pieces {
		if p.lit {
			b.WriteString(f.lit[p.off : p.off+p.n])
		} else {
			b.WriteString(in[p.off : p.off+p.n])
		}
	}
	return b.String()
}

// encodeResult writes out, the redaction of in, as pieces of in plus the
// bytes of out it does not match there. Markers in out are always stored
// as bytes; the text between them is searched for in in, from where the
// previous match ended, and where a search fails the longest match in
// place is taken and one rune of out is stored. ok is false when the form
// would hold more than memoMaxValue or does not reproduce out.
func encodeResult(in, out string) (f memoForm, ok bool) {
	f = memoForm{inLen: len(in), outLen: len(out)}
	if out == in {
		f.pieces = []memoPiece{{off: 0, n: len(in)}}
		return f, true
	}
	var lit strings.Builder
	addCopy := func(off, n int) {
		if k := len(f.pieces); k > 0 && !f.pieces[k-1].lit && f.pieces[k-1].off+f.pieces[k-1].n == off {
			f.pieces[k-1].n += n
			return
		}
		f.pieces = append(f.pieces, memoPiece{off: off, n: n})
	}
	addLit := func(s string) {
		if k := len(f.pieces); k > 0 && f.pieces[k-1].lit {
			f.pieces[k-1].n += len(s)
		} else {
			f.pieces = append(f.pieces, memoPiece{off: lit.Len(), n: len(s), lit: true})
		}
		lit.WriteString(s)
	}
	c, searches := 0, memoMaxSearches
	match := func(s string) {
		for s != "" {
			if c >= len(in) {
				addLit(s)
				return
			}
			if searches > 0 {
				if i := strings.Index(in[c:], s); i >= 0 {
					addCopy(c+i, len(s))
					c += i + len(s)
					return
				}
				searches--
			}
			if n := commonPrefixLen(in[c:], s); n > 0 {
				addCopy(c, n)
				c += n
				s = s[n:]
				continue
			}
			// The result differs here: store one rune and take it as
			// replacing one rune of the text.
			_, w := utf8.DecodeRuneInString(s)
			addLit(s[:w])
			s = s[w:]
			_, wi := utf8.DecodeRuneInString(in[c:])
			c += wi
		}
	}
	spans := protectedSpans(out)
	sort.Slice(spans, func(i, j int) bool { return spans[i][0] < spans[j][0] })
	pos := 0
	for _, sp := range spans {
		if sp[0] < pos {
			continue // overlaps the previous marker
		}
		match(out[pos:sp[0]])
		addLit(out[sp[0]:sp[1]])
		pos = sp[1]
		if lit.Len()+len(f.pieces)*memoPieceSize > memoMaxValue {
			return memoForm{}, false
		}
	}
	match(out[pos:])
	f.lit = lit.String()
	if f.size() > memoMaxValue || f.decode(in) != out {
		return memoForm{}, false
	}
	return f, true
}

func commonPrefixLen(a, b string) int {
	n := min(len(a), len(b))
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

type memoEntry struct {
	key        memoKey
	form       memoForm
	precapped  bool
	prev, next *memoEntry
}

// cmdMemo is a mutex-guarded LRU list of redaction results. Emit runs
// concurrently, but the lock covers only map and list updates, never the
// redaction itself.
type cmdMemo struct {
	mu      sync.Mutex
	entries map[memoKey]*memoEntry
	head    *memoEntry // most recently used
	tail    *memoEntry // least recently used
	bytes   int
	hits    uint64
	misses  uint64
}

var commandMemo cmdMemo

func memoKeyOf(cmd string, hint shellx.Dialect) memoKey {
	h := sha256.New()
	// Length-prefixed, so no (hint, text) pair can collide with another
	// by moving bytes across the boundary.
	h.Write([]byte(strconv.Itoa(len(hint))))
	h.Write([]byte{':'})
	h.Write([]byte(hint))
	h.Write([]byte(cmd))
	var k memoKey
	h.Sum(k[:0])
	return k
}

func entrySize(f memoForm) int { return f.size() + memoEntryOverhead }

// get returns the remembered redaction of in, whose key is k.
func (m *cmdMemo) get(k memoKey, in string) (string, bool, bool) {
	m.mu.Lock()
	e := m.entries[k]
	if e == nil || e.form.inLen != len(in) {
		m.misses++
		m.mu.Unlock()
		return "", false, false
	}
	m.hits++
	m.moveFront(e)
	f, pre := e.form, e.precapped
	m.mu.Unlock()
	return f.decode(in), pre, true
}

// put remembers out, the redaction of in, under k.
func (m *cmdMemo) put(k memoKey, in, out string, precapped bool) {
	if out == failMarker {
		return
	}
	f, ok := encodeResult(in, out)
	if !ok {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.entries == nil {
		m.entries = make(map[memoKey]*memoEntry)
	}
	if e := m.entries[k]; e != nil {
		// Another caller redacted the same text meanwhile; the result is
		// the same (pure function), so only its recency changes.
		m.moveFront(e)
		return
	}
	e := &memoEntry{key: k, form: f, precapped: precapped}
	m.entries[k] = e
	m.pushFront(e)
	m.bytes += entrySize(f)
	for (len(m.entries) > memoMaxEntries || m.bytes > memoMaxBytes) && m.tail != nil {
		m.evict(m.tail)
	}
}

func (m *cmdMemo) pushFront(e *memoEntry) {
	e.prev, e.next = nil, m.head
	if m.head != nil {
		m.head.prev = e
	}
	m.head = e
	if m.tail == nil {
		m.tail = e
	}
}

func (m *cmdMemo) unlink(e *memoEntry) {
	if e.prev != nil {
		e.prev.next = e.next
	} else {
		m.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else {
		m.tail = e.prev
	}
	e.prev, e.next = nil, nil
}

func (m *cmdMemo) moveFront(e *memoEntry) {
	if m.head == e {
		return
	}
	m.unlink(e)
	m.pushFront(e)
}

func (m *cmdMemo) evict(e *memoEntry) {
	m.unlink(e)
	delete(m.entries, e.key)
	m.bytes -= entrySize(e.form)
}

// reset empties the memo and its counters.
func (m *cmdMemo) reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.entries, m.head, m.tail = nil, nil, nil
	m.bytes, m.hits, m.misses = 0, 0, 0
}

// memoStats reports the memo's size and hit counters (tests, benchmarks).
func (m *cmdMemo) stats() (entries, bytes int, hits, misses uint64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.entries), m.bytes, m.hits, m.misses
}

// resetCommandMemo forgets every remembered redaction. Tests use it to
// exercise the uncached path; a run-time update of the redaction tables
// would have to call it.
func resetCommandMemo() { commandMemo.reset() }

// redactCommand returns cmd with credentials removed. precapped reports
// that the end of the input was dropped, because it lies beyond
// maxCommandScan or beyond where a structural view stopped; the result
// then ends in a truncation marker and callers must keep only a head of
// it, never a tail near the cut. Results are remembered per exact text
// (see cmdMemo).
func redactCommand(cmd string, hint shellx.Dialect) (string, bool) {
	if len(cmd) == 0 {
		return cmd, false
	}
	k := memoKeyOf(cmd, hint)
	if out, pre, ok := commandMemo.get(k, cmd); ok {
		return out, pre
	}
	out, pre := redactCommandUncached(cmd, hint)
	commandMemo.put(k, cmd, out, pre)
	return out, pre
}

// argvMemo remembers argument-vector redactions within one command line.
// The views of a line mostly hand redactArgs the same vectors: the word
// lexer, shellx and the syntax-blind split all read "git status" as
// [git status], and a quoted multi-word value is re-lexed into the vector
// shellx already reported for it. redactArgs is pure, so each distinct
// vector is redacted once; every view still sees, and is checked against,
// the result. Results are shared: callers only read them.
type argvMemo struct {
	m     map[string][]string
	bytes int
}

// maxArgvMemoBytes bounds the keys held for one command line. A line is
// at most maxCommandScan bytes, but decoded payloads and inline code add
// views of their own; past the bound vectors are redacted unremembered.
const maxArgvMemoBytes = 1 << 20

func (am *argvMemo) redact(argv []string) []string {
	if am == nil {
		return redactArgs(argv)
	}
	n := 0
	for _, a := range argv {
		n += len(a) + 8
	}
	// Length-prefixed, so ["a b"] and ["a", "b"] are different keys.
	key := make([]byte, 0, n)
	for _, a := range argv {
		key = strconv.AppendInt(key, int64(len(a)), 10)
		key = append(key, ':')
		key = append(key, a...)
	}
	if red, ok := am.m[string(key)]; ok {
		return red
	}
	red := redactArgs(argv)
	if am.bytes+len(key) <= maxArgvMemoBytes {
		if am.m == nil {
			am.m = make(map[string][]string, 8)
		}
		am.m[string(key)] = red
		am.bytes += len(key)
	}
	return red
}
