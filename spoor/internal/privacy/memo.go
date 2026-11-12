package privacy

import (
	"crypto/sha256"
	"strconv"
	"strings"
	"sync"

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
// The memo is keyed by SHA-256 of the hint and the text, so it does not
// keep raw command lines (which may hold credentials) in memory after
// their records are gone; it stores only redacted output, copied so that
// it never pins the buffer a command was sliced from (for a line with
// nothing to redact the output is the line itself, which is what Emit
// writes anyway). It is bounded in entries and bytes and evicts the least
// recently used entry. Failure results (the failure marker) are not
// stored.

const (
	// memoMaxEntries bounds the number of remembered command lines.
	memoMaxEntries = 4096
	// memoMaxBytes bounds the redacted text held (plus a per-entry
	// overhead estimate). Agent command lines are short; 4 MiB holds
	// thousands of them and is negligible next to the daemon's rings.
	memoMaxBytes = 4 << 20
	// memoMaxValue is the largest result stored: one huge line must not
	// evict the whole working set of ordinary commands.
	memoMaxValue = 64 << 10
	// memoEntryOverhead approximates what one entry costs besides its text
	// (key, list links, map slot).
	memoEntryOverhead = 128
)

type memoKey [sha256.Size]byte

type memoEntry struct {
	key        memoKey
	out        string
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

func entrySize(out string) int { return len(out) + memoEntryOverhead }

func (m *cmdMemo) get(k memoKey) (string, bool, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	e := m.entries[k]
	if e == nil {
		m.misses++
		return "", false, false
	}
	m.hits++
	m.moveFront(e)
	return e.out, e.precapped, true
}

func (m *cmdMemo) put(k memoKey, out string, precapped bool) {
	if len(out) > memoMaxValue || out == failMarker {
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
	e := &memoEntry{key: k, out: strings.Clone(out), precapped: precapped}
	m.entries[k] = e
	m.pushFront(e)
	m.bytes += entrySize(out)
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
	m.bytes -= entrySize(e.out)
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
	if out, pre, ok := commandMemo.get(k); ok {
		return out, pre
	}
	out, pre := redactCommandUncached(cmd, hint)
	commandMemo.put(k, out, pre)
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
