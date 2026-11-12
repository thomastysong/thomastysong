package privacy

import (
	"crypto/sha256"
	"math/rand"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/shellx"
)

// memoCorpus is every command line the redactor is tested on elsewhere
// (canaries, the over-redaction corpus, the benchmark stream) plus hostile
// shapes: oversized, invalid UTF-8, control characters, deep nesting,
// unbalanced quotes, budget exhaustion.
func memoCorpus() []string {
	var out []string
	for _, c := range canaryCorpus() {
		if e := c.build(); e.Target != nil && e.Target.Command != "" {
			out = append(out, e.Target.Command)
		}
	}
	out = append(out, benchCommands...)
	for i := range benchCommands {
		out = append(out, uniqueCmd(benchCommands[i], i))
	}
	out = append(out,
		"", " ", "\t\n",
		"git checkout 3f2a9c1e7b6d4a5f8e9c0b1a2d3e4f5a6b7c8d9e",
		`curl -H "Authorization: Bearer $TOKEN" https://api.internal`,
		"cat > notes.txt <<EOF\nhello world\nEOF",
		"mysql -pMemoPw1 db\x00; echo \xff\xfe",
		"echo a\x1b[31mred\x07 && mysql -pMemoPw2 db",
		strings.Repeat("a", maxCommandScan+1000)+" -pX",
		"mysql -pMemoPw3 "+strings.Repeat("arg ", 20000),
		strings.Repeat("$(", 2000)+"x"+strings.Repeat(")", 2000),
		strings.Repeat(`"'`, 5000),
		strings.Repeat("mysql -pP1 && ", 600),
		strings.Repeat("a;", 2100)+"P=MemoVar7; mysql -p$P db",
		`echo "`+strings.Repeat("y ", 40000)+` P=MemoQuote1; mysql -p$P`,
	)
	return out
}

var memoHints = []shellx.Dialect{"", shellx.Posix, shellx.PowerShell, shellx.Cmd}

// TestCommandMemoMatchesUncached: a remembered redaction is exactly what
// the redactor computes for that text and hint, on first use and on reuse.
func TestCommandMemoMatchesUncached(t *testing.T) {
	resetCommandMemo()
	defer resetCommandMemo()
	for _, hint := range memoHints {
		for i, cmd := range memoCorpus() {
			want, wantPre := redactCommandUncached(cmd, hint)
			for round := 0; round < 2; round++ {
				_, _, hits0, _ := commandMemo.stats()
				got, gotPre := redactCommand(cmd, hint)
				if got != want || gotPre != wantPre {
					t.Fatalf("hint %q case %d round %d: memo returned %q (pre %v), redactor %q (pre %v)",
						hint, i, round, short(got), gotPre, short(want), wantPre)
				}
				_, _, hits1, _ := commandMemo.stats()
				_, encodable := encodeResult(cmd, want)
				stored := cmd != "" && encodable && want != failMarker
				if round == 1 && stored && hits1 != hits0+1 {
					t.Errorf("hint %q case %d: second call was not served from the memo", hint, i)
				}
			}
		}
	}
}

func short(s string) string {
	if len(s) > 200 {
		return s[:100] + "..." + s[len(s)-100:]
	}
	return s
}

// TestCommandMemoKey: the hint is part of the key, and moving bytes
// between hint and text cannot make two inputs share a key.
func TestCommandMemoKey(t *testing.T) {
	if memoKeyOf("x", "posix") == memoKeyOf("posixx", "") || memoKeyOf("ab", "") == memoKeyOf("b", "a") {
		t.Fatal("hint/text boundary is ambiguous")
	}
	if memoKeyOf("ls", shellx.Posix) == memoKeyOf("ls", shellx.PowerShell) {
		t.Fatal("hint not in key")
	}
	if memoKeyOf("ls", "") != memoKeyOf("ls", "") {
		t.Fatal("key not deterministic")
	}
	resetCommandMemo()
	defer resetCommandMemo()
	cmd := `$env:OPENAI_API_KEY="MemoHintPw1"; cmd /c "set X=1"`
	for _, h := range memoHints {
		want, _ := redactCommandUncached(cmd, h)
		if got, _ := redactCommand(cmd, h); got != want {
			t.Errorf("hint %q: got %q want %q", h, got, want)
		}
	}
	if n, _, _, _ := commandMemo.stats(); n != len(memoHints) {
		t.Errorf("%d entries for %d hints", n, len(memoHints))
	}
}

func testMemoKey(i int) memoKey { return sha256.Sum256([]byte("k" + strconv.Itoa(i))) }

// TestCommandMemoBounded: entries, bytes and single-value size are
// bounded, the least recently used entry goes first, and failures are not
// remembered.
func TestCommandMemoBounded(t *testing.T) {
	resetCommandMemo()
	defer resetCommandMemo()
	m := &commandMemo
	// Synthetic entries are computed from the empty text, so every byte of
	// the value is stored.
	put := func(i int, v string, pre bool) { m.put(testMemoKey(i), "", v, pre) }
	get := func(i int) (string, bool, bool) { return m.get(testMemoKey(i), "") }

	put(-1, "keep", false)
	for i := 0; i < memoMaxEntries+500; i++ {
		put(i, "v"+strconv.Itoa(i), false)
		if i%100 == 0 {
			if _, _, ok := get(-1); !ok {
				t.Fatalf("recently used entry evicted after %d inserts", i)
			}
		}
	}
	n, b, _, _ := m.stats()
	if n != memoMaxEntries || b > memoMaxBytes {
		t.Fatalf("entries %d (max %d), bytes %d (max %d)", n, memoMaxEntries, b, memoMaxBytes)
	}
	if _, _, ok := get(0); ok {
		t.Error("least recently used entry survived")
	}
	if _, _, ok := get(memoMaxEntries + 499); !ok {
		t.Error("newest entry missing")
	}

	resetCommandMemo()
	big := strings.Repeat("a", memoMaxValue-memoPieceSize) // one piece of stored bytes
	for i := 0; i < 200; i++ {
		put(i, big, true)
	}
	n, b, _, _ = m.stats()
	if b > memoMaxBytes || n > memoMaxBytes/memoMaxValue {
		t.Fatalf("large values: %d entries, %d bytes", n, b)
	}
	if out, pre, ok := get(199); !ok || out != big || !pre {
		t.Error("large value not returned intact")
	}

	put(-2, big+"a", false)
	put(-3, failMarker, false)
	for _, k := range []int{-2, -3} {
		if _, _, ok := get(k); ok {
			t.Errorf("entry %d should not be stored", k)
		}
	}
	// A text of another length under the same key is a miss, never a
	// decode against the wrong text.
	m.put(testMemoKey(-4), "ls -la", "ls -la", false)
	if _, _, ok := m.get(testMemoKey(-4), "ls -l"); ok {
		t.Error("entry served for a text of another length")
	}

	// Re-putting an existing key keeps one entry and its byte count.
	resetCommandMemo()
	put(1, "one", false)
	put(1, "one", false)
	f, _ := encodeResult("", "one")
	if n, b, _, _ := m.stats(); n != 1 || b != entrySize(f) {
		t.Errorf("duplicate put: %d entries, %d bytes", n, b)
	}
	// The list stays consistent through moves and evictions of head and tail.
	for i := 0; i < 50; i++ {
		put(i%7, "x", false)
		get((i * 3) % 7)
	}
	seen := 0
	for e := m.head; e != nil; e = e.next {
		if e.next != nil && e.next.prev != e {
			t.Fatal("broken list links")
		}
		seen++
	}
	if n, _, _, _ := m.stats(); seen != n || m.tail == nil || m.tail.next != nil {
		t.Fatalf("list has %d entries, map %d", seen, n)
	}
}

// TestCommandMemoHoldsNoRawText: the memo keeps digests of command lines
// and the bytes of their redacted output that are not in the input, never
// a credential from the input.
func TestCommandMemoHoldsNoRawText(t *testing.T) {
	resetCommandMemo()
	defer resetCommandMemo()
	for _, c := range canaryCorpus() {
		if e := c.build(); e.Target != nil && e.Target.Command != "" {
			redactCommand(e.Target.Command, "")
		}
	}
	commandMemo.mu.Lock()
	defer commandMemo.mu.Unlock()
	if len(commandMemo.entries) == 0 {
		t.Fatal("nothing remembered")
	}
	for _, e := range commandMemo.entries {
		if strings.Contains(e.form.lit, "Canary") {
			t.Errorf("memo holds a canary: %q", e.form.lit)
		}
	}
	if reflect.TypeOf(memoEntry{}).NumField() != 5 || reflect.TypeOf(memoForm{}).NumField() != 4 {
		t.Error("memoEntry or memoForm changed: check that they still hold no input text")
	}
}

// TestCommandMemoStoresNoUnchangedText: an entry stores only what
// redaction wrote. A long benign line (which Emit writes as a 4 KiB head
// and tail) leaves none of its text in the memo, and a line with a secret
// leaves only the marker.
func TestCommandMemoStoresNoUnchangedText(t *testing.T) {
	resetCommandMemo()
	defer resetCommandMemo()
	var b strings.Builder
	for i := 0; b.Len() < 20<<10; i++ {
		b.WriteString("echo step-" + rnd(int64(100+i), 6) + "; ")
	}
	benign := b.String()
	middle := benign[10<<10 : 10<<10+40]
	out, _, _ := (&Policy{Profile: ProfileStandard}).Emit(shellEvent(benign))
	if strings.Contains(line(t, out), middle) {
		t.Fatal("setup: middle was emitted")
	}
	secret := "mysql -pMemoStorePw1 db && " + benign
	(&Policy{Profile: ProfileStandard}).Emit(shellEvent(secret))
	commandMemo.mu.Lock()
	defer commandMemo.mu.Unlock()
	if len(commandMemo.entries) != 2 {
		t.Fatalf("%d entries, want 2", len(commandMemo.entries))
	}
	for _, e := range commandMemo.entries {
		if strings.Contains(e.form.lit, middle) || strings.Contains(e.form.lit, "echo") {
			t.Errorf("memo holds %d bytes of command text: %q", len(e.form.lit), short(e.form.lit))
		}
		if e.form.lit != "" && !strings.HasPrefix(e.form.lit, markerOpen) {
			t.Errorf("stored bytes are not a marker: %q", short(e.form.lit))
		}
		if entrySize(e.form) > memoEntryOverhead+4*memoPieceSize+64 {
			t.Errorf("entry costs %d bytes for a %d-byte line", entrySize(e.form), e.form.inLen)
		}
	}
}

// TestCommandMemoKeepsPrecappedLines: a line longer than maxCommandScan
// (the costliest to redact, at 25-30 ms) is remembered, with and without
// something redacted in its head.
func TestCommandMemoKeepsPrecappedLines(t *testing.T) {
	resetCommandMemo()
	defer resetCommandMemo()
	lorem := strings.Repeat("lorem ipsum ", (70<<10)/12)
	for _, cmd := range []string{
		"echo '" + lorem + "'",
		"mysql -pMemoCapPw1 db; echo '" + lorem + "'",
		"echo \x01'" + strings.Repeat("\x02 lorem ", (70<<10)/9) + "'",
		strings.Repeat("a", 4*maxCommandScan),
	} {
		want, wantPre := redactCommandUncached(cmd, "")
		_, _, hits0, _ := commandMemo.stats()
		redactCommand(cmd, "")
		out, pre := redactCommand(cmd, "")
		if out != want || pre != wantPre || !pre {
			t.Fatalf("%d-byte line: memo returned %d bytes (pre %v), redactor %d (pre %v)", len(cmd), len(out), pre, len(want), wantPre)
		}
		if _, _, hits1, _ := commandMemo.stats(); hits1 != hits0+1 {
			t.Errorf("%d-byte line (result %d bytes) not served from the memo", len(cmd), len(want))
		}
	}
	commandMemo.mu.Lock()
	defer commandMemo.mu.Unlock()
	for _, e := range commandMemo.entries {
		if len(e.form.lit) > 1<<10 {
			t.Errorf("precapped %d-byte line stores %d bytes", e.form.inLen, len(e.form.lit))
		}
	}
}

// TestMemoFormRoundTrip: a form reproduces its result exactly from the
// text, for redactor output and for arbitrary edits (substitutions,
// insertions, deletions, markers, invalid UTF-8, empty strings), and it
// stores no byte that is not in the result.
func TestMemoFormRoundTrip(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	check := func(in, out string) {
		t.Helper()
		f, ok := encodeResult(in, out)
		if !ok {
			if len(out) <= memoMaxValue/2 {
				t.Errorf("not encodable: in %q out %q", short(in), short(out))
			}
			return
		}
		if got := f.decode(in); got != out {
			t.Fatalf("round trip: in %q out %q got %q", short(in), short(out), short(got))
		}
		if len(f.lit) > len(out) || f.inLen != len(in) || f.outLen != len(out) {
			t.Fatalf("form %+v for in %d out %d", f, len(in), len(out))
		}
	}
	for _, hint := range memoHints {
		for _, cmd := range memoCorpus() {
			out, _ := redactCommandUncached(cmd, hint)
			check(cmd, out)
		}
	}
	alpha := "ab \t\n'\"$=-[]:\x00\xff\xc3\xa9"
	pieces := []string{markerOpen + "password:hmac=0123]", truncOpen + "12B]", markerOpen, "]", "é", "\xff"}
	for i := 0; i < 3000; i++ {
		n := r.Intn(200)
		in := make([]byte, n)
		for j := range in {
			in[j] = alpha[r.Intn(len(alpha))]
		}
		out := append([]byte(nil), in...)
		for k := r.Intn(8); k > 0; k-- {
			pos := 0
			if len(out) > 0 {
				pos = r.Intn(len(out) + 1)
			}
			switch r.Intn(4) {
			case 0: // insert a marker or a fragment
				p := pieces[r.Intn(len(pieces))]
				out = append(out[:pos], append([]byte(p), out[pos:]...)...)
			case 1: // delete
				if pos < len(out) {
					end := min(len(out), pos+1+r.Intn(10))
					out = append(out[:pos], out[end:]...)
				}
			case 2: // substitute
				if pos < len(out) {
					out[pos] = ' '
				}
			case 3: // replace a span with a marker
				end := min(len(out), pos+r.Intn(20))
				out = append(out[:pos], append([]byte(pieces[0]), out[end:]...)...)
			}
		}
		check(string(in), string(out))
	}
	for _, c := range [][2]string{{"", ""}, {"a", ""}, {"", "a"}, {"abc", "abc"}, {"abc", "xyz"}, {"abcabc", "abc"}} {
		check(c[0], c[1])
	}
	// Encoding stays linear: a result that differs from its text in every
	// other byte is written without a search per difference.
	in := strings.Repeat("ab", maxCommandScan/2)
	out := strings.Repeat("a ", maxCommandScan/2)
	start := time.Now()
	check(in, out)
	if d := time.Since(start); d > 2*time.Second {
		t.Errorf("encoding a fully rewritten 64 KiB result took %v", d)
	}
}

// TestCommandMemoConcurrent: concurrent redactions (Emit runs on several
// goroutines) see correct results while the memo fills, evicts and is
// reset. Run with -race.
func TestCommandMemoConcurrent(t *testing.T) {
	resetCommandMemo()
	defer resetCommandMemo()
	cmds := append([]string{}, benchCommands...)
	for i := 0; i < 64; i++ {
		cmds = append(cmds, uniqueCmd("mysql -pMemoConc"+strconv.Itoa(i)+" db", i))
	}
	want := make([]string, len(cmds))
	for i, c := range cmds {
		want[i], _ = redactCommandUncached(c, "")
	}
	var wg sync.WaitGroup
	errs := make(chan string, 8)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 400; i++ {
				k := (i*7 + g) % len(cmds)
				if got, _ := redactCommand(cmds[k], ""); got != want[k] {
					select {
					case errs <- cmds[k]:
					default:
					}
					return
				}
				if g == 0 && i%97 == 0 {
					resetCommandMemo()
				}
			}
		}(g)
	}
	wg.Wait()
	close(errs)
	for c := range errs {
		t.Errorf("wrong result under concurrency for %q", c)
	}
}

// TestArgvMemo: identical vectors are redacted once, vectors that join to
// the same text are not confused, and the bound only stops remembering.
func TestArgvMemo(t *testing.T) {
	am := &argvMemo{}
	vecs := [][]string{
		{"mysql", "-pArgvPw1", "db"},
		{"mysql -pArgvPw1", "db"},
		{"mysql", "-pArgvPw1 db"},
		{"a b"}, {"a", "b"}, {"1:a"}, {"", "1:a"},
		{"git", "status"},
	}
	for round := 0; round < 2; round++ {
		for _, v := range vecs {
			want := redactArgs(v)
			if got := am.redact(v); !reflect.DeepEqual(got, want) {
				t.Errorf("round %d %q: got %q want %q", round, v, got, want)
			}
		}
	}
	if len(am.m) != len(vecs) {
		t.Errorf("%d entries for %d distinct vectors", len(am.m), len(vecs))
	}
	full := &argvMemo{bytes: maxArgvMemoBytes}
	v := []string{"sshpass", "-pArgvPw2", "ssh", "h"}
	if got := full.redact(v); !reflect.DeepEqual(got, redactArgs(v)) || len(full.m) != 0 {
		t.Errorf("bounded memo: %q, %d entries", got, len(full.m))
	}
	var nilMemo *argvMemo
	if got := nilMemo.redact(v); !reflect.DeepEqual(got, redactArgs(v)) {
		t.Errorf("nil memo: %q", got)
	}
}

// TestJSONFieldsCache: the cached field list is what the struct tags say,
// for every struct type the walk reaches.
func TestJSONFieldsCache(t *testing.T) {
	seen := map[reflect.Type]bool{}
	var visit func(reflect.Type)
	visit = func(rt reflect.Type) {
		for rt.Kind() == reflect.Pointer || rt.Kind() == reflect.Slice || rt.Kind() == reflect.Map {
			rt = rt.Elem()
		}
		if rt.Kind() != reflect.Struct || seen[rt] || rt == timeType {
			return
		}
		seen[rt] = true
		var want []jsonField
		for i := 0; i < rt.NumField(); i++ {
			f := rt.Field(i)
			if !f.IsExported() {
				continue
			}
			if n, ok := jsonName(f); ok {
				want = append(want, jsonField{index: i, name: n})
				visit(f.Type)
			}
		}
		for round := 0; round < 2; round++ {
			if got := jsonFields(rt); !reflect.DeepEqual(got, want) && !(len(got) == 0 && len(want) == 0) {
				t.Errorf("%v: got %v want %v", rt, got, want)
			}
		}
	}
	visit(reflect.TypeOf(event.Event{}))
	if len(seen) < 10 {
		t.Errorf("walked only %d struct types", len(seen))
	}
	for _, f := range jsonFields(reflect.TypeOf(event.Event{})) {
		if f.name == "content" || f.name == "feat" || f.name == "-" {
			t.Errorf("json:\"-\" field %q is walked", f.name)
		}
	}
}

// TestEmitMemoizedEqualsCold: whole records are byte-identical whether
// their commands were redacted now or remembered, in every profile; and
// the hook pre/post and transcript twins of one call share one redaction.
func TestEmitMemoizedEqualsCold(t *testing.T) {
	defer resetCommandMemo()
	var evs []*event.Event
	for i := 0; i < 2*len(benchCommands); i++ {
		evs = append(evs, benchCall(i, i >= len(benchCommands))...)
	}
	for _, c := range canaryCorpus() {
		evs = append(evs, c.build())
	}
	for _, prof := range Profiles {
		p := &Policy{Profile: prof, Key: testKey, KeyID: "k1"}
		for i, e := range evs {
			resetCommandMemo()
			o1, s1, ok1 := p.Emit(e)
			o2, s2, ok2 := p.Emit(e)
			if ok1 != ok2 || s1 != s2 || line(t, o1) != line(t, o2) {
				t.Fatalf("%s record %d: cold and warm differ:\n%s\n%s", prof, i, line(t, o1), line(t, o2))
			}
		}
	}

	resetCommandMemo()
	p := &Policy{Profile: ProfileStandard}
	for _, e := range benchCall(0, true) { // pre, transcript twin, post
		p.Emit(e)
	}
	if n, _, hits, misses := commandMemo.stats(); n != 1 || misses != 1 || hits != 2 {
		t.Errorf("twins: %d entries, %d misses, %d hits; want one redaction reused twice", n, misses, hits)
	}
}
