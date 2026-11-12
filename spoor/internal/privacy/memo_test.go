package privacy

import (
	"crypto/sha256"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/shellx"
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
				stored := cmd != "" && len(want) <= memoMaxValue && want != failMarker
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

	m.put(testMemoKey(-1), "keep", false)
	for i := 0; i < memoMaxEntries+500; i++ {
		m.put(testMemoKey(i), "v"+strconv.Itoa(i), false)
		if i%100 == 0 {
			if _, _, ok := m.get(testMemoKey(-1)); !ok {
				t.Fatalf("recently used entry evicted after %d inserts", i)
			}
		}
	}
	n, b, _, _ := m.stats()
	if n != memoMaxEntries || b > memoMaxBytes {
		t.Fatalf("entries %d (max %d), bytes %d (max %d)", n, memoMaxEntries, b, memoMaxBytes)
	}
	if _, _, ok := m.get(testMemoKey(0)); ok {
		t.Error("least recently used entry survived")
	}
	if _, _, ok := m.get(testMemoKey(memoMaxEntries + 499)); !ok {
		t.Error("newest entry missing")
	}

	resetCommandMemo()
	big := strings.Repeat("a", memoMaxValue)
	for i := 0; i < 200; i++ {
		m.put(testMemoKey(i), big, true)
	}
	n, b, _, _ = m.stats()
	if b > memoMaxBytes || n > memoMaxBytes/memoMaxValue {
		t.Fatalf("large values: %d entries, %d bytes", n, b)
	}
	if out, pre, ok := m.get(testMemoKey(199)); !ok || out != big || !pre {
		t.Error("large value not returned intact")
	}

	m.put(testMemoKey(-2), big+"a", false)
	m.put(testMemoKey(-3), failMarker, false)
	for _, k := range []int{-2, -3} {
		if _, _, ok := m.get(testMemoKey(k)); ok {
			t.Errorf("entry %d should not be stored", k)
		}
	}

	// Re-putting an existing key keeps one entry and its byte count.
	resetCommandMemo()
	m.put(testMemoKey(1), "one", false)
	m.put(testMemoKey(1), "one", false)
	if n, b, _, _ := m.stats(); n != 1 || b != entrySize("one") {
		t.Errorf("duplicate put: %d entries, %d bytes", n, b)
	}
	// The list stays consistent through moves and evictions of head and tail.
	for i := 0; i < 50; i++ {
		m.put(testMemoKey(i%7), "x", false)
		m.get(testMemoKey((i * 3) % 7))
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
// and their redacted output, never a credential from the input.
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
		if strings.Contains(e.out, "Canary") {
			t.Errorf("memo holds a canary: %q", e.out)
		}
	}
	if reflect.TypeOf(memoEntry{}).NumField() != 5 {
		t.Error("memoEntry changed: check that it still holds no input text")
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
