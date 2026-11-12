package transcript

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

func zstdBytes(t *testing.T, data string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := zstd.NewWriter(&buf)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte(data))
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestTailCodexZstdArchive(t *testing.T) {
	e := newEnv(t)
	dir := filepath.Join(e.home, ".codex", "archived_sessions")
	arch := filepath.Join(dir, "rollout-2026-10-01T10-00-00-old.jsonl.zst")
	writeFile(t, arch, string(zstdBytes(t, lines(codexMain...)+`{"timestamp":"2026-11-01T10:00:20.000Z","type":"event_msg","payload":{"type":"user_message","message":"unterminated tail`)))
	tl := e.tailer()
	evs, probs := mustPoll(t, tl)
	if len(probs) != 0 {
		t.Fatalf("problems: %+v", probs)
	}
	if len(evs) != 19 {
		t.Fatalf("archive yielded %d events, want 19 (the unterminated tail is not a record)", len(evs))
	}
	if evs[0].Session.Transcript != arch || evs[0].Session.ID != "0199aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee" {
		t.Errorf("session = %+v", evs[0].Session)
	}
	// Archives are read once.
	if evs, _ := mustPoll(t, tl); len(evs) != 0 {
		t.Fatalf("archive read twice")
	}
	// Same ids as the uncompressed rollout: downstream can deduplicate.
	p, _ := ForFormat(FormatCodex)
	plain, _ := parseLines(t, p, "x", codexMain...)
	if !sameIDs(mustReadFile(t, arch), plain) {
		t.Error("archive and plain rollout produce different event ids")
	}
}

func mustReadFile(t *testing.T, path string) []*event.Event {
	t.Helper()
	evs, _, err := ReadFile(path, nil, event.User{}, 0)
	if err != nil {
		t.Fatal(err)
	}
	return evs
}

func TestTailArchiveOfFollowedRolloutIsNotReplayed(t *testing.T) {
	e := newEnv(t)
	plain := filepath.Join(e.home, ".codex", "sessions", "2026", "11", "01", "rollout-2026-11-01T10-00-00-abc.jsonl")
	writeFile(t, plain, lines(codexMain...))
	tl := e.tailer()
	if evs, _ := mustPoll(t, tl); len(evs) != 19 {
		t.Fatalf("got %d events", len(evs))
	}
	// Codex compresses the rollout in place: .zst appears, .jsonl goes.
	data, _ := os.ReadFile(plain)
	writeFile(t, plain+".zst", string(zstdBytes(t, string(data))))
	os.Remove(plain)
	evs, probs := mustPoll(t, tl)
	if len(evs) != 0 || len(probs) != 0 {
		t.Fatalf("compression replayed or alarmed: events=%d problems=%+v", len(evs), probs)
	}
	if evs, probs := mustPoll(t, tl); len(evs) != 0 || len(probs) != 0 {
		t.Fatalf("second poll: events=%d problems=%+v", len(evs), probs)
	}
}

func TestTailHostileArchives(t *testing.T) {
	e := newEnv(t)
	e.opts.MaxLine = 1 << 16
	dir := filepath.Join(e.home, ".codex", "archived_sessions")
	good := zstdBytes(t, lines(codexMain[0], codexMain[4]))
	cases := map[string][]byte{
		"rollout-garbage.jsonl.zst":   []byte("this is not zstd at all"),
		"rollout-truncated.jsonl.zst": good[:len(good)/2],
		"rollout-empty.jsonl.zst":     {},
		// One enormous line: skipped, not buffered.
		"rollout-bomb.jsonl.zst": zstdBytes(t, strings.Repeat("A", 8<<20)+"\n"+codexMain[0]+"\n"),
	}
	for name, data := range cases {
		writeFile(t, filepath.Join(dir, name), string(data))
	}
	tl := e.tailer()
	evs, probs := mustPoll(t, tl)
	if len(evs) != 1 || evs[0].Type != "session.start" {
		t.Errorf("events = %v", briefs(evs))
	}
	for _, name := range []string{"rollout-garbage.jsonl.zst", "rollout-truncated.jsonl.zst"} {
		if !hasProblem(probs, ProblemUnreadable, filepath.Join(dir, name)) {
			t.Errorf("%s: no problem in %+v", name, probs)
		}
	}
	if st, _ := tl.State(filepath.Join(dir, "rollout-bomb.jsonl.zst")); st.Oversize != 1 {
		t.Errorf("bomb oversize = %d", st.Oversize)
	}
	if evs, probs := mustPoll(t, tl); len(evs) != 0 || len(probs) != 0 {
		t.Errorf("bad archives retried every poll: %d %+v", len(evs), probs)
	}
}

func TestTailGeminiLegacyDocument(t *testing.T) {
	e := newEnv(t)
	path := filepath.Join(e.home, ".gemini", "tmp", "hash", "chats", "session-2025-09-01T08-00-abcdef12.json")
	doc := func(msgs ...string) string {
		return `{"sessionId":"legacy-1","projectHash":"h","startTime":"2025-09-01T08:00:00.000Z","lastUpdated":"x","messages":[` + strings.Join(msgs, ",") + `]}`
	}
	m1 := `{"id":"u1","timestamp":"2025-09-01T08:00:01.000Z","type":"user","content":"first"}`
	m2 := `{"id":"u2","timestamp":"2025-09-01T08:00:02.000Z","type":"user","content":"second"}`
	writeFile(t, path, doc(m1))
	tl := e.tailer()
	evs, _ := mustPoll(t, tl)
	wantSeq(t, evs, "session.start", "prompt.submit")

	// The document is rewritten whole (shorter or longer, same or new inode).
	writeFile(t, path, doc(m1, m2))
	evs, probs := mustPoll(t, tl)
	if len(probs) != 0 {
		t.Fatalf("a rewritten document is not a problem: %+v", probs)
	}
	if got := prompts(evs); strings.Join(got, ",") != "second" {
		t.Fatalf("after rewrite: %v", briefs(evs))
	}
	// Caught mid-rewrite: invalid JSON is counted, the next version is read.
	writeFile(t, path, doc(m1, m2)[:60])
	if evs, _ := mustPoll(t, tl); len(evs) != 0 {
		t.Fatalf("torn document produced events")
	}
	m3 := `{"id":"u3","timestamp":"2025-09-01T08:00:03.000Z","type":"user","content":"third"}`
	writeFile(t, path, doc(m1, m2, m3))
	evs, _ = mustPoll(t, tl)
	if got := prompts(evs); strings.Join(got, ",") != "third" {
		t.Fatalf("after torn rewrite: %v", briefs(evs))
	}
	// And across a restart.
	tl = e.tailer()
	writeFile(t, path, doc(m1, m2, m3, `{"id":"u4","timestamp":"2025-09-01T08:00:04.000Z","type":"user","content":"fourth"}`))
	evs, _ = mustPoll(t, tl)
	if got := prompts(evs); strings.Join(got, ",") != "fourth" {
		t.Fatalf("after restart: %v", briefs(evs))
	}
}
