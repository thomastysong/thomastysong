package transcript

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/event"
)

// env is a temp home with one Claude root and a controllable clock.
type env struct {
	t     *testing.T
	home  string
	state string
	now   time.Time
	opts  TailerOptions
}

func newEnv(t *testing.T) *env {
	t.Helper()
	dir := t.TempDir()
	e := &env{t: t, home: filepath.Join(dir, "home"), state: filepath.Join(dir, "state", "transcripts.json"), now: time.Now()}
	e.opts = TailerOptions{
		Roots:     func() []Root { return HomeRoots(e.home, event.User{Name: "alice"}) },
		StateFile: e.state,
		FromStart: true,
		now:       func() time.Time { return e.now },
	}
	return e
}

func (e *env) tailer() *Tailer { return NewTailer(e.opts) }

func (e *env) claude(session string) string {
	return filepath.Join(e.home, ".claude", "projects", "-work-repo", session+".jsonl")
}

func (e *env) advance(d time.Duration) { e.now = e.now.Add(d) }

func prompts(evs []*event.Event) []string {
	var out []string
	for _, e := range evs {
		if e.Type == event.TypePromptSubmit && e.Content != nil {
			out = append(out, e.Content.PromptText)
		}
	}
	return out
}

func TestTailIncrementalAppendsAndTornLine(t *testing.T) {
	e := newEnv(t)
	path := e.claude("s1")
	writeFile(t, path, lines(claudePrompt("s1", 0, "one"), claudePrompt("s1", 1, "two")))
	tl := e.tailer()

	evs, probs := mustPoll(t, tl)
	if got := prompts(evs); strings.Join(got, ",") != "one,two" || len(probs) != 0 {
		t.Fatalf("first poll: %v %v", got, probs)
	}
	if evs[0].User == nil || evs[0].User.Name != "alice" || evs[0].Session.Transcript != path {
		t.Errorf("user/transcript not stamped: %+v %+v", evs[0].User, evs[0].Session)
	}
	// Nothing new: nothing emitted.
	if evs, _ := mustPoll(t, tl); len(evs) != 0 {
		t.Fatalf("idle poll emitted %d events", len(evs))
	}

	// A line being written: the part before the LF must not be consumed.
	full := claudePrompt("s1", 2, "three")
	appendFile(t, path, full[:40])
	if evs, _ := mustPoll(t, tl); len(evs) != 0 {
		t.Fatalf("torn line was parsed: %v", briefs(evs))
	}
	cp := tl.Checkpoints()[path]
	if cp.Offset >= cp.Size {
		t.Fatalf("checkpoint ran past the last LF: %+v", cp)
	}
	appendFile(t, path, full[40:]+"\n"+claudePrompt("s1", 3, "four")+"\n")
	evs, _ = mustPoll(t, tl)
	if got := prompts(evs); strings.Join(got, ",") != "three,four" {
		t.Fatalf("after completing the line: %v", got)
	}
	if cp := tl.Checkpoints()[path]; cp.Offset != cp.Size {
		t.Errorf("checkpoint = %+v", cp)
	}
	st, ok := tl.State(path)
	if !ok || st.SessionID != "s1" || st.Lines != 4 || st.Malformed != 0 {
		t.Errorf("state = %+v", st)
	}
}

func TestTailFromEndSkipsHistoryAndPartialLine(t *testing.T) {
	e := newEnv(t)
	e.opts.FromStart = false
	// A Codex rollout: the session id lives only in the first record.
	path := filepath.Join(e.home, ".codex", "sessions", "2026", "11", "01", "rollout-2026-11-01T10-00-00-abc.jsonl")
	half := codexMain[6] // a function_call, written only halfway at first sight
	writeFile(t, path, lines(codexMain[0], codexMain[2], codexMain[4])+half[:50])
	tl := e.tailer()
	if evs, _ := mustPoll(t, tl); len(evs) != 0 {
		t.Fatalf("history was emitted: %v", briefs(evs))
	}
	// The rest of the half-seen line arrives, then a fresh call and result.
	appendFile(t, path, half[50:]+"\n"+lines(codexMain[19], codexMain[20]))
	evs, _ := mustPoll(t, tl)
	wantSeq(t, evs, "tool.pre shell", "tool.post shell denied deny")
	// Session identity and posture were learned from the head without emitting it.
	if s := evs[0].Session; s.ID != "0199aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee" || s.Model != "gpt-5.2-codex" || s.PermissionMode != "default" {
		t.Errorf("primed session = %+v", s)
	}
	if st, _ := tl.State(path); st.Malformed != 0 || st.Lines != 2 {
		t.Errorf("the discarded partial line must not count: %+v", st)
	}
}

func TestTailMaxBackfillIgnoresOldFilesUntilTheyChange(t *testing.T) {
	e := newEnv(t)
	old, fresh := e.claude("old"), e.claude("fresh")
	writeFile(t, old, lines(claudePrompt("old", 0, "ancient")))
	writeFile(t, fresh, lines(claudePrompt("fresh", 0, "recent")))
	twoDays := e.now.Add(-48 * time.Hour)
	if err := os.Chtimes(old, twoDays, twoDays); err != nil {
		t.Fatal(err)
	}
	tl := e.tailer()
	evs, _ := mustPoll(t, tl)
	if got := prompts(evs); strings.Join(got, ",") != "recent" {
		t.Fatalf("backfill window not applied: %v", got)
	}
	// The old session is resumed: only what is appended is read.
	appendFile(t, old, claudePrompt("old", 1, "resumed")+"\n")
	evs, _ = mustPoll(t, tl)
	if got := prompts(evs); strings.Join(got, ",") != "resumed" {
		t.Fatalf("resumed old session: %v", got)
	}
	if evs[0].Session.ID != "old" || evs[0].Session.CWD != "/work/repo" {
		t.Errorf("session = %+v", evs[0].Session)
	}
}

func TestTailTruncationReplacementRewrite(t *testing.T) {
	e := newEnv(t)
	path := e.claude("s1")
	writeFile(t, path, lines(claudePrompt("s1", 0, "one"), claudePrompt("s1", 1, "two"), claudePrompt("s1", 2, "three")))
	tl := e.tailer()
	mustPoll(t, tl)

	// Truncated below the checkpoint.
	writeFile(t, path, lines(claudePrompt("s1", 5, "after truncate")))
	evs, probs := mustPoll(t, tl)
	if !hasProblem(probs, ProblemTruncated, path) || probs[0].SessionID != "s1" {
		t.Fatalf("no truncation problem: %+v", probs)
	}
	if got := prompts(evs); strings.Join(got, ",") != "after truncate" {
		t.Fatalf("after truncation: %v", got)
	}

	// Replaced by a different file (new inode, different content).
	tmp := path + ".new"
	writeFile(t, tmp, lines(claudePrompt("s1", 6, "replacement content"), claudePrompt("s1", 7, "more")))
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	evs, probs = mustPoll(t, tl)
	if !hasProblem(probs, ProblemReplaced, path) {
		t.Fatalf("no replacement problem: %+v", probs)
	}
	if got := prompts(evs); strings.Join(got, ",") != "replacement content,more" {
		t.Fatalf("after replacement: %v", got)
	}

	// Replaced by a copy with the same content plus one line: reported, but
	// nothing already read is emitted again.
	data, _ := os.ReadFile(path)
	writeFile(t, tmp, string(data)+claudePrompt("s1", 8, "appended to the copy")+"\n")
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
	evs, probs = mustPoll(t, tl)
	if !hasProblem(probs, ProblemReplaced, path) {
		t.Fatalf("no replacement problem for the copy: %+v", probs)
	}
	if got := prompts(evs); strings.Join(got, ",") != "appended to the copy" {
		t.Fatalf("after same-prefix replacement: %v", got)
	}

	// Rewritten in place: same inode, not shorter, different history.
	data, _ = os.ReadFile(path)
	forged := strings.ReplaceAll(string(data), "appended to the copy", "FORGED HISTORY ENTRY") + claudePrompt("s1", 9, "tail") + "\n"
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString(forged)
	f.Close()
	evs, probs = mustPoll(t, tl)
	if !hasProblem(probs, ProblemTruncated, path) || !strings.Contains(probs[0].Detail, "rewritten") {
		t.Fatalf("in-place rewrite not detected: %+v", probs)
	}
	if got := prompts(evs); len(got) != 4 || got[2] != "FORGED HISTORY ENTRY" {
		t.Fatalf("after rewrite: %v", got)
	}
}

func TestTailDeletion(t *testing.T) {
	e := newEnv(t)
	live, stale := e.claude("live"), e.claude("stale")
	writeFile(t, live, lines(claudePrompt("live", 0, "x")))
	writeFile(t, stale, lines(claudePrompt("stale", 0, "y")))
	old := e.now.Add(-72 * time.Hour)
	os.Chtimes(stale, old, old)
	tl := e.tailer()
	mustPoll(t, tl)

	os.Remove(live)
	os.Remove(stale)
	_, probs := mustPoll(t, tl)
	if len(probs) != 1 || probs[0].Kind != ProblemDeleted || probs[0].Path != live || probs[0].SessionID != "live" {
		t.Fatalf("deletion problems = %+v", probs)
	}
	if len(tl.Checkpoints()) != 0 {
		t.Errorf("checkpoints not dropped: %v", tl.Checkpoints())
	}
	// Reported once.
	if _, probs := mustPoll(t, tl); len(probs) != 0 {
		t.Errorf("deletion reported again: %+v", probs)
	}
}

func TestTailRenameKeepsCheckpoint(t *testing.T) {
	e := newEnv(t)
	from := filepath.Join(e.home, ".codex", "sessions", "2026", "11", "01", "rollout-2026-11-01T10-00-00-abc.jsonl")
	to := filepath.Join(e.home, ".codex", "archived_sessions", "rollout-2026-11-01T10-00-00-abc.jsonl")
	writeFile(t, from, lines(codexMain[0], codexMain[4]))
	tl := e.tailer()
	evs, _ := mustPoll(t, tl)
	wantSeq(t, evs, "session.start", "prompt.submit")

	if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(from, to); err != nil {
		t.Fatal(err)
	}
	appendFile(t, to, lines(codexMain[19], codexMain[20]))
	evs, probs := mustPoll(t, tl)
	if len(probs) != 0 {
		t.Fatalf("a move is not a deletion or a replacement: %+v", probs)
	}
	wantSeq(t, evs, "tool.pre shell", "tool.post shell denied deny")
	if evs[0].Session.Transcript != to || evs[0].Session.ID != "0199aaaa-bbbb-7ccc-8ddd-eeeeeeeeeeee" {
		t.Errorf("session after move = %+v", evs[0].Session)
	}
	if cps := tl.Checkpoints(); len(cps) != 1 || cps[to].Offset == 0 {
		t.Errorf("checkpoints = %+v", cps)
	}
}

func TestTailOwnerChecks(t *testing.T) {
	e := newEnv(t)
	path := e.claude("s1")
	writeFile(t, path, lines(claudePrompt("s1", 0, "x")))

	// The AllowUID hook refuses.
	e.opts.AllowUID = func(p string) bool { return p != path }
	tl := e.tailer()
	evs, probs := mustPoll(t, tl)
	if len(evs) != 0 || !hasProblem(probs, ProblemOwnerMismatch, path) {
		t.Fatalf("AllowUID not honoured: %v %+v", briefs(evs), probs)
	}
	if _, probs := mustPoll(t, tl); len(probs) != 0 {
		t.Errorf("standing problem repeated: %+v", probs)
	}
	// The hook relents: the file is read.
	e.opts.AllowUID = nil
	tl = e.tailer()
	if evs, _ := mustPoll(t, tl); len(evs) != 1 {
		t.Fatalf("got %d events", len(evs))
	}
}

func TestTailOversizeLines(t *testing.T) {
	e := newEnv(t)
	e.opts.MaxLine = 4096
	path := e.claude("s1")
	big := `{"type":"user","sessionId":"s1","message":{"role":"user","content":"` + strings.Repeat("A", 10_000) + `"}}`
	huge := `{"type":"user","sessionId":"s1","message":{"role":"user","content":"` + strings.Repeat("B", 600_000) + `"}}`
	writeFile(t, path, lines(claudePrompt("s1", 0, "before"), big, claudePrompt("s1", 1, "between"), huge, claudePrompt("s1", 2, "after")))
	tl := e.tailer()
	evs, _ := mustPoll(t, tl)
	if got := prompts(evs); strings.Join(got, ",") != "before,between,after" {
		t.Fatalf("prompts = %v", got)
	}
	st, _ := tl.State(path)
	if st.Oversize != 2 || st.Malformed != 0 {
		t.Errorf("oversize=%d malformed=%d", st.Oversize, st.Malformed)
	}

	// An oversize line that arrives in pieces across polls is still skipped
	// as one line, and the record after it is read.
	appendFile(t, path, `{"type":"user","sessionId":"s1","message":{"role":"user","content":"`+strings.Repeat("C", 500_000))
	if evs, _ := mustPoll(t, tl); len(evs) != 0 {
		t.Fatalf("partial oversize line produced events")
	}
	if cp := tl.Checkpoints()[path]; cp.Offset != cp.Size {
		t.Errorf("an oversize line in progress must not be re-read every poll: %+v", cp)
	}
	appendFile(t, path, strings.Repeat("C", 500_000))
	mustPoll(t, tl)
	appendFile(t, path, `"}}`+"\n"+claudePrompt("s1", 3, "survivor")+"\n")
	evs, _ = mustPoll(t, tl)
	if got := prompts(evs); strings.Join(got, ",") != "survivor" {
		t.Fatalf("after pieced oversize line: %v", got)
	}
	if st, _ := tl.State(path); st.Oversize != 3 || st.Malformed != 0 {
		t.Errorf("oversize=%d malformed=%d", st.Oversize, st.Malformed)
	}
}

func TestTailRestartKeepsStateAndPairs(t *testing.T) {
	e := newEnv(t)
	path := e.claude("5d1f26db")
	// Up to and including the Bash tool_use (record 3); results come later.
	writeFile(t, path, lines(claudeMain[:4]...))
	tl := e.tailer()
	evs, _ := mustPoll(t, tl)
	wantSeq(t, evs, "prompt.submit", "tool.pre Read", "tool.pre Bash")

	// The checkpoint store must not hold prompts or tool inputs.
	raw, err := os.ReadFile(e.state)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"sk-ant-SECRETSECRET", "make build", "Makefile"} {
		if strings.Contains(string(raw), secret) {
			t.Errorf("checkpoint store holds content %q", secret)
		}
	}
	if fi, err := os.Stat(e.state); err != nil || fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("checkpoint store mode = %v", fi.Mode())
	}

	// Restart: a new Tailer on the same store.
	appendFile(t, path, lines(claudeMain[4:7]...))
	tl = e.tailer()
	evs, probs := mustPoll(t, tl)
	if len(probs) != 0 {
		t.Fatalf("problems after restart: %+v", probs)
	}
	wantSeq(t, evs, "tool.post Read ok", "tool.post Bash error", "tool.pre Bash", "tool.post Bash denied deny")
	post := find(t, evs, event.TypeToolPost, "toolu_02")
	if post.Tool.Kind != event.ToolShell || post.Tool.InputSHA256 == "" || post.Session.ID != "5d1f26db" || post.Session.Model != "claude-opus-5" {
		t.Errorf("pairing across restart lost the call: %+v %+v", post.Tool, post.Session)
	}
	if st, _ := tl.State(path); st.Lines != 7 || st.Version != "2.1.300" || st.PermissionMode != "default" {
		t.Errorf("state after restart = %+v", st)
	}
}

func TestTailGeminiDedupeSurvivesRestartAndRewrite(t *testing.T) {
	e := newEnv(t)
	path := filepath.Join(e.home, ".gemini", "tmp", "repo", "chats", "session-2026-11-01T08-00-7b1c2d3e.jsonl")
	writeFile(t, path, lines(geminiMain[:4]...)) // header, prompt, $set, call executing
	tl := e.tailer()
	evs, _ := mustPoll(t, tl)
	wantSeq(t, evs, "session.start", "prompt.submit", "tool.pre run_shell_command")

	appendFile(t, path, lines(geminiMain[4], geminiMain[5])) // same message, now with result, then tokens
	tl = e.tailer()                                          // restart in between
	evs, _ = mustPoll(t, tl)
	wantSeq(t, evs, "tool.post run_shell_command ok")
	// The call's name and class survive the restart; its input and target
	// do not, because the checkpoint store never holds content.
	if evs[0].Session.ID != "7b1c2d3e-0000-4000-8000-000000000001" || evs[0].Tool.Kind != event.ToolShell || evs[0].Tool.InputSHA256 == "" || evs[0].Target != nil {
		t.Errorf("post after restart = %+v %+v %+v", evs[0].Session, evs[0].Tool, evs[0].Target)
	}

	// Gemini CLI rewrites the file (temp + rename) with re-serialized
	// records: a replacement is reported, but known ids do not replay.
	var compact []string
	for _, l := range geminiMain[:6] {
		var v any
		json.Unmarshal([]byte(l), &v)
		b, _ := json.Marshal(v)
		compact = append(compact, string(b))
	}
	compact = append(compact, `{"id":"u9","timestamp":"2026-11-01T08:10:00.000Z","type":"user","content":[{"text":"after rewrite"}]}`)
	tmp := path + ".tmp"
	writeFile(t, tmp, lines(compact...))
	os.Rename(tmp, path)
	evs, probs := mustPoll(t, tl)
	if !hasProblem(probs, ProblemReplaced, path) {
		t.Fatalf("problems = %+v", probs)
	}
	if got := prompts(evs); strings.Join(got, ",") != "after rewrite" || len(evs) != 1 {
		t.Fatalf("after rewrite: %v", briefs(evs))
	}
}

func TestTailDeferCommitRereadsUncommitted(t *testing.T) {
	e := newEnv(t)
	e.opts.DeferCommit = true
	path := e.claude("s1")
	writeFile(t, path, lines(claudePrompt("s1", 0, "one")))
	tl := e.tailer()
	first, _ := mustPoll(t, tl)
	if len(first) != 1 {
		t.Fatalf("got %d", len(first))
	}
	if _, err := os.Stat(e.state); !os.IsNotExist(err) {
		t.Fatalf("store written before Commit: %v", err)
	}
	// Crash before Commit: the batch comes back, with the same ids.
	tl = e.tailer()
	again, _ := mustPoll(t, tl)
	if !sameIDs(first, again) {
		t.Fatalf("uncommitted batch not replayed identically")
	}
	if err := tl.Commit(); err != nil {
		t.Fatal(err)
	}
	tl = e.tailer()
	if evs, _ := mustPoll(t, tl); len(evs) != 0 {
		t.Fatalf("committed batch replayed: %v", briefs(evs))
	}
}

func TestTailCorruptStoreIsReportedNotFatal(t *testing.T) {
	e := newEnv(t)
	path := e.claude("s1")
	writeFile(t, path, lines(claudePrompt("s1", 0, "one")))
	for _, bad := range []string{"{not json", `{"version":99,"files":{}}`, strings.Repeat("[", 100_000), `{"version":1,"files":{"/x":null,"":{}}}`} {
		writeFile(t, e.state, bad)
		tl := e.tailer()
		evs, probs, err := tl.Poll(t.Context())
		if err != nil {
			t.Fatalf("Poll with store %.20q: %v", bad, err)
		}
		if len(evs) != 1 {
			t.Errorf("store %.20q: %d events", bad, len(evs))
		}
		if strings.HasPrefix(bad, `{"version":1`) {
			continue // structurally valid; bad entries are dropped silently
		}
		if !hasProblem(probs, ProblemUnreadable, e.state) {
			t.Errorf("store %.20q: no problem reported: %+v", bad, probs)
		}
	}
}

func TestTailSchemaDrift(t *testing.T) {
	e := newEnv(t)
	path := e.claude("s1")
	var ls []string
	for i := 0; i < 30; i++ {
		ls = append(ls, fmt.Sprintf(`{"type":"envelope-v9","seq":%d,"body":{"kind":"turn"}}`, i))
	}
	ls = append(ls, "not json at all", claudePrompt("s1", 0, "still parsed"))
	writeFile(t, path, lines(ls...))
	tl := e.tailer()
	evs, probs := mustPoll(t, tl)
	if len(evs) != 1 || !hasProblem(probs, ProblemSchemaDrift, path) {
		t.Fatalf("events=%d problems=%+v", len(evs), probs)
	}
	appendFile(t, path, `{"type":"envelope-v9"}`+"\n")
	if _, probs := mustPoll(t, tl); len(probs) != 0 {
		t.Errorf("drift reported twice: %+v", probs)
	}
	if st, _ := tl.State(path); st.Unknown != 31 || st.Malformed != 1 {
		t.Errorf("unknown=%d malformed=%d", st.Unknown, st.Malformed)
	}
}

func TestTailByteBudgetDrainsWithoutLossOrRepeat(t *testing.T) {
	e := newEnv(t)
	e.opts.MaxPollBytes = 2048
	var want []string
	for f := 0; f < 3; f++ {
		var ls []string
		for i := 0; i < 40; i++ {
			text := fmt.Sprintf("f%d-p%d", f, i)
			want = append(want, text)
			ls = append(ls, claudePrompt(fmt.Sprintf("s%d", f), i, text))
		}
		writeFile(t, e.claude(fmt.Sprintf("s%d", f)), lines(ls...))
	}
	tl := e.tailer()
	seen := map[string]int{}
	polls := 0
	for ; polls < 200; polls++ {
		evs, _ := mustPoll(t, tl)
		if len(evs) == 0 {
			break
		}
		for _, p := range prompts(evs) {
			seen[p]++
		}
	}
	if polls < 3 {
		t.Errorf("budget was not applied: drained in %d polls", polls)
	}
	for _, w := range want {
		if seen[w] != 1 {
			t.Fatalf("prompt %q seen %d times", w, seen[w])
		}
	}
}

func TestTailContextCancelled(t *testing.T) {
	e := newEnv(t)
	writeFile(t, e.claude("s1"), lines(claudePrompt("s1", 0, "one")))
	tl := e.tailer()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	evs, probs, err := tl.Poll(ctx)
	if err != context.Canceled || len(evs) != 0 || len(probs) != 0 {
		t.Fatalf("cancelled poll: %v %v %v", evs, probs, err)
	}
	// Nothing was lost by the cancelled pass.
	if evs, _ := mustPoll(t, tl); len(evs) != 1 {
		t.Fatalf("got %d events after cancellation", len(evs))
	}
}

func TestTailConcurrentPolls(t *testing.T) {
	e := newEnv(t)
	path := e.claude("s1")
	writeFile(t, path, "")
	tl := e.tailer()
	var mu sync.Mutex
	seen := map[string]int{}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	for g := 0; g < 4; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				evs, _, _ := tl.Poll(context.Background())
				mu.Lock()
				for _, p := range prompts(evs) {
					seen[p]++
				}
				mu.Unlock()
				select {
				case <-stop:
					return
				default:
				}
			}
		}()
	}
	const n = 300
	for i := 0; i < n; i++ {
		appendFile(t, path, claudePrompt("s1", i, fmt.Sprintf("p%d", i))+"\n")
	}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		got := len(seen)
		mu.Unlock()
		if got == n {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	close(stop)
	wg.Wait()
	mustPoll(t, tl)
	if len(seen) != n {
		t.Fatalf("saw %d of %d prompts", len(seen), n)
	}
	for p, c := range seen {
		if c != 1 {
			t.Fatalf("prompt %s seen %d times", p, c)
		}
	}
}

func TestTailAllFormatsTogether(t *testing.T) {
	e := newEnv(t)
	files := map[string][]string{
		e.claude("5d1f26db"): claudeMain,
		filepath.Join(e.home, ".claude", "projects", "-work-repo", "5d1f26db", "subagents", "agent-a1.jsonl"):              claudeSub,
		filepath.Join(e.home, ".codex", "sessions", "2026", "11", "01", "rollout-2026-11-01T10-00-00-abc.jsonl"):           codexMain,
		filepath.Join(e.home, ".copilot", "session-state", "8f14e45f-ceea-4672-a1b2-0123456789ab", "events.jsonl"):         copilotMain,
		filepath.Join(e.home, ".gemini", "tmp", "repo", "chats", "session-2026-11-01T08-00-7b1c2d3e.jsonl"):                geminiMain,
		filepath.Join(e.home, ".gemini", "tmp", "repo", "chats", "7b1c2d3e-0000-4000-8000-000000000001", "sub-55aa.jsonl"): {`{"sessionId":"sub-55aa","startTime":"2026-11-01T08:01:00.000Z","kind":"subagent"}`},
		filepath.Join(e.home, ".claude", "projects", "-work-repo", "5d1f26db", "tool-results", "spill.jsonl"):              {`{"type":"user","message":{"content":"must not be read"}}`},
		filepath.Join(e.home, ".gemini", "tmp", "repo", "chats", "notes.jsonl"):                                            {`{"id":"x","type":"user","content":"must not be read"}`},
		filepath.Join(e.home, ".copilot", "session-state", "8f14e45f-ceea-4672-a1b2-0123456789ab", "workspace.yaml"):       {"cwd: /work"},
		filepath.Join(e.home, ".codex", "history.jsonl"):                                                                   {`{"text":"must not be read"}`},
	}
	for path, ls := range files {
		writeFile(t, path, lines(ls...))
	}
	tl := e.tailer()
	evs, probs := mustPoll(t, tl)
	if len(probs) != 0 {
		t.Fatalf("problems: %+v", probs)
	}
	byAgent := map[string]int{}
	for _, ev := range evs {
		byAgent[ev.Agent.ID]++
		if ev.Content != nil && strings.Contains(ev.Content.PromptText, "must not be read") {
			t.Fatalf("a non-log file was parsed: %s", ev.Session.Transcript)
		}
	}
	if byAgent["claude-code"] != 16+3 || byAgent["codex"] != 19 || byAgent["copilot-cli"] != 27 || byAgent["gemini-cli"] != 16+1 {
		t.Errorf("events per agent = %v", byAgent)
	}
	if n := len(tl.Checkpoints()); n != 6 {
		t.Errorf("followed files = %d", n)
	}
}

func TestReadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "projects", "p", "s.jsonl")
	writeFile(t, path, lines(claudeMain...)+`{"type":"user","message":{"content":"torn`)
	evs, st, err := ReadFile(path, nil, event.User{Name: "bob"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 16 || st.SessionID != "5d1f26db" || st.Malformed != 0 || evs[0].User.Name != "bob" {
		t.Errorf("events=%d state=%+v", len(evs), st)
	}
	if _, _, err := ReadFile(filepath.Join(dir, "nope.txt"), nil, event.User{}, 0); err == nil {
		t.Error("expected an error for a path no parser matches")
	}
	if _, _, err := ReadFile(filepath.Join(dir, "projects", "p", "missing.jsonl"), nil, event.User{}, 0); !os.IsNotExist(err) {
		t.Errorf("missing file: %v", err)
	}
}

func TestConfigRoots(t *testing.T) {
	dir := t.TempDir()
	// A relocated Claude config dir (CLAUDE_CONFIG_DIR) and Codex home.
	writeFile(t, filepath.Join(dir, "cc", "projects", "-p", "s.jsonl"), lines(claudePrompt("s", 0, "relocated")))
	writeFile(t, filepath.Join(dir, "cx", "sessions", "2026", "11", "01", "rollout-x.jsonl"), lines(codexMain[0], codexMain[4]))
	now := time.Now()
	tl := NewTailer(TailerOptions{FromStart: true, now: func() time.Time { return now }, Roots: func() []Root {
		return append(ConfigRoots("claude-code", filepath.Join(dir, "cc"), event.User{Name: "u"}),
			ConfigRoots(FormatCodex, filepath.Join(dir, "cx"), event.User{Name: "u"})...)
	}})
	evs, probs := mustPoll(t, tl)
	if len(evs) != 3 || len(probs) != 0 {
		t.Fatalf("events=%v problems=%+v", briefs(evs), probs)
	}
	if ConfigRoots("cursor", dir, event.User{}) != nil || ConfigRoots(FormatClaude, "", event.User{}) != nil || HomeRoots("", event.User{}) != nil {
		t.Error("unknown format or empty dir must yield no roots")
	}
	for _, r := range HomeRoots(filepath.Join(dir, "home"), event.User{Name: "u", ID: "1000"}) {
		if r.Parser == nil || r.User.ID != "1000" || !strings.HasPrefix(r.Glob, filepath.Join(dir, "home")) {
			t.Errorf("root = %+v", r)
		}
	}
}

// A record written and then taken back before its line was complete: the
// reader never parsed it, but the shrink is still reported.
func TestTailUnreadTailRemoved(t *testing.T) {
	e := newEnv(t)
	path := e.claude("s1")
	whole := lines(claudePrompt("s1", 0, "one"))
	writeFile(t, path, whole+claudePrompt("s1", 1, "a record that will vanish")[:60])
	tl := e.tailer()
	if evs, _ := mustPoll(t, tl); len(evs) != 1 {
		t.Fatalf("got %d events", len(evs))
	}
	if err := os.Truncate(path, int64(len(whole))); err != nil {
		t.Fatal(err)
	}
	evs, probs := mustPoll(t, tl)
	if len(evs) != 0 || len(probs) != 1 || probs[0].Kind != ProblemTruncated || !strings.Contains(probs[0].Detail, "shrank") {
		t.Fatalf("events=%d problems=%+v", len(evs), probs)
	}
	appendFile(t, path, claudePrompt("s1", 2, "two")+"\n")
	evs, probs = mustPoll(t, tl)
	if got := prompts(evs); strings.Join(got, ",") != "two" || len(probs) != 0 {
		t.Fatalf("after shrink: %v %+v", got, probs)
	}
}
