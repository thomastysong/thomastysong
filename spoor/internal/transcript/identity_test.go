package transcript

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/event"
)

// withLineKey simulates another process: a different line key for the
// rest of the test.
func withLineKey(t *testing.T, seed byte) {
	t.Helper()
	old := lineKey
	k := bytes.Repeat([]byte{seed}, 32)
	lineKey = func() []byte { return k }
	t.Cleanup(func() { lineKey = old })
}

func claudeUUIDPrompt(uuid, text string) string {
	return fmt.Sprintf(`{"type":"user","uuid":%q,"sessionId":"s-1","timestamp":"2026-11-01T10:00:00.000Z","message":{"role":"user","content":%q}}`, uuid, text)
}

func copilotPrompt(id, text string) string {
	return fmt.Sprintf(`{"id":%q,"parentId":null,"timestamp":"2026-11-01T09:00:05.000Z","type":"user.message","data":{"content":%q,"source":"user"}}`, id, text)
}

func geminiPrompt(id, text string) string {
	return fmt.Sprintf(`{"id":%q,"timestamp":"2026-11-01T08:00:05.000Z","type":"user","content":[{"text":%q}]}`, id, text)
}

func codexPrompt(text string) string {
	return fmt.Sprintf(`{"timestamp":"2026-11-01T10:00:00.400Z","type":"event_msg","payload":{"type":"user_message","message":%q,"images":[]}}`, text)
}

func codexHeader() string { return codexMain[0] }

// oneID parses lines with a fresh state and returns the id of the single
// event of type typ.
func oneID(t *testing.T, p Parser, path, typ string, lines ...string) string {
	t.Helper()
	evs, _ := parseLines(t, p, path, lines...)
	var ids []string
	for _, e := range evs {
		if e.Type == typ {
			ids = append(ids, e.ID)
		}
	}
	if len(ids) != 1 {
		t.Fatalf("%d %s events from %v", len(ids), typ, lines)
	}
	return ids[0]
}

// The id of an event comes from the log's record id, not from its text: two
// records with the same id and different prompts share it, and a different
// record id changes it.
func TestEventIDFromRecordIDNotContent(t *testing.T) {
	claude, _ := ForFormat(FormatClaude)
	copilot, _ := ForFormat(FormatCopilot)
	gemini, _ := ForFormat(FormatGemini)
	cases := []struct {
		name, path string
		p          Parser
		line       func(id, text string) string
		pre        []string
	}{
		{"claude", claudeMainPath, claude, claudeUUIDPrompt, nil},
		{"copilot", copilotPath, copilot, copilotPrompt, nil},
		{"gemini", geminiPath, gemini, geminiPrompt, []string{geminiMain[0]}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a := oneID(t, c.p, c.path, event.TypePromptSubmit, append(c.pre, c.line("4f1c0a9e-1111-4c4c-8888-000000000001", "deploy the payments service"))...)
			b := oneID(t, c.p, c.path, event.TypePromptSubmit, append(c.pre, c.line("4f1c0a9e-1111-4c4c-8888-000000000001", "something else entirely"))...)
			d := oneID(t, c.p, c.path, event.TypePromptSubmit, append(c.pre, c.line("4f1c0a9e-1111-4c4c-8888-000000000002", "deploy the payments service"))...)
			if a != b {
				t.Errorf("id depends on the prompt text: %s vs %s", a, b)
			}
			if a == d {
				t.Errorf("two record ids share an event id %s", a)
			}
			// Another process (another line key) derives the same id.
			withLineKey(t, 0x5a)
			if e := oneID(t, c.p, c.path, event.TypePromptSubmit, append(c.pre, c.line("4f1c0a9e-1111-4c4c-8888-000000000001", "deploy the payments service"))...); e != a {
				t.Errorf("record-id event id changed across processes: %s vs %s", a, e)
			}
		})
	}
}

// A record without an id (Codex) gets an id from a keyed digest of the
// line: deterministic within the process, different in another.
func TestEventIDLineDigestPerProcess(t *testing.T) {
	codex, _ := ForFormat(FormatCodex)
	line := codexPrompt("add a test for the parser")
	a := oneID(t, codex, codexPath, event.TypePromptSubmit, codexHeader(), line)
	b := oneID(t, codex, codexPath, event.TypePromptSubmit, codexHeader(), line)
	if a != b {
		t.Fatalf("same line, same process: %s vs %s", a, b)
	}
	if c := oneID(t, codex, codexPath, event.TypePromptSubmit, codexHeader(), codexPrompt("add a test for the lexer")); c == a {
		t.Error("two lines share an id")
	}
	withLineKey(t, 0x33)
	if c := oneID(t, codex, codexPath, event.TypePromptSubmit, codexHeader(), line); c == a {
		t.Error("line-digest id is the same under another process key")
	}
	// Tool events of a format without record ids too.
	x := oneID(t, codex, codexPath, event.TypeToolPre, codexHeader(), codexMain[6])
	if y := oneID(t, codex, codexPath, event.TypeToolPre, codexHeader(), codexMain[6]); x != y {
		t.Errorf("tool call id not stable within the process: %s vs %s", x, y)
	}
	withLineKey(t, 0x44)
	if y := oneID(t, codex, codexPath, event.TypeToolPre, codexHeader(), codexMain[6]); x == y {
		t.Error("line-digest tool id is the same under another process key")
	}
}

// A tool event is identified by its record, type and call id: the same
// call in two records (the same tool id reused in another file, say) does
// not share an id; pre and post differ; calls of one record differ.
func TestToolEventIDs(t *testing.T) {
	claude, _ := ForFormat(FormatClaude)
	call := func(uuid string) string {
		return fmt.Sprintf(`{"type":"assistant","uuid":%q,"sessionId":"s-1","timestamp":"2026-11-01T10:00:01.000Z","message":{"id":"m1","model":"claude-opus-5","content":[{"type":"tool_use","id":"toolu_77","name":"Bash","input":{"command":"ls"}}]}}`, uuid)
	}
	result := `{"type":"user","uuid":"r-1","sessionId":"s-1","timestamp":"2026-11-01T10:00:02.000Z","message":{"role":"user","content":[{"type":"tool_result","tool_use_id":"toolu_77","content":"a b"}]}}`
	a := oneID(t, claude, claudeMainPath, event.TypeToolPre, call("a-1"))
	if again := oneID(t, claude, claudeMainPath, event.TypeToolPre, call("a-1")); again != a {
		t.Errorf("same record read twice: %s vs %s", a, again)
	}
	if b := oneID(t, claude, claudeMainPath, event.TypeToolPre, call("a-2")); a == b {
		t.Errorf("one tool id in two records shares event id %s", a)
	}
	post := oneID(t, claude, claudeMainPath, event.TypeToolPost, call("a-1"), result)
	if post == a {
		t.Error("tool.pre and tool.post share an id")
	}
	two := `{"type":"assistant","uuid":"a-3","sessionId":"s-1","timestamp":"2026-11-01T10:00:01.000Z","message":{"id":"m1","content":[{"type":"tool_use","id":"toolu_1","name":"Bash","input":{"command":"ls"}},{"type":"tool_use","id":"toolu_2","name":"Bash","input":{"command":"pwd"}}]}}`
	evs, _ := parseLines(t, claude, claudeMainPath, two)
	if len(evs) != 2 || evs[0].ID == evs[1].ID {
		t.Errorf("two calls in one record: %d events, ids %v", len(evs), briefs(evs))
	}
	// Gemini: a call first recorded executing and completed by a $patch
	// keeps one tool.pre and gets one tool.post, identified by the message.
	gemini, _ := ForFormat(FormatGemini)
	gevs, _ := parseLines(t, gemini, geminiPath, geminiMain...)
	ids := map[string]bool{}
	for _, e := range gevs {
		if ids[e.ID] {
			t.Errorf("gemini: repeated id %s (%s)", e.ID, brief(e))
		}
		ids[e.ID] = true
	}
	withLineKey(t, 0x66)
	gevs2, _ := parseLines(t, gemini, geminiPath, geminiMain...)
	for i := range gevs {
		if gevs[i].ID != gevs2[i].ID {
			t.Errorf("gemini %s: id changed across processes", brief(gevs[i]))
		}
	}
}

// Several events of one identity and type in one line are numbered.
func TestEventIDsNumberedWithinRecord(t *testing.T) {
	c := &lineCtx{agent: "x", st: &FileState{Path: "p", SessionID: "s"}, line: []byte(`{"a":1}`)}
	c.record("u:", "rec-1")
	for i := 0; i < 3; i++ {
		c.newEvent(event.TypeConfigChange, time.Unix(1, 0))
	}
	c.record("", "")
	c.newEvent(event.TypeConfigChange, time.Unix(1, 0))
	c.newEvent(event.TypeConfigChange, time.Unix(1, 0))
	c.eventIDs()
	seen := map[string]bool{}
	for _, e := range c.out {
		if len(e.ID) != 36 || e.ID[14] != '7' || seen[e.ID] {
			t.Errorf("bad or repeated id %q", e.ID)
		}
		seen[e.ID] = true
	}
	// A hostile record id is clipped and never copied into the event.
	huge := strings.Repeat("Q", 1<<16)
	c2 := &lineCtx{agent: "x", st: &FileState{Path: "p"}, line: []byte(`{}`)}
	c2.record("u:", huge)
	if len(c2.rec) > maxIDLen+2 {
		t.Errorf("record id not clipped: %d bytes", len(c2.rec))
	}
	c2.newEvent(event.TypeTurnEnd, time.Time{})
	c2.eventIDs()
	if b, _ := c2.out[0].MarshalLine(); strings.Contains(string(b), "QQQQ") {
		t.Error("record id serialized")
	}
}

// ---- dictionary attack ----

// v1EventID is the derivation this package used before ids were keyed:
// SHA-256 of the line, then of (agent, line hash, index).
func v1EventID(agent string, line []byte, n int, t time.Time) string {
	lh := sha256.Sum256(line)
	h := sha256.New()
	h.Write([]byte("spoor/transcript/v1\x00"))
	h.Write([]byte(agent))
	h.Write([]byte{0})
	h.Write(lh[:])
	var idx [4]byte
	binary.BigEndian.PutUint32(idx[:], uint32(n))
	h.Write(idx[:])
	return uuidShape(t, h.Sum(nil))
}

func uuidShape(t time.Time, sum []byte) string {
	var b [16]byte
	binary.BigEndian.PutUint64(b[0:8], uint64(t.UnixMilli())<<16)
	copy(b[6:], sum[:10])
	b[6] = (b[6] & 0x0f) | 0x70
	b[8] = (b[8] & 0x3f) | 0x80
	x := hex.EncodeToString(b[:])
	return x[0:8] + "-" + x[8:12] + "-" + x[12:16] + "-" + x[16:20] + "-" + x[20:32]
}

// With the shipped event (time, agent, session, type) and the line format,
// recomputing an id over a dictionary of prompts never finds the prompt.
func TestEventIDDictionaryAttack(t *testing.T) {
	var dict []string
	for _, v := range []string{"fix", "test", "deploy", "review", "debug", "refactor", "document", "delete"} {
		for _, o := range []string{"the auth module", "the payments service", "the parser", "the build", "the README"} {
			for _, s := range []string{"", " please", " and run the tests", " now"} {
				dict = append(dict, v+" "+o+s)
			}
		}
	}
	real := dict[57]
	codex, _ := ForFormat(FormatCodex)
	claude, _ := ForFormat(FormatClaude)
	cases := []struct {
		name, path string
		p          Parser
		pre        []string
		line       func(string) string
	}{
		{"codex line digest", codexPath, codex, []string{codexHeader()}, codexPrompt},
		// The attacker is even given the record uuid here.
		{"claude record id", claudeMainPath, claude, nil, func(s string) string { return claudeUUIDPrompt("u-fixed", s) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			evs, _ := parseLines(t, c.p, c.path, append(c.pre, c.line(real))...)
			var e *event.Event
			for _, x := range evs {
				if x.Type == event.TypePromptSubmit {
					e = x
				}
			}
			if e == nil {
				t.Fatal("no prompt event")
			}
			if strings.Contains(wire(t, evs), real) {
				t.Fatal("prompt serialized: the attack is moot")
			}
			sess := e.Session.ID
			for _, cand := range dict {
				line := []byte(c.line(cand))
				for n := 0; n < 3; n++ {
					if v1EventID(c.p.AgentID(), line, n, e.TS.Time) == e.ID {
						t.Fatalf("prompt recovered with the unkeyed v1 derivation")
					}
				}
				lh := sha256.Sum256(line)
				unkeyed := "l:" + hex.EncodeToString(lh[:16])
				if eventID(e.TS.Time, c.p.AgentID(), sess, unkeyed, e.Type, "", 0) == e.ID {
					t.Fatalf("prompt recovered with an unkeyed line digest")
				}
			}
			if c.name == "codex line digest" {
				// Control: with the process key the same recomputation
				// finds it, so the negative above is meaningful.
				rec := "l:" + lineDigest(c.p.AgentID(), []byte(c.line(real)))
				if eventID(e.TS.Time, c.p.AgentID(), sess, rec, e.Type, "", 0) != e.ID {
					t.Fatal("control: keyed recomputation does not give the id; the attack model is wrong")
				}
			}
		})
	}
}

// ---- tool output ----

// No transcript event carries a digest of tool output, in any format; the
// length is kept.
func TestNoToolOutputDigest(t *testing.T) {
	type fixture struct {
		format, path string
		lines        []string
	}
	fixtures := []fixture{
		{FormatClaude, claudeMainPath, claudeMain},
		{FormatClaude, claudeSubPath, claudeSub},
		{FormatCodex, codexPath, codexMain},
		{FormatCopilot, copilotPath, copilotMain},
		{FormatGemini, geminiPath, geminiMain},
	}
	posts := 0
	for _, f := range fixtures {
		p, _ := ForFormat(f.format)
		evs, _ := parseLines(t, p, f.path, f.lines...)
		w := wire(t, evs)
		for _, e := range evs {
			if e.Tool == nil {
				continue
			}
			if e.Tool.OutputSHA256 != "" {
				t.Errorf("%s %s: output digest %q", f.format, e.Type, e.Tool.OutputSHA256)
			}
			if e.Content == nil || e.Content.ToolOutput == "" {
				continue
			}
			posts++
			if e.Tool.OutputLen != len(e.Content.ToolOutput) {
				t.Errorf("%s: output_len %d for %d bytes", f.format, e.Tool.OutputLen, len(e.Content.ToolOutput))
			}
			sum := sha256.Sum256([]byte(e.Content.ToolOutput))
			if strings.Contains(w, hex.EncodeToString(sum[:])[:16]) {
				t.Errorf("%s: a digest of tool output is serialized", f.format)
			}
		}
	}
	if posts < 10 {
		t.Errorf("only %d events with output: fixtures changed?", posts)
	}
}

// ---- checkpoints across processes ----

// A restarted daemon has another line key. Its checkpoints still verify
// (the tail fingerprint does not depend on the key): nothing is read twice
// and no file looks replaced. A batch that was read but not committed comes
// back with the same ids when the log gives record ids.
func TestTailCheckpointsSurviveAnotherProcessKey(t *testing.T) {
	e := newEnv(t)
	e.opts.DeferCommit = true
	path := e.claude("s-1")
	writeFile(t, path, lines(claudeUUIDPrompt("u-1", "one"), claudeUUIDPrompt("u-2", "two")))
	withLineKey(t, 0x01)
	tl := e.tailer()
	first, _ := mustPoll(t, tl)
	if len(first) != 2 {
		t.Fatalf("first poll: %v", briefs(first))
	}
	// Crash before Commit, restart in a new process.
	withLineKey(t, 0x02)
	tl = e.tailer()
	again, probs := mustPoll(t, tl)
	if len(probs) != 0 || !sameIDs(first, again) {
		t.Fatalf("uncommitted batch not replayed identically across processes: %v %v", briefs(again), probs)
	}
	if err := tl.Commit(); err != nil {
		t.Fatal(err)
	}
	// Restart after Commit, in a third process: resume at the checkpoint.
	withLineKey(t, 0x03)
	tl = e.tailer()
	if evs, probs := mustPoll(t, tl); len(evs) != 0 || len(probs) != 0 {
		t.Fatalf("committed lines read again or checkpoint refused: %v %+v", briefs(evs), probs)
	}
	appendFile(t, path, claudeUUIDPrompt("u-3", "three")+"\n")
	evs, probs := mustPoll(t, tl)
	if got := prompts(evs); strings.Join(got, ",") != "three" || len(probs) != 0 {
		t.Fatalf("after append: %v %+v", got, probs)
	}
	// The checkpoint store holds neither the prompts nor an event id.
	raw, err := os.ReadFile(e.state)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{"one", "two", "three", first[0].ID} {
		if strings.Contains(string(raw), `"`+s+`"`) {
			t.Errorf("checkpoint store holds %q", s)
		}
	}
}
