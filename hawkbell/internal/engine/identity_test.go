package engine

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/config"
	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/toolmap"
)

// testKey returns a deterministic identity key distinct per seed.
func testKey(seed byte) []byte {
	return bytes.Repeat([]byte{seed}, IdentityKeyLen)
}

// keyedHarness is a standard-profile pipeline with the given identity key
// (nil: the per-process key, so the pipeline has no data directory to keep
// a key file in).
func keyedHarness(t *testing.T, key []byte) *harness {
	t.Helper()
	return newHarness(t, func(c *config.Config, o *Options) {
		c.Privacy.Profile = "standard"
		o.IdentityKey = key
		if key == nil {
			c.DataDir = ""
		}
	})
}

// shellNoID is a shell call from an agent that gives no tool-call id: its
// identity is the engine's content digest. InputSHA256 is set the way
// hookio and the transcript parsers set it.
func shellNoID(cmd string) evOpt {
	return func(e *event.Event) {
		in := map[string]any{"command": cmd}
		e.Tool = &event.Tool{Name: "Bash", Kind: event.ToolShell, InputSHA256: toolmap.InputHash(in)}
		e.Target = &event.Target{Command: cmd}
		e.Content = &event.Content{ToolInput: in}
	}
}

// idPair is the shipped identity of one record.
type idPair struct{ id, dedupe string }

func onlyOne(t *testing.T, h *harness, typ string) idPair {
	t.Helper()
	evs := h.out.ofType(typ)
	if len(evs) != 1 {
		t.Fatalf("%d %s records:\n%s", len(evs), typ, dump(h.out.all()))
	}
	return idPair{evs[0].ID, evs[0].Dedupe}
}

// (a) The same prompt from the hook and the transcript is still one
// activity record, with a keyed digest and with the per-process key.
func TestIdentityPromptPairsAcrossSurfaces(t *testing.T) {
	for _, tc := range []struct {
		name string
		key  []byte
	}{{"configured", testKey(7)}, {"per-process", nil}} {
		t.Run(tc.name, func(t *testing.T) {
			h := keyedHarness(t, tc.key)
			h.ingest(transcript(event.TypePromptSubmit, "pa", prompt("rotate the staging certificates")))
			h.advance(2 * time.Second)
			h.ingest(hook(event.TypePromptSubmit, "pa", prompt("rotate the staging certificates")))
			h.advance(HoldFor + time.Second)
			h.tick()
			ps := h.out.ofType(event.TypePromptSubmit)
			if len(ps) != 1 || ps[0].Source != event.SourceHook {
				t.Fatalf("prompts:\n%s", dump(ps))
			}
			if got := ps[0].Sources; len(got) != 2 || got[0] != event.SourceHook || got[1] != event.SourceTranscript {
				t.Errorf("sources = %v, want [hook transcript]", got)
			}
			if h.stats()["correlate.matched"] == 0 {
				t.Errorf("no correlation counted: %v", h.stats())
			}
			if ps[0].Prompt == nil || ps[0].Prompt.Text != "" || ps[0].Dedupe == "" {
				t.Errorf("shipped prompt = %+v dedupe %q", ps[0].Prompt, ps[0].Dedupe)
			}
		})
	}
}

// identityRun feeds a fixed sequence and returns the shipped identities of
// the prompt and of the id-less shell call (ingested twice, in two Ingest
// calls).
func identityRun(t *testing.T, key []byte) (pr, call idPair) {
	t.Helper()
	return identitySeq(t, keyedHarness(t, key))
}

// identitySeq is identityRun's sequence on a given pipeline.
func identitySeq(t *testing.T, h *harness) (pr, call idPair) {
	t.Helper()
	h.ingest(hook(event.TypePromptSubmit, "ib", prompt("deploy the payments service to staging")))
	h.ingest(hook(event.TypeToolPre, "ib", shellNoID("make deploy ENV=staging")))
	h.tick()
	h.advance(time.Second)
	h.ingest(hook(event.TypeToolPre, "ib", shellNoID("make deploy ENV=staging")))
	h.tick()
	pr = onlyOne(t, h, event.TypePromptSubmit)
	calls := h.out.ofType(event.TypeToolPre)
	if len(calls) != 2 {
		t.Fatalf("%d tool.pre records:\n%s", len(calls), dump(h.out.all()))
	}
	a, b := idPair{calls[0].ID, calls[0].Dedupe}, idPair{calls[1].ID, calls[1].Dedupe}
	if a != b {
		t.Errorf("the same record ingested twice in one pipeline got %v and %v", a, b)
	}
	if a.id == "" || a.dedupe == "" || pr.id == "" || pr.dedupe == "" {
		t.Fatalf("empty identity: prompt %v call %v", pr, a)
	}
	return pr, a
}

// (b) Identities are stable across Ingest calls and across pipelines that
// share a key; (c) two keys give different identities.
func TestIdentityStableAndKeyed(t *testing.T) {
	p1, c1 := identityRun(t, testKey(1))
	p2, c2 := identityRun(t, testKey(1))
	if p1 != p2 || c1 != c2 {
		t.Errorf("same key, two pipelines: prompt %v vs %v, call %v vs %v", p1, p2, c1, c2)
	}
	p3, c3 := identityRun(t, testKey(2))
	if p3.id == p1.id || p3.dedupe == p1.dedupe || c3.id == c1.id || c3.dedupe == c1.dedupe {
		t.Errorf("two keys share an identity: prompt %v vs %v, call %v vs %v", p1, p3, c1, c3)
	}
	// Without a key the process key is used: stable within the process,
	// and neither a configured key's identity nor a fixed one.
	p4, c4 := identityRun(t, nil)
	p5, c5 := identityRun(t, nil)
	if p4 != p5 || c4 != c5 {
		t.Errorf("per-process key not stable: prompt %v vs %v, call %v vs %v", p4, p5, c4, c5)
	}
	if p4 == p1 || p4 == p3 || c4 == c1 || c4 == c3 {
		t.Error("per-process identity equals a configured key's")
	}
}

func TestIdentityKeyOption(t *testing.T) {
	if _, err := New(Options{Outbox: &memSink{name: "o"}, Mode: ModeDetect, IdentityKey: make([]byte, MinIdentityKeyLen-1)}); err == nil ||
		!strings.Contains(err.Error(), "IdentityKey") {
		t.Errorf("short key accepted: %v", err)
	}
	// The pipeline keeps its own copy: changing the caller's slice later
	// cannot move identities.
	key := testKey(9)
	p, err := New(Options{Outbox: &memSink{name: "o"}, Mode: ModeDetect, IdentityKey: key})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	ev := hook(event.TypePromptSubmit, "k", prompt("x"))
	before := p.naturalKey(ev)
	key[0] ^= 0xff
	if after := p.naturalKey(ev); after != before {
		t.Error("identity follows the caller's slice")
	}
	if p.o.IdentityKey != nil {
		t.Error("Options copy still references the caller's key")
	}
	// The per-process key is one key, drawn once.
	if !bytes.Equal(processIdentityKey(), processIdentityKey()) || len(processIdentityKey()) != IdentityKeyLen {
		t.Error("per-process key is not stable")
	}
}

func TestNaturalKeys(t *testing.T) {
	p, err := New(Options{Outbox: &memSink{name: "o"}, Mode: ModeDetect, IdentityKey: testKey(3)})
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close()
	cases := []struct {
		name string
		ev   *event.Event
		want string // "" none; "keyed" a keyed prompt digest
	}{
		{"tool id kept", hook(event.TypeToolPre, "n", shell("toolu_9", "ls")), "tool:toolu_9"},
		{"tool post id kept", hook(event.TypeToolPost, "n", shell("toolu_9", "ls")), "tool:toolu_9"},
		{"tool without id", hook(event.TypeToolPre, "n", shell("", "ls")), ""},
		{"session start", hook(event.TypeSessionStart, "n"), "session"},
		{"session end without id", hook(event.TypeSessionEnd, ""), ""},
		{"prompt", hook(event.TypePromptSubmit, "n", prompt("hello")), "keyed"},
		{"empty prompt", hook(event.TypePromptSubmit, "n", prompt("")), ""},
		{"turn end", hook(event.TypeTurnEnd, "n"), ""},
	}
	for _, c := range cases {
		got := p.naturalKey(c.ev)
		if hasNaturalKey(c.ev) != (got != "") {
			t.Errorf("%s: hasNaturalKey disagrees with %q", c.name, got)
		}
		switch c.want {
		case "keyed":
			m := hmac.New(sha256.New, testKey(3))
			m.Write([]byte(domPrompt + "\x00hello"))
			if want := "prompt:" + hex.EncodeToString(m.Sum(nil)[:16]); got != want {
				t.Errorf("%s: %q, want %q", c.name, got, want)
			}
			sum := sha256.Sum256([]byte("hello"))
			if strings.Contains(got, hex.EncodeToString(sum[:8])) {
				t.Errorf("%s: unkeyed digest in %q", c.name, got)
			}
		default:
			if got != c.want {
				t.Errorf("%s: %q, want %q", c.name, got, c.want)
			}
		}
	}
	// The content digest is length-delimited: moving bytes between
	// adjacent fields gives another digest.
	a := hook(event.TypeToolPre, "n", func(e *event.Event) { e.Target = &event.Target{Command: "ab", Path: "c"} })
	b := hook(event.TypeToolPre, "n", func(e *event.Event) { e.Target = &event.Target{Command: "a", Path: "bc"} })
	if p.contentKey(a) == p.contentKey(b) {
		t.Error("content digest is ambiguous across fields")
	}
	q1 := hook(event.TypeToolPre, "n", func(e *event.Event) { e.Target = &event.Target{Query: "first query"} })
	q2 := hook(event.TypeToolPre, "n", func(e *event.Event) { e.Target = &event.Target{Query: "second query"} })
	if p.contentKey(q1) == p.contentKey(q2) {
		t.Error("the search query is not part of the content digest")
	}
}

// ---- (d) dictionary attack ----

// The attacker's tools: the unkeyed derivations this package used before
// identities were keyed, recomputed from what a shipped record shows.

func unkeyedPromptKey(text string) string {
	sum := sha256.Sum256([]byte(text))
	return "prompt:" + hex.EncodeToString(sum[:16])
}

func unkeyedContentKey(ev *event.Event) string {
	h := sha256.New()
	w := func(s string) {
		h.Write([]byte(s))
		h.Write([]byte{0})
	}
	host, user, agent, sess := idParts(ev)
	w(host)
	w(user)
	w(agent)
	w(sess)
	if t := ev.Tool; t != nil {
		w(t.Name)
		w(t.UseID)
		w(t.InputSHA256)
	}
	if t := ev.Target; t != nil {
		w(t.Command)
		w(t.Path)
		w(t.URL)
	}
	if c := ev.Content; c != nil {
		w(c.PromptText)
	}
	return hex.EncodeToString(h.Sum(nil)[:16])
}

// promptDictionary is 1,600 plausible prompts, the size of the dictionary
// the privacy red team recovered prompts with.
func promptDictionary() []string {
	verbs := []string{"fix", "refactor", "test", "deploy", "review", "document", "debug", "optimize",
		"migrate", "rename", "delete", "explain", "rewrite", "profile", "lint", "build", "upgrade", "revert", "audit", "port"}
	objects := []string{"the auth module", "the payments service", "the login page", "the build", "the parser",
		"the database schema", "the CI pipeline", "the README", "the API client", "the cache layer",
		"the failing tests", "the Dockerfile", "the config loader", "the billing job", "the search index",
		"the user model", "the rate limiter", "the websocket server", "the cron jobs", "the release script"}
	tails := []string{"", " please", " and run the tests", " for staging"}
	var out []string
	for _, v := range verbs {
		for _, o := range objects {
			for _, t := range tails {
				out = append(out, v+" "+o+t)
			}
		}
	}
	return out
}

func TestIdentityDictionaryAttackOnPrompts(t *testing.T) {
	dict := promptDictionary()
	if len(dict) != 1600 {
		t.Fatalf("dictionary has %d entries", len(dict))
	}
	// Six real prompts, all in the attacker's dictionary.
	secret := []string{dict[3], dict[250], dict[611], dict[902], dict[1333], dict[1599]}
	for _, tc := range []struct {
		name string
		key  []byte
	}{{"configured", testKey(5)}, {"per-process", nil}} {
		t.Run(tc.name, func(t *testing.T) {
			h := keyedHarness(t, tc.key)
			t0 := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
			for i, s := range secret {
				h.ingest(hook(event.TypePromptSubmit, "dict", at(t0.Add(time.Duration(i)*time.Minute)), prompt(s)))
			}
			h.tick()
			shipped := h.out.ofType(event.TypePromptSubmit)
			if len(shipped) != len(secret) {
				t.Fatalf("%d prompts shipped", len(shipped))
			}
			raw := string(h.out.raw())
			for _, s := range secret {
				if strings.Contains(raw, s) {
					t.Fatalf("prompt text shipped: the attack is moot")
				}
			}
			recovered, controls := 0, 0
			for i, e := range shipped {
				host, user, agent, sess := idParts(e)
				guess := func(nat string) bool {
					for n := 0; n < 4; n++ {
						if event.DedupeKey(host, user, agent, sess, nat+"#"+strconv.Itoa(n), e.Type) == e.Dedupe {
							return true
						}
					}
					return event.StableID(e.TS.Time, "hawkbell/engine", string(e.Source), event.DedupeKey(host, user, agent, sess, nat, e.Type)) == e.ID
				}
				for _, cand := range dict {
					if guess(unkeyedPromptKey(cand)) {
						recovered++
						t.Errorf("prompt %d recovered from its shipped identity", i)
						break
					}
					// A key the attacker might try: none at all.
					m := hmac.New(sha256.New, nil)
					m.Write([]byte(domPrompt + "\x00" + cand))
					if guess("prompt:" + hex.EncodeToString(m.Sum(nil)[:16])) {
						recovered++
						t.Errorf("prompt %d recovered with an empty HMAC key", i)
						break
					}
				}
				// Control: the same recomputation with the pipeline's key
				// finds the prompt, so the negative above is meaningful.
				m := hmac.New(sha256.New, h.p.idKey)
				m.Write([]byte(domPrompt + "\x00" + secret[i]))
				if guess("prompt:" + hex.EncodeToString(m.Sum(nil)[:16])) {
					controls++
				}
			}
			if recovered != 0 {
				t.Errorf("recovered %d of %d prompts", recovered, len(secret))
			}
			if controls != len(secret) {
				t.Errorf("with the key the recomputation matched %d of %d: the attack model is wrong", controls, len(secret))
			}
		})
	}
}

func TestIdentityDictionaryAttackOnRedactedSecret(t *testing.T) {
	// Candidate secrets, built at run time; the real one is among them.
	var cands []string
	for i := 0; i < 400; i++ {
		cands = append(cands, "Canary"+"Pw"+fmt.Sprintf("%03d", i))
	}
	real := cands[217]
	cmdOf := func(s string) string { return "mysql -u root -p" + s + " -h db.internal prod" }
	h := keyedHarness(t, testKey(6))
	h.ingest(hook(event.TypeToolPre, "sec", shellNoID(cmdOf(real))))
	h.tick()
	calls := h.out.ofType(event.TypeToolPre)
	if len(calls) != 1 {
		t.Fatalf("%d calls:\n%s", len(calls), dump(h.out.all()))
	}
	e := calls[0]
	if strings.Contains(string(h.out.raw()), real) {
		t.Fatal("the secret was shipped: the attack is moot")
	}
	if e.Target == nil || e.Target.Command == "" || e.Tool == nil {
		t.Fatalf("shipped call lacks its redacted command: %+v", e)
	}
	// Rebuild the record as the engine saw it, from what was shipped and a
	// guess at the secret.
	rebuild := func(s string) *event.Event {
		cmd := cmdOf(s)
		in := map[string]any{"command": cmd}
		return &event.Event{
			Type: e.Type, Source: e.Source, TS: e.TS,
			Host: e.Host, User: e.User, Agent: e.Agent, Session: &event.Session{ID: e.Session.ID},
			Tool:    &event.Tool{Name: e.Tool.Name, UseID: e.Tool.UseID, InputSHA256: toolmap.InputHash(in)},
			Target:  &event.Target{Command: cmd},
			Content: &event.Content{ToolInput: in},
		}
	}
	idOf := func(ck string) string {
		return event.StableID(e.TS.Time, "hawkbell/engine", string(e.Source), e.Type, ck)
	}
	for _, s := range cands {
		if idOf(unkeyedContentKey(rebuild(s))) == e.ID {
			t.Fatalf("redacted secret recovered from the shipped id")
		}
	}
	// Control: with the key, the rebuilt record of the real secret gives
	// the shipped id and Dedupe.
	ev := rebuild(real)
	if idOf(h.p.contentKey(ev)) != e.ID {
		t.Fatal("control: keyed recomputation does not give the shipped id; the attack model is wrong")
	}
	host, user, agent, sess := idParts(e)
	if event.DedupeKey(host, user, agent, sess, "id:"+e.ID, e.Type) != e.Dedupe {
		t.Error("control: Dedupe is not derived from the id")
	}
}

// ---- the identity key file ----

func TestLoadOrCreateIdentityKey(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "checkpoints", IdentityKeyFile)
	k1, err := LoadOrCreateIdentityKey(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(k1) != IdentityKeyLen {
		t.Fatalf("key is %d bytes", len(k1))
	}
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != hex.EncodeToString(k1)+"\n" {
		t.Errorf("file holds %q", b)
	}
	if runtime.GOOS != "windows" {
		fi, _ := os.Stat(path)
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("key file mode %04o", fi.Mode().Perm())
		}
		di, _ := os.Stat(filepath.Dir(path))
		if di.Mode().Perm() != 0o700 {
			t.Errorf("key dir mode %04o", di.Mode().Perm())
		}
	}
	k2, err := LoadOrCreateIdentityKey(path)
	if err != nil || !bytes.Equal(k1, k2) {
		t.Fatalf("second load: %v, same=%v", err, bytes.Equal(k1, k2))
	}
	entries, _ := os.ReadDir(filepath.Dir(path))
	if len(entries) != 1 {
		t.Errorf("temporary files left behind: %v", entries)
	}
	// Two pipelines on the stored key derive the same identities.
	p1, _ := identityRun(t, k1)
	p2, _ := identityRun(t, k2)
	if p1 != p2 {
		t.Error("stored key does not give stable identities")
	}
	cfg := config.Default(dir)
	if got, want := IdentityKeyPath(cfg), filepath.Join(dir, "checkpoints", IdentityKeyFile); got != want {
		t.Errorf("IdentityKeyPath = %q, want %q", got, want)
	}
	if IdentityKeyPath(&config.Config{}) != "" || IdentityKeyPath(nil) != "" {
		t.Error("IdentityKeyPath without a data dir")
	}
	if _, err := LoadOrCreateIdentityKey(""); err == nil {
		t.Error("empty path accepted")
	}
}

func TestLoadOrCreateIdentityKeyConcurrent(t *testing.T) {
	path := filepath.Join(t.TempDir(), IdentityKeyFile)
	const n = 12
	keys := make([][]byte, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			keys[i], errs[i] = LoadOrCreateIdentityKey(path)
		}(i)
	}
	wg.Wait()
	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("creator %d: %v", i, errs[i])
		}
		if !bytes.Equal(keys[i], keys[0]) {
			t.Fatalf("creators disagree on the key")
		}
	}
}

func TestReadIdentityKeyRefuses(t *testing.T) {
	dir := t.TempDir()
	write := func(name, content string, mode os.FileMode) string {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, []byte(content), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(p, mode); err != nil {
			t.Fatal(err)
		}
		return p
	}
	good := hex.EncodeToString(testKey(4))
	cases := []struct {
		name, path, want string
	}{
		{"not hex", write("nothex", "zz-not-a-key\n", 0o600), "not hex"},
		{"too short", write("short", hex.EncodeToString(make([]byte, MinIdentityKeyLen-1)), 0o600), "required"},
		{"empty", write("empty", "", 0o600), "required"},
		{"too large", write("large", strings.Repeat("a", maxIdentityKeyFile+2), 0o600), "larger"},
		{"directory", filepath.Join(dir, "adir"), "regular"},
	}
	if err := os.Mkdir(filepath.Join(dir, "adir"), 0o700); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		cases = append(cases, struct{ name, path, want string }{"group readable", write("open", good, 0o640), "chmod 600"})
		target := write("target", good, 0o600)
		link := filepath.Join(dir, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
		cases = append(cases, struct{ name, path, want string }{"symlink", link, ""})
	}
	for _, c := range cases {
		if c.name == "directory" && runtime.GOOS == "windows" {
			continue
		}
		_, err := ReadIdentityKey(c.path)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err = %v, want %q", c.name, err, c.want)
		}
		// LoadOrCreate never replaces a file it cannot trust.
		if _, err := LoadOrCreateIdentityKey(c.path); err == nil {
			t.Errorf("%s: LoadOrCreate accepted it", c.name)
		}
	}
	if k, err := ReadIdentityKey(write("ok", "  "+good+"\r\n", 0o600)); err != nil || !bytes.Equal(k, testKey(4)) {
		t.Errorf("valid key: %v", err)
	}
	if _, err := ReadIdentityKey(filepath.Join(dir, "missing")); err == nil || !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}
}

// ---- the daemon's key file (the pipeline loads it itself) ----

// daemonHarness is a standard-profile daemon over dir with no
// Options.IdentityKey, as the daemon builds it.
func daemonHarness(t *testing.T, dir string) *harness {
	t.Helper()
	return newHarness(t, func(c *config.Config, o *Options) {
		c.Privacy.Profile = "standard"
		c.DataDir = dir
	})
}

// A daemon restart over the same data directory keeps every identity: a
// hook prompt redelivered from the spool after a restart, or a transcript
// line re-read after a crash, ships under the Dedupe and ID of its first
// copy, so downstream collapses them.
func TestDaemonIdentityKeyHoldsAcrossRestarts(t *testing.T) {
	dir := t.TempDir()
	h1 := daemonHarness(t, dir)
	p1, c1 := identitySeq(t, h1)
	if err := h1.p.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "checkpoints", IdentityKeyFile)
	stored, err := ReadIdentityKey(path)
	if err != nil {
		t.Fatalf("the daemon kept no key: %v", err)
	}
	if st := h1.stats(); st["identity.key_stored"] != 1 || st["identity.key_errors"] != 0 {
		t.Errorf("heartbeat key status: stored %d errors %d", st["identity.key_stored"], st["identity.key_errors"])
	}
	h2 := daemonHarness(t, dir) // the restarted daemon
	p2, c2 := identitySeq(t, h2)
	if p1 != p2 || c1 != c2 {
		t.Errorf("restart moved identities: prompt %v -> %v, call %v -> %v", p1, p2, c1, c2)
	}
	// It is the stored key that holds them, not a constant: a configured
	// key equal to it gives the same identities, another data directory
	// (another key) different ones.
	if p3, c3 := identityRun(t, stored); p3 != p1 || c3 != c1 {
		t.Errorf("stored key as Options.IdentityKey: prompt %v vs %v, call %v vs %v", p3, p1, c3, c1)
	}
	if p4, c4 := identitySeq(t, daemonHarness(t, t.TempDir())); p4.dedupe == p1.dedupe || c4.id == c1.id {
		t.Error("two data directories share an identity key")
	}
	// A configured key wins over the file.
	if p5, _ := identitySeq(t, newHarness(t, func(c *config.Config, o *Options) {
		c.Privacy.Profile = "standard"
		c.DataDir = dir
		o.IdentityKey = testKey(1)
	})); p5 == p1 {
		t.Error("Options.IdentityKey ignored in favour of the key file")
	}
}

// A key file the daemon cannot trust is neither used nor replaced: the
// pipeline runs on the per-process key and says so in the heartbeat.
func TestDaemonIdentityKeyFileUntrusted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "checkpoints", IdentityKeyFile)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	content := hex.EncodeToString(testKey(3)) + "\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	os.Chmod(path, 0o644)
	h := daemonHarness(t, dir)
	pr, _ := identitySeq(t, h)
	st := h.stats()
	if st["identity.key_errors"] != 1 || st["identity.key_stored"] != 0 {
		t.Errorf("untrusted key file not reported: errors %d stored %d", st["identity.key_errors"], st["identity.key_stored"])
	}
	if b, _ := os.ReadFile(path); string(b) != content {
		t.Error("an untrusted key file was replaced")
	}
	if p3, _ := identityRun(t, testKey(3)); p3 == pr {
		t.Error("the world-readable key was used")
	}
	if pp, _ := identityRun(t, nil); pp != pr {
		t.Error("fallback is not the per-process key")
	}
}

// ---- the first-seen baseline file ----

// The baseline file records which account contacted which egress host. A
// reader of the file alone (a backup, a support copy) with a host list and
// the host's account names must not recover that history: every stored key
// is an HMAC under the identity key. The control recomputes the stored
// keys with the identity key, so the dictionary below would find the host
// if the digests were unkeyed.
func TestBaselineDigestsAreKeyed(t *testing.T) {
	key := testKey(9)
	h := newHarness(t, func(c *config.Config, o *Options) {
		c.Privacy.Profile = "standard"
		o.IdentityKey = key
	})
	secretHost := "payroll-export.internal.example"
	h.ingest(hook(event.TypeToolPre, "bl", web("t1", "https://"+secretHost+"/q?id=7")))
	h.tick()
	if err := h.p.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	b, err := os.ReadFile(filepath.Join(h.cfg.CheckDir(), BaselineFile))
	if err != nil {
		t.Fatalf("baseline not written: %v", err)
	}
	if strings.Contains(string(b), secretHost) {
		t.Fatal("host stored in clear")
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	stored := map[string]bool{}
	for _, l := range lines[1:] {
		stored[l] = true
	}
	if len(stored) < 2 {
		t.Fatalf("expected the first-seen and the novelty key, file:\n%s", b)
	}
	if strings.Contains(lines[0], hex.EncodeToString(key)) {
		t.Fatal("the key is in the header")
	}
	unkeyed := func(s string) string { // the version 1 form
		sum := sha256.Sum256([]byte(s))
		return hex.EncodeToString(sum[:12])
	}
	withKey, _ := OpenBaseline("", 0, key)
	dict := []string{"github.com", "pypi.org", "registry.npmjs.org", "api.openai.com", "pastebin.com", secretHost, "example.com"}
	var recovered, control []string
	for _, acct := range []string{"root", "dev", "1001", "eve", "1002"} {
		for _, host := range dict {
			forms := []string{
				"hawkbell/first_seen\x00net.host\x00" + acct + "\x00" + host, // engine first-seen feature
				event.DedupeKey("HB-T-006", acct, host),                      // rules novelty block
			}
			for _, f := range forms {
				if stored[unkeyed(f)] || stored[f] {
					recovered = append(recovered, acct+" -> "+host)
				}
				if stored[withKey.digest(f)] {
					control = append(control, acct+" -> "+host)
				}
			}
		}
	}
	if len(recovered) > 0 {
		t.Errorf("baseline (%d keys) gives up egress history to a dictionary: %v", len(stored), recovered)
	}
	if len(control) != 2 || control[0] != "dev -> "+secretHost {
		t.Errorf("control: with the identity key the dictionary finds %v, want the host twice (first-seen and novelty keys)", control)
	}
}

// A baseline in the old unkeyed format is discarded on start (counted) and
// overwritten at the first tick, so the unkeyed digests do not stay on disk
// after an upgrade; a baseline written under another key is treated alike.
func TestBaselineLegacyFileOverwritten(t *testing.T) {
	for _, tc := range []struct{ name, content string }{
		{"v1-unkeyed", "hawkbell-baseline 1\n" + hex.EncodeToString(make([]byte, 12)) + "\n"},
		{"other-key", "hawkbell-baseline 2 0123456789abcdef\n" + hex.EncodeToString(make([]byte, 12)) + "\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "checkpoints", BaselineFile)
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(tc.content), 0o600); err != nil {
				t.Fatal(err)
			}
			h := daemonHarness(t, dir)
			if h.stats()["baseline.errors"] != 1 {
				t.Errorf("stale baseline not reported: %v", h.stats()["baseline.errors"])
			}
			h.tick() // nothing new was seen: the file is replaced anyway
			b, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(b), hex.EncodeToString(make([]byte, 12))) || !strings.HasPrefix(string(b), "hawkbell-baseline 2 ") {
				t.Errorf("stale baseline still on disk after the first tick: %q", b)
			}
		})
	}
}
