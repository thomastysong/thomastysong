package transcript

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// codexRollout writes the first records of the Codex fixture (session
// start, prompt, one call and its result: no record carries a log id) as a
// rollout under home and returns its path.
func codexRollout(t *testing.T, home string) string {
	t.Helper()
	path := filepath.Join(home, ".codex", "sessions", "2026", "11", "01", filepath.Base(codexPath))
	writeFile(t, path, lines(codexMain[:9]...))
	return path
}

// codexIDs polls the Codex rollouts under home with DeferCommit and never
// commits (the daemon dies before handing the events on), returning the
// event ids by "type/tool-call id".
func codexIDs(t *testing.T, home, state string, key []byte) (map[string]string, []Problem) {
	t.Helper()
	tl := NewTailer(TailerOptions{
		Roots:       func() []Root { return HomeRoots(home, event.User{Name: "alice"}) },
		StateFile:   state,
		FromStart:   true,
		DeferCommit: true,
		IdentityKey: key,
	})
	out := map[string]string{}
	var probs []Problem
	for i := 0; i < 4; i++ {
		evs, p := mustPoll(t, tl)
		probs = append(probs, p...)
		if len(evs) == 0 {
			break
		}
		for _, e := range evs {
			k := e.Type
			if e.Tool != nil {
				k += "/" + e.Tool.UseID
			}
			out[k] = e.ID
		}
	}
	return out, probs
}

// TestDeferCommitHelperProcess is the "restarted daemon": it only runs as a
// subprocess of TestDeferCommitSameIDsAfterRestart.
func TestDeferCommitHelperProcess(t *testing.T) {
	home := os.Getenv("HAWKBELL_TEST_LINEKEY_HOME")
	if home == "" {
		t.Skip("helper process")
	}
	ids, _ := codexIDs(t, home, os.Getenv("HAWKBELL_TEST_LINEKEY_STATE"), nil)
	var out []string
	for k, v := range ids {
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	os.Stdout.WriteString("IDS\n" + strings.Join(out, "\n") + "\nEND\n")
}

// DeferCommit promises that a crash between Poll and Commit re-reads the
// lines with the same event ids. A crash means a new process; Codex
// records carry no log id, so their ids come from the line key, which the
// tailer keeps beside its checkpoint store. The restarted daemon is a real
// second process here (the test binary run again).
func TestDeferCommitSameIDsAfterRestart(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	state := filepath.Join(dir, "state", "transcripts.json")
	codexRollout(t, home)

	first, probs := codexIDs(t, home, state, nil) // this process, never committed
	if len(first) < 4 || len(probs) != 0 {
		t.Fatalf("first run: %v %+v", first, probs)
	}

	cmd := exec.Command(os.Args[0], "-test.run=^TestDeferCommitHelperProcess$", "-test.count=1")
	cmd.Env = append(os.Environ(), "HAWKBELL_TEST_LINEKEY_HOME="+home, "HAWKBELL_TEST_LINEKEY_STATE="+state)
	b, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("helper: %v\n%s", err, b)
	}
	s := string(b)
	i, j := strings.Index(s, "IDS\n"), strings.Index(s, "\nEND")
	if i < 0 || j < i {
		t.Fatalf("helper output:\n%s", s)
	}
	second := map[string]string{}
	for _, l := range strings.Split(s[i+len("IDS\n"):j], "\n") {
		if k, v, ok := strings.Cut(l, "="); ok {
			second[k] = v
		}
	}
	changed := 0
	for k, v := range first {
		if second[k] != v {
			changed++
			t.Logf("%-28s first run %s, after restart %s", k, v, second[k])
		}
	}
	if changed > 0 || len(second) != len(first) {
		t.Errorf("%d of %d re-read events changed id after a restart (%d re-read); DeferCommit promises the same ids", changed, len(first), len(second))
	}
}

// The line key file: created once beside the checkpoint store, 0600, read
// back by every later tailer on that store; it is what keys the ids (the
// control recomputes an id with it), and it is not in the store.
func TestLineKeyFile(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home")
	state := filepath.Join(dir, "state", "transcripts.json")
	codexRollout(t, home)

	withLineKey(t, 0x11) // "process" one
	a, probs := codexIDs(t, home, state, nil)
	if len(probs) != 0 {
		t.Fatalf("problems: %+v", probs)
	}
	keyPath := state + KeyFileSuffix
	raw, err := os.ReadFile(keyPath)
	if err != nil {
		t.Fatalf("no key file: %v", err)
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil || len(key) != lineKeyLen {
		t.Fatalf("key file %q: %v", raw, err)
	}
	if runtime.GOOS != "windows" {
		if fi, _ := os.Stat(keyPath); fi.Mode().Perm() != 0o600 {
			t.Errorf("key file mode %04o", fi.Mode().Perm())
		}
	}
	entries, _ := os.ReadDir(filepath.Dir(keyPath))
	for _, en := range entries {
		if strings.Contains(en.Name(), ".tmp-") {
			t.Errorf("temporary file left behind: %s", en.Name())
		}
	}
	withLineKey(t, 0x22) // "process" two, same checkpoint store
	b, probs := codexIDs(t, home, state, nil)
	if len(probs) != 0 || len(a) != len(b) {
		t.Fatalf("second tailer: %v %+v", b, probs)
	}
	for k, v := range a {
		if b[k] != v {
			t.Errorf("%s: %s vs %s across processes on one store", k, v, b[k])
		}
	}
	if again, _ := os.ReadFile(keyPath); !bytes.Equal(again, raw) {
		t.Error("key file rewritten")
	}
	if st, _ := os.ReadFile(state); bytes.Contains(st, raw[:16]) {
		t.Error("checkpoint store holds the key")
	}

	// Control: the prompt id is the line digest under the stored key, and
	// no unkeyed digest of the line gives it.
	codex, _ := ForFormat(FormatCodex)
	var pr *event.Event
	var line string
	st := &FileState{Path: codexPath}
	for _, l := range codexMain[:9] {
		evs, _ := codex.ParseLine([]byte(l), st)
		for _, e := range evs {
			if e.Type == event.TypePromptSubmit {
				pr, line = e, l
			}
		}
	}
	if pr == nil {
		t.Fatal("fixture has no Codex prompt")
	}
	want := a[event.TypePromptSubmit]
	keyed := eventID(pr.TS.Time, codex.AgentID(), pr.Session.ID, "l:"+lineDigest(key, codex.AgentID(), []byte(line)), pr.Type, "", 0)
	if keyed != want {
		t.Errorf("control: the stored key does not reproduce the id (%s vs %s)", keyed, want)
	}
	sum := sha256.Sum256([]byte(line))
	if eventID(pr.TS.Time, codex.AgentID(), pr.Session.ID, "l:"+hex.EncodeToString(sum[:16]), pr.Type, "", 0) == want {
		t.Error("the id is an unkeyed digest of the line")
	}
}

// A key file that cannot be trusted is reported and left alone; the tailer
// keys with the per-process key, so nothing it emits can be tested against
// a key others can read.
func TestLineKeyFileUntrusted(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits and symlinks")
	}
	for _, tc := range []struct {
		name  string
		setup func(t *testing.T, keyPath string)
		want  string
	}{
		{"group readable", func(t *testing.T, p string) {
			writeFile(t, p, hex.EncodeToString(bytes.Repeat([]byte{7}, 32))+"\n")
			os.Chmod(p, 0o640)
		}, "chmod 600"},
		{"symlink", func(t *testing.T, p string) {
			target := filepath.Join(t.TempDir(), "k")
			os.WriteFile(target, []byte(hex.EncodeToString(bytes.Repeat([]byte{7}, 32))+"\n"), 0o600)
			if err := os.Symlink(target, p); err != nil {
				t.Fatal(err)
			}
		}, "symbolic link"},
		{"not hex", func(t *testing.T, p string) {
			writeFile(t, p, "not a key\n")
			os.Chmod(p, 0o600)
		}, "not hex"},
		{"short", func(t *testing.T, p string) {
			writeFile(t, p, "00ff\n")
			os.Chmod(p, 0o600)
		}, "required"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			home := filepath.Join(dir, "home")
			state := filepath.Join(dir, "state", "transcripts.json")
			codexRollout(t, home)
			keyPath := state + KeyFileSuffix
			if err := os.MkdirAll(filepath.Dir(keyPath), 0o700); err != nil {
				t.Fatal(err)
			}
			tc.setup(t, keyPath)
			before, _ := os.Lstat(keyPath)
			withLineKey(t, 0x33)
			ids, probs := codexIDs(t, home, state, nil)
			if len(probs) != 1 || probs[0].Kind != ProblemUnreadable || probs[0].Path != keyPath || !strings.Contains(probs[0].Detail, tc.want) {
				t.Errorf("problems: %+v", probs)
			}
			if after, _ := os.Lstat(keyPath); after == nil || !os.SameFile(before, after) {
				t.Error("an untrusted key file was replaced")
			}
			// The per-process key keyed them: a tailer without a store
			// (always the process key) agrees.
			noStore, _ := codexIDs(t, home, "", nil)
			if ids[event.TypePromptSubmit] != noStore[event.TypePromptSubmit] {
				t.Error("fallback is not the per-process key")
			}
		})
	}
}

// TailerOptions.IdentityKey: one key across stores (the daemon's identity
// key), no key file; another key, other ids; a short key is refused and
// reported, and the key file is used instead.
func TestTailerIdentityKey(t *testing.T) {
	k1 := bytes.Repeat([]byte{1}, 32)
	run := func(key []byte) (map[string]string, []Problem, string) {
		dir := t.TempDir()
		home := filepath.Join(dir, "home")
		state := filepath.Join(dir, "state", "transcripts.json")
		codexRollout(t, home)
		ids, probs := codexIDs(t, home, state, key)
		return ids, probs, state
	}
	a, pa, sa := run(k1)
	b, pb, _ := run(append([]byte(nil), k1...))
	if len(pa)+len(pb) != 0 || a[event.TypePromptSubmit] == "" || a[event.TypePromptSubmit] != b[event.TypePromptSubmit] || a["tool.pre/call_1"] != b["tool.pre/call_1"] {
		t.Errorf("one identity key, two stores: %v vs %v (%+v %+v)", a, b, pa, pb)
	}
	if _, err := os.Stat(sa + KeyFileSuffix); !os.IsNotExist(err) {
		t.Error("a key file was created although IdentityKey was given")
	}
	if c, _, _ := run(bytes.Repeat([]byte{2}, 32)); c[event.TypePromptSubmit] == a[event.TypePromptSubmit] {
		t.Error("two identity keys share an id")
	}
	// The line key is derived, not the identity key itself.
	if bytes.Equal(lineKeyFrom(k1), k1) {
		t.Error("identity key used as the line key")
	}
	_, ps, ss := run(make([]byte, minIdentityKeyLen-1))
	if len(ps) != 1 || ps[0].Kind != ProblemUnreadable || !strings.Contains(ps[0].Detail, "identity key") {
		t.Errorf("short key: %+v", ps)
	}
	if _, err := os.Stat(ss + KeyFileSuffix); err != nil {
		t.Errorf("short key: no key file fallback: %v", err)
	}
}
