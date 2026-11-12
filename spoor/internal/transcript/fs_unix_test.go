//go:build linux || darwin || freebsd || netbsd || openbsd || dragonfly

package transcript

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/event"
)

func TestTailRefusesSymlinks(t *testing.T) {
	e := newEnv(t)
	outside := filepath.Join(t.TempDir(), "outside")
	secret := filepath.Join(outside, "secret.jsonl")
	writeFile(t, secret, lines(claudePrompt("victim", 0, "contents of a file outside the tree")))
	writeFile(t, filepath.Join(outside, "proj", "inner.jsonl"), lines(claudePrompt("victim", 1, "reached through a directory link")))

	real := e.claude("real")
	writeFile(t, real, lines(claudePrompt("real", 0, "legit")))
	link := e.claude("link")
	if err := os.Symlink(secret, link); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	// A project directory that is a link to somewhere else.
	dirLink := filepath.Join(e.home, ".claude", "projects", "-linked-project")
	if err := os.Symlink(filepath.Join(outside, "proj"), dirLink); err != nil {
		t.Fatal(err)
	}

	tl := e.tailer()
	evs, probs := mustPoll(t, tl)
	if got := prompts(evs); strings.Join(got, ",") != "legit" {
		t.Fatalf("read through a symlink: %v", got)
	}
	if !hasProblem(probs, ProblemSymlinkRefused, link) {
		t.Errorf("file symlink not reported: %+v", probs)
	}
	if _, probs := mustPoll(t, tl); len(probs) != 0 {
		t.Errorf("standing problem repeated: %+v", probs)
	}

	// A followed log swapped for a symlink between polls.
	if err := os.Remove(real); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, real); err != nil {
		t.Fatal(err)
	}
	evs, probs = mustPoll(t, tl)
	if len(evs) != 0 || !hasProblem(probs, ProblemSymlinkRefused, real) {
		t.Fatalf("swap to symlink: events=%v problems=%+v", briefs(evs), probs)
	}
}

func TestOpenBeneathRefusesLinkedComponents(t *testing.T) {
	base := t.TempDir()
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "f.jsonl"), "x\n")
	writeFile(t, filepath.Join(base, "real", "f.jsonl"), "y\n")
	if err := os.Symlink(outside, filepath.Join(base, "linkdir")); err != nil {
		t.Skip(err)
	}
	if err := os.Symlink(filepath.Join(outside, "f.jsonl"), filepath.Join(base, "real", "link.jsonl")); err != nil {
		t.Fatal(err)
	}

	f, m, err := openBeneath(base, filepath.Join("real", "f.jsonl"))
	if err != nil || !m.regular || m.size != 2 || m.id == "" || m.owner != strconv.Itoa(os.Getuid()) {
		t.Fatalf("regular open: %v %+v", err, m)
	}
	f.Close()

	for _, rel := range []string{filepath.Join("linkdir", "f.jsonl"), filepath.Join("real", "link.jsonl")} {
		if f, _, err := openBeneath(base, rel); !errors.Is(err, errSymlink) {
			if f != nil {
				f.Close()
			}
			t.Errorf("openBeneath(%q) = %v; want symlink refusal", rel, err)
		}
	}
	if _, _, err := openBeneath(base, filepath.Join("real", "..", "..", "etc", "passwd")); err == nil {
		t.Error("path traversal was not refused")
	}
	if _, _, err := openBeneath(base, "real"); !errors.Is(err, errNotRegular) {
		t.Errorf("directory: %v", err)
	}
	if _, _, err := openBeneath(base, filepath.Join("real", "missing.jsonl")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}
}

// A FIFO planted at a transcript path must neither block the daemon nor be
// read. The test fails by timeout if open blocks.
func TestTailIgnoresFIFO(t *testing.T) {
	e := newEnv(t)
	writeFile(t, e.claude("real"), lines(claudePrompt("real", 0, "legit")))
	fifo := e.claude("fifo")
	if err := syscall.Mkfifo(fifo, 0o644); err != nil {
		t.Skip("mkfifo unavailable:", err)
	}
	done := make(chan struct{})
	var evs []*event.Event
	go func() {
		defer close(done)
		evs, _, _ = e.tailer().Poll(t.Context())
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Poll blocked on a FIFO")
	}
	if got := prompts(evs); strings.Join(got, ",") != "legit" {
		t.Fatalf("prompts = %v", got)
	}
	// Opened directly, it is refused as not regular, still without blocking.
	if _, _, err := openBeneath(filepath.Dir(fifo), filepath.Base(fifo)); !errors.Is(err, errNotRegular) {
		t.Errorf("fifo open: %v", err)
	}
}

func TestTailOwnerMismatchByUID(t *testing.T) {
	e := newEnv(t)
	path := e.claude("s1")
	writeFile(t, path, lines(claudePrompt("s1", 0, "x")))
	glob := filepath.Join(e.home, ".claude", "projects", "*", "*.jsonl")

	// The root says these logs belong to a different account.
	e.opts.Roots = func() []Root { return []Root{{Glob: glob, User: event.User{Name: "mallory", ID: "4294967"}}} }
	tl := e.tailer()
	evs, probs := mustPoll(t, tl)
	if len(evs) != 0 || !hasProblem(probs, ProblemOwnerMismatch, path) {
		t.Fatalf("foreign-owned file was read: %v %+v", briefs(evs), probs)
	}
	// With the real owner it is read, and the user id is stamped.
	me := strconv.Itoa(os.Getuid())
	e.opts.Roots = func() []Root { return []Root{{Glob: glob, User: event.User{Name: "me", ID: me}}} }
	tl = e.tailer()
	evs, probs = mustPoll(t, tl)
	if len(evs) != 1 || len(probs) != 0 || evs[0].User.ID != me {
		t.Fatalf("own file: %v %+v", briefs(evs), probs)
	}
}

func TestTailUnreadableFileIsReportedOnce(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root reads everything")
	}
	e := newEnv(t)
	path := e.claude("s1")
	writeFile(t, path, lines(claudePrompt("s1", 0, "x")))
	os.Chmod(path, 0)
	tl := e.tailer()
	_, probs := mustPoll(t, tl)
	if !hasProblem(probs, ProblemUnreadable, path) {
		t.Fatalf("problems = %+v", probs)
	}
	if _, probs := mustPoll(t, tl); len(probs) != 0 {
		t.Errorf("repeated: %+v", probs)
	}
	os.Chmod(path, 0o644)
	if evs, _ := mustPoll(t, tl); len(evs) != 1 {
		t.Errorf("not read after becoming readable")
	}
}

// With Root.Base set to the home directory, a ~/.claude that is itself a
// symlink (to another user's tree, say) is refused instead of followed.
func TestTailRootBaseRefusesLinkedConfigDir(t *testing.T) {
	dir := t.TempDir()
	home := filepath.Join(dir, "home", "mallory")
	victim := filepath.Join(dir, "home", "victim", ".claude")
	writeFile(t, filepath.Join(victim, "projects", "-p", "v.jsonl"), lines(claudePrompt("v", 0, "the victim's prompt")))
	if err := os.MkdirAll(home, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(victim, filepath.Join(home, ".claude")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	glob := filepath.Join(home, ".claude", "projects", "*", "*.jsonl")
	now := time.Now()
	opts := TailerOptions{FromStart: true, now: func() time.Time { return now }}

	// Without Base the fixed prefix is the operator's word and is followed.
	opts.Roots = func() []Root { return []Root{{Glob: glob}} }
	if evs, _ := mustPoll(t, NewTailer(opts)); len(evs) != 1 {
		t.Fatalf("baseline: %d events", len(evs))
	}
	// With Base it is refused, reported once, and nothing is read.
	opts.Roots = func() []Root { return []Root{{Glob: glob, Base: home}} }
	tl := NewTailer(opts)
	evs, probs := mustPoll(t, tl)
	if len(evs) != 0 || !hasProblem(probs, ProblemSymlinkRefused, filepath.Join(home, ".claude")) {
		t.Fatalf("linked config dir was followed: %v %+v", briefs(evs), probs)
	}
	if _, probs := mustPoll(t, tl); len(probs) != 0 {
		t.Errorf("repeated: %+v", probs)
	}
	// A real directory under the same Base works, and opens are walked
	// from Base so nothing in between can be swapped for a link.
	os.Remove(filepath.Join(home, ".claude"))
	real := filepath.Join(home, ".claude", "projects", "-p", "m.jsonl")
	writeFile(t, real, lines(claudePrompt("m", 0, "mine")))
	evs, probs = mustPoll(t, tl)
	if got := prompts(evs); strings.Join(got, ",") != "mine" || len(probs) != 0 {
		t.Fatalf("real dir under Base: %v %+v", got, probs)
	}
	os.Rename(filepath.Join(home, ".claude", "projects"), filepath.Join(home, ".claude", "projects.real"))
	os.Symlink(filepath.Join(victim, "projects"), filepath.Join(home, ".claude", "projects"))
	evs, probs = mustPoll(t, tl)
	if len(evs) != 0 || !hasProblem(probs, ProblemSymlinkRefused, "") {
		t.Fatalf("swap below Base: %v %+v", briefs(evs), probs)
	}
}
