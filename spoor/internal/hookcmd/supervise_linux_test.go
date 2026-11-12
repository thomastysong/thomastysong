//go:build linux

package hookcmd

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/hookio"
)

// runSupervisedAsync runs the supervisor in a goroutine (the worker is this
// test binary) and returns a channel with its result.
func runSupervisedAsync(t *testing.T, s *sandbox, agent string, stdin io.Reader) <-chan hookResult {
	t.Helper()
	t.Setenv(envRole, "hook")
	t.Setenv(envFault, "")
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	env := OSEnv()
	env.Exe = exe
	args := []string{"--agent", agent, "--config", s.cfg}
	done := make(chan hookResult, 1)
	go func() {
		var out, errb bytes.Buffer
		start := time.Now()
		code := Run(stdin, &out, &errb, args, env)
		done <- hookResult{stdout: out.Bytes(), stderr: errb.Bytes(), code: code, dur: time.Since(start)}
	}()
	return done
}

// holdLock takes an exclusive flock on path from this process, as another
// process of the user could (`flock <path> sleep inf`).
func holdLock(t *testing.T, path string) (unlock func()) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := unix.Flock(fd, unix.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	return func() { _ = unix.Flock(fd, unix.LOCK_UN); _ = unix.Close(fd) }
}

// Any process of the user can hold the spool's .lock, and spool.Append
// waits for it without a timeout. The supervisor answers anyway, inside its
// deadline plus a bounded health wait: a guard deny the worker already
// produced is forwarded, and observe mode returns at once with nothing.
// (Before the fix the supervisor blocked in its health append until the
// lock was released, so every hook waited for the agent's own timeout.)
func TestHeldSpoolLockDoesNotHangSupervisor(t *testing.T) {
	for _, c := range []struct {
		name, cfg, cmd string
		deadline       time.Duration
		want           func([]byte) bool
	}{
		{"observe", cfgObserve, "ls", observeDeadline, func(b []byte) bool { return len(b) == 0 }},
		{"guard-deny", cfgGuardCrash, "spoor-test-block now", time.Second, func(b []byte) bool { return replyCarries(b, hookio.ActionDeny) }},
		{"guard-allow", cfgGuardCrash, "ls -la", time.Second, func(b []byte) bool { return len(b) == 0 }},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := newSandbox(t, c.cfg)
			unlock := holdLock(t, filepath.Join(s.spool, ".lock"))
			done := runSupervisedAsync(t, s, "claude-code", bytes.NewReader(dialects[0].payload(c.cmd)))
			limit := (c.deadline + 250*time.Millisecond + healthWait + time.Second) * raceSlowdown
			var r hookResult
			select {
			case r = <-done:
			case <-time.After(limit):
				unlock()
				r = <-done
				healthPending.Wait()
				t.Fatalf("supervisor still running %v after start (hard deadline %v); it returned %v after start, once the lock was released, with reply %q", limit, c.deadline, r.dur, r.stdout)
			}
			unlock()
			// The abandoned health append finishes once the lock is free;
			// wait for it so it does not race the temp dir cleanup.
			healthPending.Wait()
			if r.code != 0 || !c.want(r.stdout) {
				t.Fatalf("exit %d reply %q", r.code, r.stdout)
			}
		})
	}
}

// The session-state lock is held by someone else: the guard still answers
// in time, saves its state without the lock, and says so.
func TestHeldStateLockSavesUnlocked(t *testing.T) {
	s := newSandbox(t, cfgGuard)
	unlock := holdLock(t, filepath.Join(s.spool, "state", stateLockName))
	defer unlock()
	d := dialects[0]
	r := s.supervised(t, d.agent, d.payload("spoor-test-arm"), "")
	if r.code != 0 || len(r.stdout) != 0 {
		t.Fatalf("arm: exit %d reply %q", r.code, r.stdout)
	}
	if a := lastActivity(t, s); a.Labels["hook_state"] != "unlocked" {
		t.Fatalf("labels %v", a.Labels)
	}
	r = s.supervised(t, d.agent, d.payload("spoor-test-armed"), "")
	if !replyCarries(r.stdout, hookio.ActionAsk) {
		t.Fatalf("state saved without the lock did not arm the guard rule: %q", r.stdout)
	}
	if hs := s.ofKind(t, event.KindHealth); len(hs) != 0 {
		t.Fatalf("health %v", healthReasons(hs))
	}
}

func TestTryLock(t *testing.T) {
	p := filepath.Join(t.TempDir(), "l")
	un, ok := tryLock(p, 0)
	if !ok {
		t.Fatal("free lock not taken")
	}
	start := time.Now()
	if _, ok := tryLock(p, 30*time.Millisecond); ok {
		t.Fatal("held lock taken twice")
	}
	if d := time.Since(start); d < 30*time.Millisecond || d > time.Second*raceSlowdown {
		t.Fatalf("waited %v for a held lock, want about 30ms", d)
	}
	un()
	un2, ok := tryLock(p, 0)
	if !ok {
		t.Fatal("released lock not taken")
	}
	un2()
	// A symlink or a FIFO at the lock path is refused, never followed or
	// waited on.
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(p, link); err != nil {
		t.Fatal(err)
	}
	if _, ok := tryLock(link, 0); ok {
		t.Fatal("lock through a symlink")
	}
	fifo := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok := tryLock(fifo, 0); ok {
		t.Fatal("lock on a FIFO")
	}
}
