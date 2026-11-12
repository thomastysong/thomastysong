//go:build linux || darwin

package spool

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

func TestReaderRefusesLinksAndSpecialFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file types")
	}
	dir := privateDir(t)
	secret := filepath.Join(t.TempDir(), "shadow")
	os.WriteFile(secret, []byte(`{"v":1,"event":{"kind":"activity","type":"tool.pre","target":{"command":"SECRET-CONTENT"}}}`+"\n"), 0o600)
	if err := os.Symlink(secret, filepath.Join(dir, "activity-1.ndjson")); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(filepath.Join(dir, "activity-2.ndjson"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := NewReader(ReaderOptions{Roots: func() []Root { return []Root{myRoot(dir)} }})
	done := make(chan struct{})
	var evs []*event.Event
	var probs []Problem
	go func() {
		evs, probs, _ = r.Poll(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("reader blocked on a FIFO")
	}
	if len(evs) != 0 {
		t.Fatalf("read through a link or FIFO: %+v", evs[0].Target)
	}
	kinds := map[string]bool{}
	for _, p := range probs {
		kinds[p.Kind] = true
	}
	if !kinds["symlink_refused"] || !kinds["not_regular"] {
		t.Errorf("problems: %+v", probs)
	}
}

func TestReaderOwnerMismatch(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() != 0 {
		t.Skip("needs root to chown")
	}
	dir := privateDir(t)
	w, _ := OpenWriter(dir)
	w.Append(activity("id"))
	for _, f := range mustGlob(t, filepath.Join(dir, "*.ndjson")) {
		if err := os.Chown(f, 4242, 4242); err != nil {
			t.Fatal(err)
		}
	}
	r := NewReader(ReaderOptions{Roots: func() []Root { return []Root{myRoot(dir)} }})
	evs, probs, _ := r.Poll(context.Background())
	if len(evs) != 0 || len(probs) == 0 || probs[0].Kind != "owner_mismatch" {
		t.Fatalf("foreign-owned file accepted: %d events, %+v", len(evs), probs)
	}
}
