//go:build unix

package daemon

import (
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"

	"github.com/thomastysong/thomastysong/hawkbell/internal/config"
	"github.com/thomastysong/thomastysong/hawkbell/internal/platform"
)

func quietLog() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func TestPrepareLayoutModes(t *testing.T) {
	data := filepath.Join(t.TempDir(), "data")
	cfg := config.Default(data)
	priv := os.Geteuid() == 0
	l, err := prepareLayout(cfg, priv, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		l.data: "0711", l.outbox: "2750", l.local: "0700", l.check: "0700", l.spool: "0711", l.bundle: "0755",
	}
	for p, m := range want {
		fi, err := os.Lstat(p)
		if err != nil {
			t.Fatal(err)
		}
		if got := modeString(fi.Mode()); got != m {
			t.Errorf("%s: %s, want %s", p, got, m)
		}
	}
	// Repair: modes widened or narrowed by hand come back; a segment file
	// with the wrong mode is fixed.
	os.Chmod(l.outbox, 0o777)
	os.Chmod(l.bundle, 0o700)
	os.Chmod(l.data, 0o777)
	seg := filepath.Join(l.outbox, "detection-20261112-05-0000.ndjson")
	os.WriteFile(seg, []byte("{}\n"), 0o666)
	os.Chmod(seg, 0o666)
	if _, err := prepareLayout(cfg, priv, quietLog()); err != nil {
		t.Fatal(err)
	}
	for p, m := range map[string]string{l.outbox: "2750", l.bundle: "0755", l.data: "0755"} {
		fi, _ := os.Lstat(p)
		if got := modeString(fi.Mode()); got != m {
			t.Errorf("after repair %s: %s, want %s", p, got, m)
		}
	}
	if fi, _ := os.Lstat(seg); fi.Mode().Perm() != 0o640 {
		t.Errorf("segment mode %04o", fi.Mode().Perm())
	}
}

func TestPrepareLayoutRefusesLinks(t *testing.T) {
	data := filepath.Join(t.TempDir(), "data")
	cfg := config.Default(data)
	mustMkdir(t, data, 0o711)
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, cfg.OutboxDir()); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareLayout(cfg, os.Geteuid() == 0, quietLog()); err == nil {
		t.Fatal("a symlinked outbox was accepted")
	}
	// A data directory that is a link (a deliberate relocation) is followed.
	target := filepath.Join(t.TempDir(), "real")
	mustMkdir(t, target, 0o755)
	link := filepath.Join(t.TempDir(), "data-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := prepareLayout(config.Default(link), os.Geteuid() == 0, quietLog()); err != nil {
		t.Fatalf("relocated data directory: %v", err)
	}
	// ... unless its target is writable by others.
	os.Chmod(target, 0o777)
	if os.Geteuid() == 0 {
		if _, err := prepareLayout(config.Default(link), true, quietLog()); err == nil {
			t.Error("a world-writable link target was accepted")
		}
	}
}

func TestEnsureUserSpool(t *testing.T) {
	data := filepath.Join(t.TempDir(), "data")
	l, err := prepareLayout(config.Default(data), os.Geteuid() == 0, quietLog())
	if err != nil {
		t.Fatal(err)
	}
	me := platform.UserHome{Name: "me", UID: currentUID(), Home: t.TempDir()}
	if err := ensureUserSpool(l, me, os.Geteuid() == 0); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(l.spool, me.UID)
	fi, err := os.Lstat(dir)
	if err != nil || modeString(fi.Mode()) != "0700" {
		t.Fatalf("spool dir: %v %v", fi, err)
	}
	if st := fi.Sys().(*syscall.Stat_t); strconv.Itoa(int(st.Uid)) != me.UID {
		t.Errorf("owner %d", st.Uid)
	}
	// A loosened mode is repaired.
	os.Chmod(dir, 0o777)
	if err := ensureUserSpool(l, me, os.Geteuid() == 0); err != nil {
		t.Fatal(err)
	}
	if fi, _ := os.Lstat(dir); modeString(fi.Mode()) != "0700" {
		t.Errorf("not repaired: %s", modeString(fi.Mode()))
	}
	// Ids that would make a bad path component get nothing.
	for _, bad := range []string{"..", "../0", "", "a b"} {
		if err := ensureUserSpool(l, platform.UserHome{UID: bad}, true); err == nil {
			t.Errorf("uid %q accepted", bad)
		}
	}
	if os.Geteuid() == 0 {
		other := platform.UserHome{Name: "other", UID: "4242", Home: "/nonexistent"}
		if err := ensureUserSpool(l, other, true); err != nil {
			t.Fatal(err)
		}
		fi, _ := os.Lstat(filepath.Join(l.spool, "4242"))
		if st := fi.Sys().(*syscall.Stat_t); st.Uid != 4242 || fi.Mode().Perm() != 0o700 {
			t.Errorf("other account's spool: uid %d mode %04o", st.Uid, fi.Mode().Perm())
		}
	} else if err := ensureUserSpool(l, platform.UserHome{UID: "4242"}, false); err != nil {
		t.Errorf("unprivileged: another account's spool must be skipped, got %v", err)
	}
}
