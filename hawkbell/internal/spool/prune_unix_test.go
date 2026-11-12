//go:build linux || darwin

package spool

import (
	"os"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// lsetAge sets the times of a link itself, not of its target.
func lsetAge(t *testing.T, path string, age time.Duration) {
	t.Helper()
	tv := unix.NsecToTimeval(time.Now().Add(-age).UnixNano())
	if err := unix.Lutimes(path, []unix.Timeval{tv, tv}); err != nil {
		t.Fatal(err)
	}
}

// Links are never followed and never deleted, whether they name a record
// file, the state directory or the spool directory itself; FIFOs are left
// alone and do not block the scan.
func TestPruneNeverFollowsLinks(t *testing.T) {
	dir := privateDir(t)
	outside := t.TempDir()
	target := filepath.Join(outside, "victim.ndjson")
	writeAged(t, target, old)
	link := filepath.Join(dir, "activity-20261101.ndjson")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	lsetAge(t, link, old)
	// "state" as a link to a directory of expired session state elsewhere.
	otherState := filepath.Join(outside, "state")
	victimState := filepath.Join(otherState, "0123456789abcdef0123456789abcdef.json")
	writeAged(t, victimState, old)
	if err := os.Symlink(otherState, filepath.Join(dir, "state")); err != nil {
		t.Fatal(err)
	}
	lsetAge(t, filepath.Join(dir, "state"), old)
	fifo := filepath.Join(dir, "activity-20261102.ndjson")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	setAge(t, fifo, old)
	plain := filepath.Join(dir, "activity-20261103.ndjson")
	writeAged(t, plain, old)

	done := make(chan struct{})
	var res PruneResult
	var err error
	go func() {
		res, err = maybePrune(Target{Dir: dir}, 0, time.Now())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("prune blocked on a FIFO")
	}
	if err != nil || res.Removed != 1 || exists(plain) {
		t.Fatalf("result %+v %v; the plain expired file must be the only one deleted", res, err)
	}
	for _, p := range []string{target, victimState, link, fifo, filepath.Join(dir, "state")} {
		if !exists(p) {
			t.Errorf("%s deleted", p)
		}
	}

	// The spool directory itself replaced by a link: nothing is touched.
	real := privateDir(t)
	f := filepath.Join(real, "activity-20261101.ndjson")
	writeAged(t, f, old)
	alias := filepath.Join(t.TempDir(), "spool")
	if err := os.Symlink(real, alias); err != nil {
		t.Fatal(err)
	}
	if res, err := maybePrune(Target{Dir: alias}, 0, time.Now()); err == nil || res.Scanned || !exists(f) {
		t.Fatalf("pruned through a linked spool directory: %+v %v", res, err)
	}
}

// A directory that is not private to the caller is refused.
func TestPruneRefusesSharedDir(t *testing.T) {
	dir := privateDir(t)
	f := filepath.Join(dir, "activity-20261101.ndjson")
	writeAged(t, f, old)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if res, err := maybePrune(Target{Dir: dir}, 0, time.Now()); err == nil || res.Scanned || !exists(f) {
		t.Fatalf("pruned a non-private directory: %+v %v", res, err)
	}
}

// statInfo is an lstat result with the given ownership.
type statInfo struct {
	os.FileInfo
	sys any
}

func (s statInfo) Sys() any { return s.sys }

// fileOwner reads the uid of the lstat result, without root: another uid
// is not the caller's, and a result without ownership is nobody's.
func TestFileOwnerReadsUID(t *testing.T) {
	p := filepath.Join(privateDir(t), "activity-20261101.ndjson")
	writeAged(t, p, old)
	fi, err := os.Lstat(p)
	if err != nil {
		t.Fatal(err)
	}
	me := callerOwners()
	other := uint32(os.Geteuid()) + 4242
	if o, ok := fileOwner(statInfo{fi, &syscall.Stat_t{Uid: other}}, p); !ok || o != strconv.FormatUint(uint64(other), 10) {
		t.Fatalf("fileOwner = %q %v, want %d", o, ok, other)
	}
	if ownedBy(statInfo{fi, &syscall.Stat_t{Uid: other}}, p, me) {
		t.Fatal("a file of another uid counted as the caller's")
	}
	if ownedBy(statInfo{fi, nil}, p, me) {
		t.Fatal("a file without ownership information counted as the caller's")
	}
	if !ownedBy(fi, p, me) {
		t.Fatal("the caller's own file not recognised")
	}
}

// A file another account owns stays, even in the caller's own spool; so
// does a directory another account owns.
func TestPruneLeavesOtherAccountsFiles(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("needs root to chown")
	}
	dir := privateDir(t)
	foreign := filepath.Join(dir, "activity-20261101.ndjson")
	foreignState := filepath.Join(dir, "state", "0123456789abcdef0123456789abcdef.json")
	mine := filepath.Join(dir, "activity-20261102.ndjson")
	for _, p := range []string{foreign, foreignState, mine} {
		writeAged(t, p, old)
	}
	for _, p := range []string{foreign, foreignState} {
		if err := os.Chown(p, 4242, 4242); err != nil {
			t.Fatal(err)
		}
	}
	res, err := maybePrune(Target{Dir: dir}, 0, time.Now())
	if err != nil || res.Removed != 1 || exists(mine) || !exists(foreign) || !exists(foreignState) {
		t.Fatalf("result %+v %v: only the caller's file may go", res, err)
	}

	theirs := privateDir(t)
	f := filepath.Join(theirs, "activity-20261101.ndjson")
	writeAged(t, f, old)
	if err := os.Chown(theirs, 4242, 4242); err != nil {
		t.Fatal(err)
	}
	if res, err := maybePrune(Target{Dir: theirs}, 0, time.Now()); err == nil || res.Scanned || !exists(f) {
		t.Fatalf("pruned another account's directory: %+v %v", res, err)
	}
}
