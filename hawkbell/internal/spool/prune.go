package spool

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/platform"
)

// Retention of what no daemon deletes.
//
// The daemon deletes a fully read record file from a system spool
// (<data_dir>/spool/<uid>/) once its last write is older than
// retention.spool (Reader.maybeRetire). It deletes nothing else: not the
// guard-mode session state the hook keeps next to the records (state/,
// which can hold the text of scripts the agent wrote), and nothing at all
// in the fallback spool in a home directory (it does not write into homes;
// systemd ProtectHome=read-only) or in $HAWKBELL_SPOOL (which it does not
// know). In daemonless mode nothing reads those spools at all. They hold
// full local content, so the hook prunes them itself: MaybePrune, called by
// the hook after its reply (after its own appends, or in their place when
// every event was excluded), deletes the caller's own files there whose
// last write is older than the retention. A hook that is switched off
// prunes nothing.
const (
	// DefaultRetention is retention.spool when the setting is zero or
	// negative (config has no lower bound for it).
	DefaultRetention = 72 * time.Hour
	// PruneEvery is how often MaybePrune scans one directory, across all
	// of the caller's hook processes (or once per retention, if that is
	// shorter, but never more than once per minPruneAge; and again at
	// once after a scan that reached maxPruneRemovals).
	PruneEvery = time.Hour
	// minPruneAge: a file written less than this long ago is never
	// deleted, whatever the retention. SaveState replaces a state file
	// under the spool lock the scan holds, but saves without it when the
	// lock was busy for longer than stateLockWait; this keeps the
	// temporary file of such a save out of reach. It does not protect the
	// state file such a save replaces: a scan that found the old file
	// expired can delete the new one.
	minPruneAge = time.Minute
	// pruneMarker's modification time is when the directory was last
	// scanned. The reader skips names that start with a dot.
	pruneMarker = ".prune"
)

// maxPruneRemovals bounds the files one scan deletes, so a spool that grew
// for a year costs one hook a bounded delay; the next due hook goes on.
// Tests lower it.
var maxPruneRemovals = 1000

// pruneOwners lists the owners whose files a scan may delete
// (callerOwners). Tests replace it to stand in for another account without
// root.
var pruneOwners = callerOwners

// Kind is the spool directory Locate chose.
type Kind uint8

const (
	// KindOverride is $HAWKBELL_SPOOL (containers, CI, tests).
	KindOverride Kind = iota + 1
	// KindSystem is <dataDir>/spool/<uid>/, which the daemon reads and
	// prunes.
	KindSystem
	// KindFallback is the caller's own state directory
	// (platform.UserDirs(home).Spool).
	KindFallback
)

// Location is where a hook process appends, and which spools it prunes
// itself.
type Location struct {
	Dir  string
	Kind Kind
	// Prune lists what the hook prunes with MaybePrune:
	//   - KindFallback: Dir.
	//   - KindOverride: Dir; when it is the system spool of uid, only its
	//     state (see KindSystem). Nothing else: the variable replaces every
	//     other location, the home included.
	//   - KindSystem: the state of Dir, whose record files the daemon
	//     deletes once it has read them (the hook does not delete records
	//     the daemon may not have read yet); and the fallback spool in
	//     home, which the hook used while the system spool was unreachable
	//     and which the daemon reads but never deletes from (not when home
	//     is "").
	Prune []Target
}

// Target is a spool directory the hook prunes.
type Target struct {
	Dir string
	// StateOnly leaves the record files (*.ndjson) to the daemon and
	// deletes only session state and temporary files.
	StateOnly bool
}

// Locate resolves where a hook process running as uid may append, in
// order: $HAWKBELL_SPOOL; <dataDir>/spool/<uid>/ when it exists, is owned by
// the caller and is private (0700); else the caller's own state directory.
// It never returns a shared, world-writable directory. On error, Dir is
// still the directory that was refused.
func Locate(dataDir, uid, home string) (Location, error) {
	sys := ""
	if dataDir != "" && uid != "" {
		sys = filepath.Join(dataDir, "spool", uid)
	}
	if d := os.Getenv(EnvSpool); d != "" {
		l := Location{Dir: d, Kind: KindOverride}
		if err := os.MkdirAll(d, 0o700); err != nil {
			return l, err
		}
		if err := checkPrivate(d, uid); err != nil {
			return l, err
		}
		l.Prune = []Target{{Dir: d, StateOnly: sameDir(d, sys)}}
		return l, nil
	}
	if sys != "" && checkPrivate(sys, uid) == nil {
		l := Location{Dir: sys, Kind: KindSystem, Prune: []Target{{Dir: sys, StateOnly: true}}}
		if home != "" {
			if fb := platform.UserDirs(home).Spool; fb != "" {
				l.Prune = append(l.Prune, Target{Dir: fb})
			}
		}
		return l, nil
	}
	d := platform.UserDirs(home).Spool
	if d == "" {
		return Location{}, errors.New("spool: no user directory")
	}
	l := Location{Dir: d, Kind: KindFallback}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return l, err
	}
	if err := checkPrivate(d, uid); err != nil {
		return l, err
	}
	l.Prune = []Target{{Dir: d}}
	return l, nil
}

// sameDir reports whether a and b name the same existing directory.
func sameDir(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	fa, err := os.Lstat(a)
	if err != nil {
		return false
	}
	fb, err := os.Lstat(b)
	return err == nil && os.SameFile(fa, fb)
}

// PruneResult is what one MaybePrune call did.
type PruneResult struct {
	Scanned bool // the directory was scanned
	Busy    bool // another process held the spool's lock: nothing was done
	Removed int  // files deleted
	Capped  bool // maxPruneRemovals was reached; the next due hook goes on
}

// MaybePrune deletes the caller's own expired files from the spool
// directory t.Dir. It scans the directory at most once per PruneEvery
// across all of the caller's hook processes, more often in two cases: when
// retain is shorter (then once per retain, but never more than once a
// minute), and right after a scan that stopped at maxPruneRemovals, which
// leaves the next call due. A file is expired when its last write is older
// than retain (DefaultRetention when retain <= 0; never less than a
// minute).
//
// What is deleted: regular files owned by the calling account (on Unix its
// effective uid; on Windows its user or its token's default owner, see
// callerOwners) whose names the hook writes: record files (*.ndjson; not
// with t.StateOnly), guard-mode session state and the payload-key secret
// (state/*.json) and leftovers of interrupted atomic writes (.tmp-*). The
// lock file, the sequence counters and anything else are left alone.
//
// Cost: when dir was scanned less than the interval ago, the call is one
// lstat of dir/.prune; when dir does not exist, two (the marker, then
// dir). A scan runs under the spool's lock, taken without waiting: when
// another process holds it (an append in progress, another hook pruning),
// the call returns at once and a later hook does the scan. So no file is
// deleted while an append to it is in progress, nor a state file that
// SaveState replaces during the scan (unless SaveState gave up waiting for
// the lock, see stateLockWait).
//
// Safety: dir must stay the directory that was checked while it is
// scanned (os.Root), and "state" must be a real directory inside it.
// Links, FIFOs and devices are never deleted, and nothing outside dir is
// touched. On Unix dir must also be a real directory (not a link), owned
// by the caller and private (checkPrivate), and a file is deleted only
// when its owner, read from the same lstat as its age, is the caller. On
// Windows (untested there) checkPrivate checks only that dir is a
// directory and not a link or junction, not its owner or ACL; each file's
// owner is read by path (platform.PathOwner), not through the handle the
// delete uses, so a junction swapped into dir's path between the two
// makes the check read another file; and an elevated hook counts the
// Administrators group as its own (callerOwners).
//
// A missing directory is not an error.
func MaybePrune(t Target, retain time.Duration) (PruneResult, error) {
	return maybePrune(t, retain, time.Now())
}

func maybePrune(t Target, retain time.Duration, now time.Time) (PruneResult, error) {
	dir := t.Dir
	retain, every := pruneTimes(retain)
	marker := filepath.Join(dir, pruneMarker)
	if markerFresh(marker, now, every) {
		return PruneResult{}, nil
	}
	if err := checkPrivate(dir, currentUID()); err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return PruneResult{}, nil
		}
		return PruneResult{}, err
	}
	unlock, ok := tryLockDir(dir)
	if !ok {
		return PruneResult{Busy: true}, nil
	}
	defer unlock()
	// Another hook may have scanned between the first look and the lock.
	if markerFresh(marker, now, every) {
		return PruneResult{}, nil
	}
	if err := writeFileAtomic(marker, nil, 0o600); err != nil {
		return PruneResult{}, err
	}
	res, err := prune(dir, t.StateOnly, retain, now)
	if res.Capped {
		// Make the next hook due at once.
		_ = os.Remove(marker)
	}
	return res, err
}

// pruneTimes returns the age at which a file expires and the interval
// between scans.
func pruneTimes(retain time.Duration) (expire, every time.Duration) {
	if retain <= 0 {
		retain = DefaultRetention
	}
	expire = max(retain, minPruneAge)
	every = min(max(retain, minPruneAge), PruneEvery)
	return expire, every
}

// markerFresh reports whether the marker says the directory was scanned
// less than every ago. A marker from the future by more than every (the
// clock was set back) is stale.
func markerFresh(marker string, now time.Time, every time.Duration) bool {
	fi, err := os.Lstat(marker)
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	age := now.Sub(fi.ModTime())
	return age > -every && age < every
}

// prune deletes the expired files of dir (with stateOnly, no record
// files). The caller holds dir's lock.
func prune(dir string, stateOnly bool, expire time.Duration, now time.Time) (PruneResult, error) {
	res := PruneResult{Scanned: true}
	root, err := openDirRoot(dir)
	if err != nil {
		return res, err
	}
	defer root.Close()
	owners := pruneOwners()
	budget := maxPruneRemovals
	sweep := func(r *os.Root, path string, want func(string) bool) error {
		d, err := r.Open(".")
		if err != nil {
			return err
		}
		ents, err := d.ReadDir(-1)
		d.Close()
		if err != nil {
			return err
		}
		for _, e := range ents {
			name := e.Name()
			if !e.Type().IsRegular() || !want(name) {
				continue
			}
			// Lstat on the root never follows a link, and the type is
			// checked again: the directory entry may be stale.
			fi, err := r.Lstat(name)
			if err != nil || !fi.Mode().IsRegular() || now.Sub(fi.ModTime()) < expire {
				continue
			}
			if !ownedBy(fi, filepath.Join(path, name), owners) {
				continue
			}
			if budget <= 0 {
				res.Capped = true
				return nil
			}
			// Remove unlinks the name in r; it never follows a link.
			if err := r.Remove(name); err == nil {
				res.Removed++
				budget--
			}
		}
		return nil
	}
	if err := sweep(root, dir, func(n string) bool { return (!stateOnly && isRecordFile(n)) || isTempFile(n) }); err != nil {
		return res, err
	}
	if res.Capped {
		return res, nil
	}
	state := filepath.Join(dir, "state")
	sr, err := openSubRoot(root, "state")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) || errors.Is(err, errNotPlainDir) {
			return res, nil // no state, or not one the hook made
		}
		return res, err
	}
	defer sr.Close()
	return res, sweep(sr, state, func(n string) bool {
		return (strings.HasSuffix(n, ".json") && !strings.HasPrefix(n, ".")) || isTempFile(n)
	})
}

// ownedBy reports whether the file fi (from an lstat of path) is owned by
// one of owners. A file whose owner cannot be read is not.
func ownedBy(fi os.FileInfo, path string, owners []string) bool {
	o, ok := fileOwner(fi, path)
	return ok && o != "" && slices.Contains(owners, o)
}

// isRecordFile is a spool file the reader reads.
func isRecordFile(name string) bool {
	return strings.HasSuffix(name, ".ndjson") && !strings.HasPrefix(name, ".")
}

// isTempFile is a temporary file of writeFileAtomic.
func isTempFile(name string) bool { return strings.HasPrefix(name, ".tmp-") }

// errNotPlainDir refuses a spool directory that is a link or was replaced
// while it was being opened.
var errNotPlainDir = errors.New("spool: not a plain directory")

// openDirRoot opens dir, which must be a real directory and not a link, as
// an os.Root, and checks that the root is the directory that was checked.
func openDirRoot(dir string) (*os.Root, error) {
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, errNotPlainDir
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	if got, err := r.Stat("."); err != nil || !os.SameFile(fi, got) {
		r.Close()
		return nil, errNotPlainDir
	}
	return r, nil
}

// openSubRoot opens name in r, which must be a real directory and not a
// link.
func openSubRoot(r *os.Root, name string) (*os.Root, error) {
	fi, err := r.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, errNotPlainDir
	}
	sub, err := r.OpenRoot(name)
	if err != nil {
		return nil, err
	}
	if got, err := sub.Stat("."); err != nil || !os.SameFile(fi, got) {
		sub.Close()
		return nil, errNotPlainDir
	}
	return sub, nil
}
