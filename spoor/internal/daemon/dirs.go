package daemon

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"regexp"

	"github.com/thomastysong/spoor/internal/config"
	"github.com/thomastysong/spoor/internal/platform"
	"github.com/thomastysong/spoor/internal/sink"
)

// layout is the daemon's directory tree under the data directory.
type layout struct {
	data, outbox, local, check, spool, bundle string
	// outboxGID is the group allowed to read the outbox (output.group), or
	// -1 when it does not exist on this host (or on Windows).
	outboxGID int
	group     string
}

// dirKind selects the ownership and access rules of a directory.
type dirKind int

const (
	dirData       dirKind = iota // traversable by everyone, writable by the sensor only
	dirPrivate                   // the sensor only: local ring, checkpoints
	dirOutbox                    // the sensor writes, output.group reads
	dirSpoolRoot                 // traversable, not listable: users reach their own subdirectory
	dirBundle                    // signed public content: readable by everyone
	dirUserSpool                 // one account's private spool
)

// Unix modes per kind. Explicit chmod after creation, because the service
// runs with UMask=0027 and MkdirAll's mode is filtered by it.
var unixModes = map[dirKind]os.FileMode{
	dirData:      0o711,
	dirPrivate:   0o700,
	dirOutbox:    0o750 | os.ModeSetgid,
	dirSpoolRoot: 0o711,
	dirBundle:    0o755,
	dirUserSpool: 0o700,
}

// errSymlinkDir is returned for a symbolic link (or Windows reparse point)
// where the daemon expects a directory of its own.
var errSymlinkDir = errors.New("is a symbolic link or reparse point, not a directory")

// prepareLayout creates the directory tree with explicit modes and owners,
// repairing what exists with the wrong ones. Only a link planted where a
// directory belongs is refused: following it would make the sensor write,
// as root, wherever it points.
func prepareLayout(cfg *config.Config, privileged bool, log *slog.Logger) (layout, error) {
	l := layout{
		data:      cfg.DataDir,
		outbox:    cfg.OutboxDir(),
		local:     cfg.LocalDir(),
		check:     cfg.CheckDir(),
		spool:     cfg.SpoolDir(),
		bundle:    cfg.BundleDir(),
		outboxGID: -1,
		group:     cfg.Output.Group,
	}
	if err := secureDataDir(l.data, privileged); err != nil {
		return l, fmt.Errorf("daemon: data directory %s: %w", l.data, err)
	}
	if l.group != "" {
		if gid, ok := lookupGroup(l.group); ok {
			l.outboxGID = gid
		} else if privileged {
			log.Warn("output.group does not exist; the outbox stays readable by root only", "group", l.group)
		}
	}
	for _, d := range []struct {
		path string
		kind dirKind
	}{
		{l.check, dirPrivate},
		{l.local, dirPrivate},
		{l.outbox, dirOutbox},
		{l.spool, dirSpoolRoot},
		{l.bundle, dirBundle},
	} {
		if err := secureDir(d.path, d.kind, privileged, "", l.outboxGID); err != nil {
			return l, fmt.Errorf("daemon: %s: %w", d.path, err)
		}
	}
	if err := repairOutboxFiles(l, privileged); err != nil {
		log.Warn("could not repair outbox file modes", "error", err)
	}
	return l, nil
}

// spoolDirFor is <data>/spool/<uid>. A uid that is not a plain account id
// (digits on POSIX, a SID on Windows) gets no system spool directory: the
// name becomes a path component.
func (l layout) spoolDirFor(uid string) (string, bool) {
	if !validUID(uid) {
		return "", false
	}
	return filepath.Join(l.spool, uid), true
}

var uidRE = regexp.MustCompile(`^(?:[0-9]{1,10}|S-1(?:-[0-9]{1,10}){1,15})$`)

func validUID(uid string) bool { return uidRE.MatchString(uid) }

// ensureUserSpool creates <data>/spool/<uid>/ for an account: mode 0700,
// owned by the account, so that its hooks can append there and nobody else
// can (spool.Dir accepts nothing else). Unprivileged, only the caller's own
// directory can be made.
func ensureUserSpool(l layout, u platform.UserHome, privileged bool) error {
	dir, ok := l.spoolDirFor(u.UID)
	if !ok {
		return fmt.Errorf("account id %q cannot name a directory", u.UID)
	}
	if !privileged && u.UID != currentUID() {
		return nil
	}
	return secureDir(dir, dirUserSpool, privileged, u.UID, -1)
}

// repairOutboxFiles gives existing segments the outbox's file mode and
// group: segments written before output.group was set, or under a
// different umask, must still be readable by the shipper.
func repairOutboxFiles(l layout, privileged bool) error {
	ents, err := os.ReadDir(l.outbox)
	if err != nil {
		return err
	}
	var errs []error
	for _, e := range ents {
		if _, ok := sink.ParseSegmentName(e.Name()); !ok {
			continue
		}
		if err := secureSegmentFile(filepath.Join(l.outbox, e.Name()), privileged, l.outboxGID); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
