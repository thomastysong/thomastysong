//go:build windows

package main

import (
	"errors"
	"os"
	"os/user"
)

// Windows access is decided by ACLs, which mode bits do not describe; the
// checks that depend on them report "skip" here.
func fileOwner(os.FileInfo) (uid, gid int, ok bool) { return 0, 0, false }

func lookupUID(name string) string {
	u, err := user.Lookup(name)
	if err != nil {
		return ""
	}
	return u.Uid
}

const permsChecked = false

type accessor struct{ name string }

func lookupAccessor(name string) (*accessor, error) {
	return nil, errors.New("--as-user is not supported on Windows (access is decided by ACLs)")
}

func (a *accessor) canRead(string, []string) (bool, string) {
	return false, "unsupported on Windows"
}

// rewriteFlags: Windows has no FIFO-on-open hazard for ordinary paths.
const rewriteFlags = 0

// linkCount is not read on Windows: NTFS hard links need write access to
// the target, so a link the account planted reaches only files it could
// change itself.
// UNVERIFIED: compiled and vetted only.
func linkCount(os.FileInfo) uint64 { return 1 }

// prepareOutbox is a no-op on Windows: the outbox inherits the ACL of the
// data directory, which the installer (or the daemon) sets.
// UNVERIFIED: the daemon's explicit ACLs are not applied by a daemonless
// scan.
func prepareOutbox(dataDir, outbox, group string) []string { return nil }
