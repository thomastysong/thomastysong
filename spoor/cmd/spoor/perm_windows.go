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
