//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !windows

package spool

import (
	"fmt"
	"os"
)

func currentUID() string                  { return "unknown" }
func checkPrivate(dir, uid string) error  { return nil }
func freeBytes(dir string) (uint64, bool) { return 0, false }
func lockDir(dir string) (func(), error)  { return func() {}, nil }
func openAppend(path string) (*os.File, error) {
	if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("not a regular file")
	}
	return os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
}
