//go:build !unix && !windows

package sink

import (
	"errors"
	"io/fs"
	"os"
)

// Fallback for platforms hawkbell does not target (plan9, wasm): plain opens,
// no symlink or FIFO hardening.

func openAppend(path string, mode os.FileMode) (*os.File, bool, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE|os.O_EXCL, mode)
	if err == nil {
		return f, true, nil
	}
	if !errors.Is(err, fs.ErrExist) {
		return nil, false, err
	}
	f, err = os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	return f, false, err
}

func openRead(path string) (*os.File, error) { return os.Open(path) }

func linkCount(os.FileInfo) uint64 { return 1 }

func syncDir(string) error { return nil }
