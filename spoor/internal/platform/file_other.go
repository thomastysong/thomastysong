//go:build !linux && !darwin && !windows

package platform

import (
	"fmt"
	"os"
)

const openNonblock = 0

// OpenNoFollow opens path for reading, refusing symbolic links on the final
// component and anything but a regular file. This portable version compares
// the file before and after opening instead of using O_NOFOLLOW.
func OpenNoFollow(path string) (*os.File, error) {
	before, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if before.Mode()&os.ModeSymlink != 0 {
		return nil, &os.PathError{Op: "open", Path: path, Err: ErrSymlink}
	}
	if !before.Mode().IsRegular() {
		return nil, &os.PathError{Op: "open", Path: path, Err: ErrNotRegular}
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	after, err := f.Stat()
	if err != nil || !after.Mode().IsRegular() || !os.SameFile(before, after) {
		f.Close()
		return nil, &os.PathError{Op: "open", Path: path, Err: ErrSymlink}
	}
	return f, nil
}

// FileID has no portable implementation; it returns "".
func FileID(fi os.FileInfo, path string) string { return "" }

func fileIDOfHandle(f *os.File) (string, error) {
	return "", fmt.Errorf("file identity: %w", ErrUnsupported)
}

// OwnerUID has no portable implementation.
func OwnerUID(fi os.FileInfo) (string, bool) { return "", false }

// PathOwner has no portable implementation.
func PathOwner(path string) (string, bool) { return "", false }

func hostIDFileTrusted(fi os.FileInfo, system bool) bool { return true }

// TrustedPath has no portable implementation: nothing is trusted.
func TrustedPath(p string) bool { return false }
