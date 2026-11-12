//go:build unix

package procmon

import (
	"os"
	"path/filepath"

	"github.com/thomastysong/spoor/internal/platform"
)

// canaryCommand returns the self-test program: the first of the usual
// locations of true(1) that only root can have put there. true ignores its
// arguments, which is the point. The path is executed as given (not the
// resolved target) because a busybox-style multi-call binary decides what to
// be from argv[0].
func canaryCommand() (string, []string, bool) {
	for _, p := range []string{"/usr/bin/true", "/bin/true"} {
		if rootOnlyExecutable(p) {
			return p, []string{p}, true
		}
	}
	return "", nil, false
}

// rootOnlyExecutable reports whether path is an executable that nobody but
// root can have planted or replaced: the file and the directory holding it
// are owned by root and not writable by group or others. One symlink is
// allowed (Alpine's /bin/true -> /bin/busybox) when the link and its
// directory pass the same test.
func rootOnlyExecutable(path string) bool {
	fi, err := os.Lstat(path)
	if err != nil || !rootOwnedNotShared(fi) || !rootOnlyDir(filepath.Dir(path)) {
		return false
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		target, err := filepath.EvalSymlinks(path)
		if err != nil {
			return false
		}
		if fi, err = os.Lstat(target); err != nil || !rootOnlyDir(filepath.Dir(target)) {
			return false
		}
	}
	return fi.Mode().IsRegular() && rootOwnedNotShared(fi) && fi.Mode().Perm()&0o111 != 0
}

func rootOwnedNotShared(fi os.FileInfo) bool {
	if fi.Mode()&os.ModeSymlink == 0 && fi.Mode().Perm()&0o022 != 0 {
		return false
	}
	uid, ok := platform.OwnerUID(fi)
	return ok && uid == "0"
}

func rootOnlyDir(dir string) bool {
	fi, err := os.Stat(dir)
	return err == nil && fi.IsDir() && fi.Mode().Perm()&0o022 == 0 && rootOwnedNotShared(fi)
}

func canaryDir() string { return "/" }
