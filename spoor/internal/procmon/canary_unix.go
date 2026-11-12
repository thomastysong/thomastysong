//go:build unix

package procmon

import (
	"os"
	"path/filepath"
	"strings"

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
// root can have planted or replaced. os.StartProcess resolves the path again
// at exec time, so every name on the way must be one only root can change:
// each directory walked through is root-owned and not writable by group or
// others (a sticky directory such as /tmp is accepted, because only root
// can rename or remove root's entries in it, and every entry walked is
// root-owned), and so is each symbolic link. Directory links (/bin ->
// usr/bin on merged-/usr systems) are followed under the same rule; the
// program itself may be one link (Alpine's /bin/true -> /bin/busybox) whose
// target is a regular file, never a second link.
func rootOnlyExecutable(path string) bool {
	if !filepath.IsAbs(path) {
		return false
	}
	links := 0
	dir, ok := trustedDir(filepath.Dir(filepath.Clean(path)), &links)
	if !ok {
		return false
	}
	p := filepath.Join(dir, filepath.Base(path))
	fi, err := os.Lstat(p)
	if err != nil || !rootOwnedNotShared(fi) {
		return false
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		target, err := os.Readlink(p)
		if err != nil || target == "" {
			return false
		}
		if !filepath.IsAbs(target) {
			target = filepath.Join(dir, target)
		}
		tdir, ok := trustedDir(filepath.Dir(filepath.Clean(target)), &links)
		if !ok {
			return false
		}
		if fi, err = os.Lstat(filepath.Join(tdir, filepath.Base(target))); err != nil {
			return false
		}
	}
	return fi.Mode().IsRegular() && rootOwnedNotShared(fi) && fi.Mode().Perm()&0o111 != 0
}

// maxDirLinks bounds the directory links trustedDir follows.
const maxDirLinks = 8

// trustedDir resolves an absolute directory path one name at a time and
// returns it without symbolic links, or false when any directory or link on
// the way could have been changed by someone other than root.
func trustedDir(dir string, links *int) (string, bool) {
	if !filepath.IsAbs(dir) {
		return "", false
	}
	cur := string(filepath.Separator)
	if !rootOnlyDir(cur) {
		return "", false
	}
	rest := strings.Split(strings.TrimPrefix(filepath.Clean(dir), cur), string(filepath.Separator))
	for _, name := range rest {
		if name == "" || name == "." {
			continue
		}
		// Clean has removed every "..": an absolute path keeps none.
		next := filepath.Join(cur, name)
		fi, err := os.Lstat(next)
		if err != nil {
			return "", false
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			*links++
			if *links > maxDirLinks || !rootOwnedNotShared(fi) {
				return "", false
			}
			target, err := os.Readlink(next)
			if err != nil || target == "" {
				return "", false
			}
			if !filepath.IsAbs(target) {
				target = filepath.Join(cur, target)
			}
			resolved, ok := trustedDir(target, links)
			if !ok {
				return "", false
			}
			cur = resolved
			continue
		}
		if !rootOnlyDir(next) {
			return "", false
		}
		cur = next
	}
	return cur, true
}

func rootOwnedNotShared(fi os.FileInfo) bool {
	if fi.Mode()&os.ModeSymlink == 0 && fi.Mode().Perm()&0o022 != 0 {
		return false
	}
	uid, ok := platform.OwnerUID(fi)
	return ok && uid == "0"
}

// rootOnlyDir checks one directory, not following a link in its last name.
func rootOnlyDir(dir string) bool {
	fi, err := os.Lstat(dir)
	if err != nil || !fi.IsDir() {
		return false
	}
	uid, ok := platform.OwnerUID(fi)
	if !ok || uid != "0" {
		return false
	}
	return fi.Mode().Perm()&0o022 == 0 || fi.Mode()&os.ModeSticky != 0
}

func canaryDir() string { return "/" }
