package platform

import (
	"os"
	"path"
	"strings"
)

// maxTrustedLinks bounds the symbolic links walkTrusted follows (Linux
// stops at 40 too).
const maxTrustedLinks = 40

// walkTrusted resolves an absolute, slash-separated path one component at a
// time, as the kernel does (".." after a symbolic link is the parent of
// the link's target, not of the link), and asks fine about "/" and about
// every directory and file the walk reaches. Those are every directory a
// name is looked up in, through every symbolic link, and the final file.
// Anyone who may write to one of them can change what the path names. A
// symbolic link cannot change without being replaced in its directory,
// and that directory is checked. It reports whether fine accepted all of
// them and the walk ended at a regular file. lstat and readlink are the
// file system (os.Lstat, os.Readlink); tests pass their own.
func walkTrusted(p string, lstat func(string) (os.FileInfo, error), readlink func(string) (string, error), fine func(string, os.FileInfo) bool) bool {
	if !strings.HasPrefix(p, "/") {
		return false
	}
	fi, err := lstat("/")
	if err != nil || !fi.IsDir() || !fine("/", fi) {
		return false
	}
	cur := "/"
	rest := strings.Split(p, "/")
	links := 0
	for len(rest) > 0 {
		name := rest[0]
		rest = rest[1:]
		switch name {
		case "", ".":
			continue
		case "..":
			// The parent of a directory the walk reached was reached first.
			cur = path.Dir(cur)
			continue
		}
		next := path.Join(cur, name)
		fi, err := lstat(next)
		if err != nil {
			return false
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			if links++; links > maxTrustedLinks {
				return false
			}
			target, err := readlink(next)
			if err != nil || target == "" {
				return false
			}
			if strings.HasPrefix(target, "/") {
				cur = "/"
			}
			rest = append(strings.Split(target, "/"), rest...)
			continue
		}
		if !fine(next, fi) {
			return false
		}
		switch {
		case fi.IsDir():
			cur = next
		case fi.Mode().IsRegular():
			// A file in the middle of a path ("hawkbell/.." or "hawkbell/x")
			// fails in the kernel with ENOTDIR.
			for _, r := range rest {
				if r != "" {
					return false
				}
			}
			return true
		default:
			return false
		}
	}
	return false // the path names a directory
}
