package platform

import (
	"io/fs"
	"os"
	"strings"
	"testing"
	"time"
)

// fakeFS is a slash-path file system for walkTrusted: dirs, files and
// symbolic links.
type fakeFS map[string]string // path -> "dir" | "file" | "link:<target>"

type fakeFI struct {
	name string
	mode fs.FileMode
}

func (f fakeFI) Name() string       { return f.name }
func (f fakeFI) Size() int64        { return 0 }
func (f fakeFI) Mode() fs.FileMode  { return f.mode }
func (f fakeFI) ModTime() time.Time { return time.Time{} }
func (f fakeFI) IsDir() bool        { return f.mode.IsDir() }
func (f fakeFI) Sys() any           { return nil }

func (f fakeFS) lstat(p string) (os.FileInfo, error) {
	switch e := f[p]; {
	case e == "dir":
		return fakeFI{p, fs.ModeDir | 0o755}, nil
	case e == "file":
		return fakeFI{p, 0o755}, nil
	case strings.HasPrefix(e, "link:"):
		return fakeFI{p, fs.ModeSymlink | 0o777}, nil
	}
	return nil, fs.ErrNotExist
}

func (f fakeFS) readlink(p string) (string, error) {
	if t, ok := strings.CutPrefix(f[p], "link:"); ok {
		return t, nil
	}
	return "", fs.ErrInvalid
}

// TestWalkTrusted: every directory the kernel looks a name up in, through
// every symbolic link (also links met while resolving another link's
// target, which a check of the lexical path and of its fully resolved form
// would both miss), and the file itself are checked.
func TestWalkTrusted(t *testing.T) {
	f := fakeFS{
		"/": "dir", "/usr": "dir", "/usr/bin": "dir", "/usr/bin/hawkbell": "file",
		"/usr/local": "dir", "/usr/local/bin": "dir",
		"/usr/local/bin/hawkbell": "link:../../../opt/hawkbell/hawkbell",
		"/opt":                    "dir", "/opt/hawkbell": "dir", "/opt/hawkbell/hawkbell": "file",
		// /a/b -> /p/q/r, and /p/q -> /s: the walk passes through /p.
		"/a": "dir", "/a/b": "link:/p/q/r", "/p": "dir", "/p/q": "link:/s", "/s": "dir", "/s/r": "dir", "/s/r/hawkbell": "file",
		// ".." after a link is the parent of the link's target.
		"/l": "link:/x/y", "/x": "dir", "/x/y": "dir", "/x/f": "file",
		"/loop": "link:/loop",
	}
	walk := func(p string, bad ...string) bool {
		return walkTrusted(p, f.lstat, f.readlink, func(q string, _ os.FileInfo) bool {
			for _, b := range bad {
				if q == b {
					return false
				}
			}
			return true
		})
	}
	for _, c := range []struct {
		path string
		bad  []string
		want bool
	}{
		{"/usr/bin/hawkbell", nil, true},
		{"/usr/bin/hawkbell", []string{"/usr"}, false},
		{"/usr/bin/hawkbell", []string{"/"}, false},
		{"/usr/bin/hawkbell", []string{"/usr/bin/hawkbell"}, false},
		{"/usr/local/bin/hawkbell", nil, true},
		{"/usr/local/bin/hawkbell", []string{"/usr/local/bin"}, false}, // the link's directory
		{"/usr/local/bin/hawkbell", []string{"/opt"}, false},           // the target's chain
		{"/a/b/hawkbell", nil, true},
		{"/a/b/hawkbell", []string{"/p"}, false}, // only reached while resolving /p/q
		{"/a/b/hawkbell", []string{"/s"}, false},
		{"/l/../f", nil, true},
		{"/l/../f", []string{"/x"}, false},
		{"/loop", nil, false},
		{"/usr/bin", nil, false},            // a directory
		{"/usr/bin/hawkbell/x", nil, false}, // a file in the middle
		{"/usr/bin/hawkbell/..", nil, false},
		{"/usr/bin/missing", nil, false},
		{"usr/bin/hawkbell", nil, false}, // relative
		{"", nil, false},
	} {
		if got := walk(c.path, c.bad...); got != c.want {
			t.Errorf("walkTrusted(%q, bad %v) = %v, want %v", c.path, c.bad, got, c.want)
		}
	}
}
