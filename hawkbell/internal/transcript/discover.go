package transcript

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// Walk bounds. Roots point into user-writable trees: a directory with a
// million entries or a thousand levels must cost a bounded amount of work.
const (
	maxWalkDepth    = 12
	maxWalkEntries  = 200_000 // directory entries examined per root per pass
	maxFilesPerRoot = 50_000
	dirBatch        = 1024
)

// candidate is one file a root glob matched.
type candidate struct {
	path string
	base string // fixed, operator-chosen prefix of the glob
	rel  string // path below base
	root int    // index into the roots slice
	meta fileMeta
	// symlink marks a match that is a symbolic link; it is reported, never
	// opened.
	symlink bool
}

func hasMeta(seg string) bool { return strings.ContainsAny(seg, "*?[") }

// splitGlob separates a glob into its fixed directory prefix and the
// pattern segments below it. "**" matches zero or more directories.
func splitGlob(pattern string) (base string, segs []string) {
	pattern = filepath.Clean(filepath.FromSlash(pattern))
	vol := filepath.VolumeName(pattern)
	rest := pattern[len(vol):]
	sep := string(filepath.Separator)
	abs := strings.HasPrefix(rest, sep)
	parts := strings.Split(strings.Trim(rest, sep), sep)
	i := 0
	for i < len(parts) && !hasMeta(parts[i]) {
		i++
	}
	base = vol
	if abs {
		base += sep
	}
	base = filepath.Join(base, filepath.Join(parts[:i]...))
	if base == "" {
		base = "."
	}
	return base, parts[i:]
}

type walker struct {
	ctx     context.Context
	root    int
	base    string
	entries int
	out     []candidate
	stopped bool
}

// expandGlob lists the files matching pattern without ever descending into
// or yielding through a symbolic link below the fixed prefix.
func expandGlob(ctx context.Context, root int, pattern string) []candidate {
	base, segs := splitGlob(pattern)
	w := &walker{ctx: ctx, root: root, base: base}
	if len(segs) == 0 {
		// A literal path: the file itself, with its directory as the base.
		dir, name := filepath.Split(base)
		if dir == "" {
			dir = "."
		}
		w.base = filepath.Clean(dir)
		w.consider(w.base, name)
		return w.out
	}
	w.walk(base, segs, 0)
	return w.out
}

func (w *walker) stop() bool {
	if w.stopped {
		return true
	}
	if w.ctx.Err() != nil || w.entries >= maxWalkEntries || len(w.out) >= maxFilesPerRoot {
		w.stopped = true
	}
	return w.stopped
}

// consider examines dir/name as a final match.
func (w *walker) consider(dir, name string) {
	path := filepath.Join(dir, name)
	m, err := lstatMeta(path)
	if err != nil {
		return
	}
	rel, err := filepath.Rel(w.base, path)
	if err != nil {
		return
	}
	switch {
	case m.symlink:
		w.out = append(w.out, candidate{path: path, base: w.base, rel: rel, root: w.root, meta: m, symlink: true})
	case m.regular:
		w.out = append(w.out, candidate{path: path, base: w.base, rel: rel, root: w.root, meta: m})
	}
	// Directories, FIFOs, sockets and devices are not session logs.
}

func (w *walker) walk(dir string, segs []string, depth int) {
	if len(segs) == 0 || depth > maxWalkDepth || w.stop() {
		return
	}
	seg, last := segs[0], len(segs) == 1
	if seg == "**" {
		if last {
			// Trailing "**": every file below dir.
			w.each(dir, func(name string, isDir bool) {
				if isDir {
					w.walk(filepath.Join(dir, name), segs, depth+1)
				} else {
					w.consider(dir, name)
				}
			})
			return
		}
		w.walk(dir, segs[1:], depth) // zero directories
		w.each(dir, func(name string, isDir bool) {
			if isDir {
				w.walk(filepath.Join(dir, name), segs, depth+1)
			}
		})
		return
	}
	if !hasMeta(seg) {
		// A literal segment needs no directory listing.
		if last {
			w.consider(dir, seg)
			return
		}
		next := filepath.Join(dir, seg)
		if m, err := lstatMeta(next); err == nil && m.dir && !m.symlink {
			w.walk(next, segs[1:], depth+1)
		}
		return
	}
	w.each(dir, func(name string, isDir bool) {
		if ok, _ := filepath.Match(seg, name); !ok {
			return
		}
		switch {
		case last && !isDir:
			w.consider(dir, name)
		case !last && isDir:
			w.walk(filepath.Join(dir, name), segs[1:], depth+1)
		}
	})
}

// each calls fn for the entries of dir in batches. isDir is true only for
// real directories: a symlink to a directory is reported as a non-directory
// so it is never descended into (consider() then sees it is a link).
func (w *walker) each(dir string, fn func(name string, isDir bool)) {
	f, err := os.Open(dir)
	if err != nil {
		return
	}
	defer f.Close()
	for !w.stop() {
		ents, err := f.ReadDir(dirBatch)
		for _, d := range ents {
			w.entries++
			typ := d.Type()
			isDir := d.IsDir() && typ&(os.ModeSymlink|os.ModeIrregular) == 0
			fn(d.Name(), isDir)
			if w.stop() {
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				return
			}
			return
		}
	}
}
