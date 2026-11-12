package rules

import (
	"crypto/sha256"
	"embed"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"sort"
	"strings"
	"sync"
)

// The embedded content is the floor every sensor ships with. Bundles merge
// over it (Set.Merge), so a host that never receives a bundle still
// detects. The whole packs directory is embedded (not packs/*.yaml) so the
// package still compiles when packs/embedded.cache is absent: the cache
// generator imports this package.
//
//go:generate go run ./cmd/rulescache -dir . -out packs/embedded.cache
//go:embed packs lists.yaml
var embeddedFS embed.FS

var (
	embOnce      sync.Once
	embSet       *Set
	embErr       error
	embFromCache bool // which path LoadEmbedded took, for tests
)

// LoadEmbedded compiles the packs built into the binary (packs/*.yaml and
// lists.yaml). Rules loaded this way are marked embedded, which the linter
// uses to forbid response: block in them. The content is read from the
// pre-parsed packs/embedded.cache when that was generated from exactly
// these YAML bytes, and parsed from the YAML otherwise. Loading happens
// once per process; each call returns an independent copy.
func LoadEmbedded() (*Set, error) {
	embOnce.Do(func() {
		embSet, embFromCache, embErr = compileEmbedded()
	})
	if embErr != nil {
		return nil, embErr
	}
	return embSet.clone(), nil
}

// compileEmbedded does the work of the first LoadEmbedded call in a
// process and reports whether the pre-parsed cache served it. The YAML is
// read whole only when the cache cannot be used; otherwise it is only
// streamed through the digest that proves the cache was made from it.
func compileEmbedded() (*Set, bool, error) {
	if c, err := embeddedFS.ReadFile(cacheFileName); err == nil {
		if d, err := embeddedDigest(); err == nil {
			if srcs, err := decodeCache(c, d); err == nil {
				if s, err := loadSources(srcs, true); err == nil {
					return s, true, nil
				}
			}
		}
	}
	files, err := readEmbedded()
	if err != nil {
		return nil, false, err
	}
	s, err := load(files, true)
	return s, false, err
}

// embeddedNames returns the embedded content file names: packs/*.yaml and
// lists.yaml.
func embeddedNames() ([]string, error) {
	entries, err := fs.ReadDir(embeddedFS, "packs")
	if err != nil {
		return nil, fmt.Errorf("rules: embedded packs: %w", err)
	}
	var names []string
	for _, e := range entries {
		if !e.IsDir() && wantFile(e.Name()) {
			names = append(names, "packs/"+e.Name())
		}
	}
	if _, err := fs.Stat(embeddedFS, "lists.yaml"); err == nil {
		names = append(names, "lists.yaml")
	}
	return names, nil
}

// readEmbedded returns the embedded content files.
func readEmbedded() (map[string][]byte, error) {
	names, err := embeddedNames()
	if err != nil {
		return nil, err
	}
	files := make(map[string][]byte, len(names))
	for _, n := range names {
		b, err := embeddedFS.ReadFile(n)
		if err != nil {
			return nil, fmt.Errorf("rules: embedded %s: %w", n, err)
		}
		files[n] = b
	}
	return files, nil
}

// embeddedDigest is sourceDigest(readEmbedded()) computed by streaming the
// files through one buffer instead of copying each.
func embeddedDigest() ([sha256.Size]byte, error) {
	var out [sha256.Size]byte
	names, err := embeddedNames()
	if err != nil {
		return out, err
	}
	sort.Strings(names)
	h := sha256.New()
	buf := make([]byte, 32<<10)
	var n [8]byte
	for _, name := range names {
		if fileRole(name) == "" {
			continue
		}
		f, err := embeddedFS.Open(name)
		if err != nil {
			return out, err
		}
		st, err := f.Stat()
		if err != nil {
			f.Close()
			return out, err
		}
		h.Write([]byte(name))
		h.Write([]byte{0})
		binary.BigEndian.PutUint64(n[:], uint64(st.Size()))
		h.Write(n[:])
		w, err := io.CopyBuffer(h, struct{ io.Reader }{f}, buf)
		f.Close()
		if err != nil || w != st.Size() {
			return out, fmt.Errorf("rules: embedded %s: short read", name)
		}
	}
	h.Sum(out[:0])
	return out, nil
}

// ErrInsecureDir is returned by LoadDir when the directory or a file in it
// could have been written by someone other than root/Administrators or the
// calling user. Rules decide what is reported and, in guard mode, what is
// blocked, so whoever can write them controls the sensor.
var ErrInsecureDir = errors.New("rules: insecure rules directory")

// maxDirEntries bounds a directory listing.
const maxDirEntries = 4096

// LoadDir compiles the content of a rules directory: either a bundle
// version directory (rules/*.yaml, lists.yaml, suppressions.yaml) or a flat
// directory of packs with optional lists.yaml and suppressions.yaml. The
// directory and every file read must be owned by root (Administrators,
// SYSTEM or TrustedInstaller on Windows) or by the calling user and must
// not be writable by group or others; this is checked on the open
// descriptor, never by path, and symbolic links are not followed. Files
// whose names do not end in ".yaml", or that start with a dot, are ignored.
func LoadDir(dir string) (*Set, error) {
	files, err := readTrustedDir(dir)
	if err != nil {
		return nil, err
	}
	return load(files, false)
}

// wantFile reports whether a directory entry is rule content.
func wantFile(name string) bool {
	return strings.HasSuffix(name, ".yaml") && !strings.HasPrefix(name, ".") && len(name) <= 255
}

// fileCap is the size limit for one content file.
func fileCap(name string) int64 {
	switch name {
	case "lists.yaml":
		return maxListBytes
	case "suppressions.yaml":
		return maxSuppBytes
	}
	return MaxPackBytes
}

// sortedNames returns the wanted names of a listing in order.
func sortedNames(names []string) []string {
	out := make([]string, 0, len(names))
	for _, n := range names {
		if wantFile(n) {
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}
