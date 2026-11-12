package rules

import (
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"path"
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
		files, err := readEmbedded()
		if err != nil {
			embErr = err
			return
		}
		if c, err := embeddedFS.ReadFile(cacheFileName); err == nil {
			if srcs, err := decodeCache(c, sourceDigest(files)); err == nil {
				if s, err := loadSources(srcs, true); err == nil {
					embSet, embFromCache = s, true
					return
				}
			}
		}
		embSet, embErr = load(files, true)
	})
	if embErr != nil {
		return nil, embErr
	}
	return embSet.clone(), nil
}

// readEmbedded returns the embedded content files: packs/*.yaml and
// lists.yaml.
func readEmbedded() (map[string][]byte, error) {
	files := map[string][]byte{}
	entries, err := fs.ReadDir(embeddedFS, "packs")
	if err != nil {
		return nil, fmt.Errorf("rules: embedded packs: %w", err)
	}
	for _, e := range entries {
		if e.IsDir() || !wantFile(e.Name()) {
			continue
		}
		b, err := embeddedFS.ReadFile(path.Join("packs", e.Name()))
		if err != nil {
			return nil, fmt.Errorf("rules: embedded pack %s: %w", e.Name(), err)
		}
		files["packs/"+e.Name()] = b
	}
	if b, err := embeddedFS.ReadFile("lists.yaml"); err == nil {
		files["lists.yaml"] = b
	}
	return files, nil
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
