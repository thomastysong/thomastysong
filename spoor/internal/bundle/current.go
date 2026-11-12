package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"time"
)

// Info describes the bundle that is current under a destination directory.
type Info struct {
	// Dir holds the bundle's files. It stays in place until the install
	// after next, so a reader may finish loading after a switch.
	Dir string
	// Manifest is read from Dir. Install does not accept it.
	Manifest *Manifest
	// InstalledAt is when this host switched to the bundle.
	InstalledAt time.Time
}

// Current returns the directory and manifest of the active bundle. ok is
// false when nothing usable is installed, whatever the reason; callers then
// run on the content embedded in the binary. Installed reports the reason.
//
// It reads two small files and hashes nothing, so it is cheap enough for a
// hook process to call on every invocation.
func Current(destDir string) (dir string, m *Manifest, ok bool) {
	info, err := Installed(destDir)
	if err != nil {
		return "", nil, false
	}
	return info.Dir, info.Manifest, true
}

// Installed is Current with a reason: ErrNotInstalled when there is no
// bundle, ErrInsecure when the destination could have been modified by
// another user, ErrCorrupt when the pointer or its target cannot be read
// back.
func Installed(destDir string) (info *Info, err error) {
	defer func() {
		if r := recover(); r != nil {
			info, err = nil, recovered(r)
		}
	}()
	if destDir == "" {
		return nil, ErrNotInstalled
	}
	fi, err := os.Stat(destDir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, ErrNotInstalled
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("%w: %s is not a directory", ErrCorrupt, destDir)
	}
	if err := checkOwner(destDir, fi); err != nil {
		return nil, err
	}
	pt, err := readPointer(destDir)
	if err != nil {
		return nil, err
	}
	dir := filepath.Join(destDir, pt.Dir)
	m, err := readInstalledManifest(dir, pt.Version)
	if err != nil {
		return nil, err
	}
	return &Info{Dir: dir, Manifest: m, InstalledAt: pt.Installed}, nil
}

// Audit re-hashes every file of the current bundle against its manifest and
// looks for files the manifest does not list. It detects disk corruption and
// modifications that did not also rewrite manifest.json; it is not a
// signature check. Run it at start-up and from diagnostics, not per event.
func Audit(destDir string) (info *Info, err error) {
	defer func() {
		if r := recover(); r != nil {
			info, err = nil, recovered(r)
		}
	}()
	info, err = Installed(destDir)
	if err != nil {
		return nil, err
	}
	if err := auditDir(info.Dir, info.Manifest); err != nil {
		return nil, err
	}
	return info, nil
}

// ReadFile returns the bytes of one content file of an installed bundle
// after checking them against the manifest. dir and m are the values Current
// returned. It fails with an error matching fs.ErrNotExist when the bundle
// does not carry name, and with ErrMismatch when the file on disk is not the
// one that was installed.
func ReadFile(dir string, m *Manifest, name string) (data []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			data, err = nil, recovered(r)
		}
	}()
	if m == nil {
		return nil, errors.New("bundle: nil manifest")
	}
	want, ok := m.Files[name]
	if !ok {
		return nil, fmt.Errorf("bundle: %s is not part of bundle version %d: %w", quote(name), m.Version, fs.ErrNotExist)
	}
	if err := checkName(name); err != nil {
		return nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	defer root.Close()
	data, sum, err := readHashed(root, name, MaxBytes)
	if err != nil {
		return nil, err
	}
	if sum != want {
		return nil, fmt.Errorf("%w: %s was modified after it was installed", ErrMismatch, quote(name))
	}
	return data, nil
}

// readHashed reads a regular file inside root, refusing symlinks, and
// returns its bytes and hex SHA-256.
func readHashed(root *os.Root, name string, limit int64) ([]byte, string, error) {
	native := filepath.FromSlash(name)
	li, err := root.Lstat(native)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %s: %v", ErrMismatch, quote(name), pathless(err))
	}
	if !li.Mode().IsRegular() {
		return nil, "", fmt.Errorf("%w: %s is not a regular file", ErrMismatch, quote(name))
	}
	f, err := root.Open(native)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %s: %v", ErrMismatch, quote(name), pathless(err))
	}
	defer f.Close()
	// The file is checked again on the open handle: the name could have
	// been swapped between Lstat and Open.
	if fi, err := f.Stat(); err != nil || !os.SameFile(li, fi) {
		return nil, "", fmt.Errorf("%w: %s changed while it was read", ErrMismatch, quote(name))
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, "", fmt.Errorf("%w: %s: %v", ErrMismatch, quote(name), pathless(err))
	}
	if int64(len(data)) > limit {
		return nil, "", fmt.Errorf("%w: %s is larger than the bundle limit", ErrMismatch, quote(name))
	}
	sum := sha256.Sum256(data)
	return data, hex.EncodeToString(sum[:]), nil
}

// auditDir compares a version directory with its manifest in both
// directions: every listed file intact, nothing else present.
func auditDir(dir string, m *Manifest) error {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCorrupt, pathless(err))
	}
	defer root.Close()

	left := int64(MaxBytes)
	for _, name := range m.Paths() {
		data, sum, err := readHashed(root, name, left)
		if err != nil {
			return err
		}
		left -= int64(len(data))
		if sum != m.Files[name] {
			return fmt.Errorf("%w: %s was modified after it was installed", ErrMismatch, quote(name))
		}
	}
	// A loader that globs rules/*.yaml would pick up a planted file, so an
	// unlisted entry is a finding even though ReadFile would never serve it.
	expect := map[string]bool{manifestName: true}
	for name := range m.Files {
		expect[name] = true
		if d := path.Dir(name); d != "." {
			expect[d] = true
		}
	}
	if err := noExtras(root, ".", expect); err != nil {
		return err
	}
	for d := range contentDirs {
		if expect[d] {
			if err := noExtras(root, d, expect); err != nil {
				return err
			}
		}
	}
	return nil
}

func noExtras(root *os.Root, dir string, expect map[string]bool) error {
	f, err := root.Open(dir)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrCorrupt, pathless(err))
	}
	defer f.Close()
	// One entry more than a bundle can hold is enough to know it is wrong.
	entries, err := f.ReadDir(MaxFiles + 8)
	if err != nil && err != io.EOF {
		return fmt.Errorf("%w: %v", ErrCorrupt, pathless(err))
	}
	for _, e := range entries {
		name := e.Name()
		if dir != "." {
			name = dir + "/" + name
		}
		if !expect[name] {
			return fmt.Errorf("%w: %s is not listed in the manifest", ErrMismatch, quote(name))
		}
	}
	return nil
}

// readPointer loads and validates the "current" file. The directory it
// names must be exactly v<version>: the pointer can never direct a reader
// outside the destination, whatever was written into it.
func readPointer(destDir string) (*pointer, error) {
	b, err := readRegular(filepath.Join(destDir, pointerName), maxPointerBytes)
	// On Windows the pointer is briefly inaccessible while an installer
	// replaces it.
	for i := 0; runtime.GOOS == "windows" && err != nil && !errors.Is(err, fs.ErrNotExist) && i < 5; i++ {
		time.Sleep(10 * time.Millisecond)
		b, err = readRegular(filepath.Join(destDir, pointerName), maxPointerBytes)
	}
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return nil, ErrNotInstalled
	case errors.Is(err, ErrInsecure):
		return nil, err
	case err != nil:
		return nil, fmt.Errorf("%w: pointer: %v", ErrCorrupt, pathless(err))
	}
	var pt pointer
	if err := json.Unmarshal(b, &pt); err != nil {
		return nil, fmt.Errorf("%w: pointer is not valid JSON", ErrCorrupt)
	}
	if pt.Version == 0 || pt.Dir != versionDir(pt.Version) {
		return nil, fmt.Errorf("%w: pointer does not name a version directory", ErrCorrupt)
	}
	return &pt, nil
}

// readInstalledManifest loads manifest.json from a version directory and
// checks that it is the manifest of that version.
func readInstalledManifest(dir string, version uint64) (*Manifest, error) {
	li, err := os.Lstat(dir)
	if err != nil {
		return nil, fmt.Errorf("%w: version directory: %v", ErrCorrupt, pathless(err))
	}
	if !li.IsDir() {
		return nil, fmt.Errorf("%w: %s is not a directory", ErrCorrupt, filepath.Base(dir))
	}
	if err := checkOwner(dir, li); err != nil {
		return nil, err
	}
	b, err := readRegular(filepath.Join(dir, manifestName), maxManifestBytes)
	if errors.Is(err, ErrInsecure) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("%w: manifest: %v", ErrCorrupt, pathless(err))
	}
	m, err := parseManifest(b)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCorrupt, err)
	}
	if m.Version != version {
		return nil, fmt.Errorf("%w: %s holds the manifest of version %d", ErrCorrupt, filepath.Base(dir), m.Version)
	}
	return m, nil
}

// readRegular reads a small file that must be a regular file (not a
// symlink) with safe ownership.
func readRegular(name string, limit int64) ([]byte, error) {
	li, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !li.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular file", filepath.Base(name))
	}
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !os.SameFile(li, fi) {
		return nil, fmt.Errorf("%s changed while it was read", filepath.Base(name))
	}
	if err := checkOwner(name, fi); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than %d bytes", filepath.Base(name), limit)
	}
	return b, nil
}

// pathless strips the path from an *fs.PathError: the destination is known
// to the caller, and error text ends up in records that leave the host.
func pathless(err error) error {
	var pe *fs.PathError
	if errors.As(err, &pe) {
		return pe.Err
	}
	return err
}
