package bundle

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const (
	pointerName     = "current"
	pointerTmp      = "current.tmp"
	stageSuffix     = ".tmp"
	maxPointerBytes = 512
	defaultLockWait = 30 * time.Second
	staleStateAge   = 10 * time.Minute
	dirMode         = 0o755
	fileMode        = 0o644
)

// InstallOptions tune InstallWith. The zero value is what Install uses.
type InstallOptions struct {
	// Validate, when set, is called with the staging directory holding the
	// fully extracted bundle and a copy of its manifest, before anything
	// becomes current. An error (or a panic) aborts the install: the
	// previous bundle stays active and the error is returned wrapped in
	// ErrRejected. Use it to parse rule packs and catalog overlays so that a
	// correctly signed but broken bundle never replaces a working one.
	//
	// dir is renamed right after Validate returns; do not keep it.
	Validate func(dir string, m *Manifest) error
	// LockTimeout bounds the wait for another installer on the same
	// destination. Zero means 30 seconds.
	LockTimeout time.Duration
}

// Install makes a verified bundle the current one under destDir.
//
// m must be the value Verify returned for tarball; anything else is refused
// with ErrNotVerified. The archive is extracted to <destDir>/v<version>.tmp,
// synced, renamed to <destDir>/v<version>, and only then does the "current"
// pointer file move, by an atomic rename. A crash at any point leaves the
// previous bundle current. Installers on the same destination are
// serialised, also across processes.
//
// A version that is not higher than the installed one is refused with a
// *VersionError matching ErrDowngrade, or ErrAlreadyInstalled when the
// offered bundle is exactly the installed one and its files are intact.
func Install(tarball []byte, m *Manifest, destDir string) error {
	return InstallWith(tarball, m, destDir, InstallOptions{})
}

// InstallWith is Install with options.
func InstallWith(tarball []byte, m *Manifest, destDir string, o InstallOptions) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = recovered(r)
		}
	}()
	if m == nil || !m.verified || sha256.Sum256(tarball) != m.sum {
		return ErrNotVerified
	}
	if destDir == "" {
		return errors.New("bundle: empty destination directory")
	}
	// The caller could have changed m's exported fields since Verify. The
	// bytes are what was signed, so everything is derived from them again.
	trusted, err := checkArchive(tarball)
	if err != nil {
		return err
	}
	if err := prepareDest(destDir); err != nil {
		return err
	}
	wait := o.LockTimeout
	if wait <= 0 {
		wait = defaultLockWait
	}
	release, err := acquire(filepath.Join(destDir, lockName), wait)
	if err != nil {
		return err
	}
	defer release()
	return installLocked(tarball, trusted, destDir, o.Validate)
}

// prepareDest creates the destination when it is missing and refuses one
// that another user could write.
func prepareDest(destDir string) error {
	_, statErr := os.Stat(destDir)
	created := errors.Is(statErr, os.ErrNotExist)
	if err := os.MkdirAll(destDir, dirMode); err != nil {
		return fmt.Errorf("bundle: create destination: %w", err)
	}
	if created {
		// The umask may have removed the read bits hook processes need.
		if err := os.Chmod(destDir, dirMode); err != nil {
			return fmt.Errorf("bundle: create destination: %w", err)
		}
	}
	fi, err := os.Stat(destDir)
	if err != nil {
		return fmt.Errorf("bundle: destination: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: %s is not a directory", ErrCorrupt, destDir)
	}
	return checkOwner(destDir, fi)
}

func installLocked(tarball []byte, m *Manifest, destDir string, validate func(string, *Manifest) error) error {
	lay, err := scanLayout(destDir)
	if err != nil {
		return err
	}
	existing := lay.complete[m.Version]
	switch {
	case m.Version < lay.pointed, m.Version < lay.highest:
		return &VersionError{Installed: max(lay.pointed, lay.highest), Offered: m.Version}
	case existing != nil && !existing.Equal(m):
		// A version number names one content on this host, for good.
		return &VersionError{Installed: m.Version, Offered: m.Version}
	case existing != nil && m.Version == lay.pointed:
		if auditDir(filepath.Join(destDir, versionDir(m.Version)), existing) == nil {
			return &VersionError{Installed: m.Version, Offered: m.Version, Identical: true}
		}
		// Same bundle, but the installed files are damaged: lay it down
		// again rather than staying broken until a higher version ships.
	}
	// Reaching this point with a directory for m.Version already present
	// means that directory is not serving as current: a crash left it
	// behind before the pointer moved, the pointer is damaged, or the audit
	// above failed. It is replaced by the same content.

	for _, name := range lay.stale {
		if err := os.RemoveAll(filepath.Join(destDir, name)); err != nil {
			return fmt.Errorf("bundle: remove leftover %s: %w", name, err)
		}
	}
	final := filepath.Join(destDir, versionDir(m.Version))
	stage := final + stageSuffix
	if err := extract(tarball, m, stage); err != nil {
		os.RemoveAll(stage)
		return err
	}
	if validate != nil {
		if err := runValidator(validate, stage, m); err != nil {
			os.RemoveAll(stage)
			return fmt.Errorf("%w: %w", ErrRejected, err)
		}
	}
	if err := os.RemoveAll(final); err != nil {
		os.RemoveAll(stage)
		return fmt.Errorf("bundle: replace %s: %w", versionDir(m.Version), err)
	}
	if err := renameRetry(stage, final); err != nil {
		os.RemoveAll(stage)
		return fmt.Errorf("bundle: activate %s: %w", versionDir(m.Version), err)
	}
	syncDir(destDir)
	pt := pointer{Version: m.Version, Dir: versionDir(m.Version), Installed: time.Now().UTC().Truncate(time.Second)}
	if err := writePointer(destDir, pt); err != nil {
		return err
	}

	// Keep the directory that was current until now: a reader that resolved
	// the pointer a moment ago may still be loading from it. Everything
	// older goes. Failures are ignored (on Windows an open file blocks
	// deletion); the next install tries again.
	keep := map[string]bool{pt.Dir: true}
	if lay.pointed != 0 {
		keep[versionDir(lay.pointed)] = true
	}
	for _, name := range lay.dirs {
		if !keep[name] {
			os.RemoveAll(filepath.Join(destDir, name))
		}
	}
	return nil
}

func runValidator(fn func(string, *Manifest) error, dir string, m *Manifest) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("validator panicked: %v", r)
		}
	}()
	return fn(dir, m.clone())
}

// extract writes the archive into a new staging directory, checking each
// file against the manifest as it is written. It goes through os.Root, which
// refuses any path that would leave the staging directory, so the name
// checks in walk are not the only thing between an archive and the rest of
// the filesystem.
func extract(tarball []byte, m *Manifest, stage string) error {
	if err := os.Mkdir(stage, dirMode); err != nil {
		return fmt.Errorf("bundle: stage: %w", err)
	}
	if err := os.Chmod(stage, dirMode); err != nil {
		return fmt.Errorf("bundle: stage: %w", err)
	}
	root, err := os.OpenRoot(stage)
	if err != nil {
		return fmt.Errorf("bundle: stage: %w", err)
	}
	defer root.Close()

	made := map[string]bool{}
	err = walk(tarball, func(name string, _ int64, r io.Reader) error {
		if dir := path.Dir(name); dir != "." && !made[dir] {
			if err := root.Mkdir(dir, dirMode); err != nil {
				return fmt.Errorf("bundle: stage: %w", err)
			}
			if err := root.Chmod(dir, dirMode); err != nil {
				return fmt.Errorf("bundle: stage: %w", err)
			}
			made[dir] = true
		}
		sum, err := writeFile(root, name, r)
		if err != nil {
			return err
		}
		if name != manifestName && sum != m.Files[name] {
			return fmt.Errorf("%w: %s", ErrMismatch, quote(name))
		}
		return nil
	})
	if err != nil {
		return err
	}
	for dir := range made {
		syncDir(filepath.Join(stage, dir))
	}
	syncDir(stage)
	return nil
}

// writeFile creates one file exclusively (never through an existing name),
// fixes its mode against the umask, and syncs it before the directory is
// renamed into place.
func writeFile(root *os.Root, name string, r io.Reader) (sum string, err error) {
	f, err := root.OpenFile(filepath.FromSlash(name), os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
	if err != nil {
		return "", fmt.Errorf("bundle: stage: %w", err)
	}
	defer func() {
		if cerr := f.Close(); cerr != nil && err == nil {
			err = fmt.Errorf("bundle: stage: %w", cerr)
		}
	}()
	h := sha256.New()
	src := &trackedReader{r: r}
	if _, err := io.Copy(io.MultiWriter(f, h), src); err != nil {
		if src.err != nil {
			return "", readError(src.err)
		}
		return "", fmt.Errorf("bundle: stage: %w", err)
	}
	// Windows has no mode bits to fix; its Chmod only toggles read-only.
	if err := f.Chmod(fileMode); err != nil && runtime.GOOS != "windows" {
		return "", fmt.Errorf("bundle: stage: %w", err)
	}
	if err := f.Sync(); err != nil {
		return "", fmt.Errorf("bundle: stage: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// trackedReader remembers a read failure, so a failed copy can be blamed on
// the archive or on the disk.
type trackedReader struct {
	r   io.Reader
	err error
}

func (t *trackedReader) Read(p []byte) (int, error) {
	n, err := t.r.Read(p)
	if err != nil && err != io.EOF {
		t.err = err
	}
	return n, err
}

// pointer is the content of the "current" file.
type pointer struct {
	Version   uint64    `json:"version"`
	Dir       string    `json:"dir"`
	Installed time.Time `json:"installed"`
}

func versionDir(v uint64) string { return "v" + strconv.FormatUint(v, 10) }

// parseVersionDir accepts only the exact name versionDir produces, so that
// "v07" or "v7 " can never alias the directory of version 7.
func parseVersionDir(name string) (uint64, bool) {
	if len(name) < 2 || name[0] != 'v' {
		return 0, false
	}
	v, err := strconv.ParseUint(name[1:], 10, 64)
	if err != nil || v == 0 || versionDir(v) != name {
		return 0, false
	}
	return v, true
}

func writePointer(destDir string, pt pointer) error {
	b, err := json.Marshal(pt)
	if err != nil {
		return fmt.Errorf("bundle: pointer: %w", err)
	}
	tmp := filepath.Join(destDir, pointerTmp)
	os.Remove(tmp)
	f, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, fileMode)
	if err != nil {
		return fmt.Errorf("bundle: pointer: %w", err)
	}
	_, werr := f.Write(append(b, '\n'))
	if cerr := f.Chmod(fileMode); werr == nil && cerr != nil && runtime.GOOS != "windows" {
		werr = cerr
	}
	if serr := f.Sync(); werr == nil {
		werr = serr
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = renameRetry(tmp, filepath.Join(destDir, pointerName))
	}
	if werr != nil {
		os.Remove(tmp)
		return fmt.Errorf("bundle: pointer: %w", werr)
	}
	syncDir(destDir)
	return nil
}

// renameRetry retries on Windows, where a rename fails while a reader or a
// virus scanner has the target or a file inside the source open. Elsewhere
// rename either works or fails for good.
func renameRetry(from, to string) error {
	err := os.Rename(from, to)
	if runtime.GOOS != "windows" {
		return err
	}
	for i := 0; err != nil && i < 40; i++ {
		time.Sleep(25 * time.Millisecond)
		err = os.Rename(from, to)
	}
	return err
}

// syncDir flushes directory entries so a rename survives power loss. It is
// best effort: Windows cannot sync a directory handle, and NTFS journals the
// rename itself.
func syncDir(dir string) {
	if d, err := os.Open(dir); err == nil {
		d.Sync()
		d.Close()
	}
}

func olderThan(e os.DirEntry, age time.Duration) bool {
	info, err := e.Info()
	return err == nil && time.Since(info.ModTime()) > age
}

// layout is what a destination directory holds at the start of an install.
type layout struct {
	pointed  uint64               // version named by the pointer, 0 when missing or damaged
	complete map[uint64]*Manifest // manifests of the version directories that can be read back
	highest  uint64               // highest version in complete
	dirs     []string             // every v<N> entry
	stale    []string             // staging leftovers of interrupted installs
}

func scanLayout(destDir string) (*layout, error) {
	lay := &layout{complete: make(map[uint64]*Manifest)}
	if pt, err := readPointer(destDir); err == nil {
		lay.pointed = pt.Version
	} else if errors.Is(err, ErrInsecure) {
		return nil, err
	}
	entries, err := os.ReadDir(destDir)
	if err != nil {
		return nil, fmt.Errorf("bundle: destination: %w", err)
	}
	for _, e := range entries {
		name := e.Name()
		if name == pointerTmp {
			lay.stale = append(lay.stale, name)
			continue
		}
		if base, ok := strings.CutSuffix(name, stageSuffix); ok {
			_, isVersion := parseVersionDir(base)
			// Pull writes its state through pull.json.<random>.tmp without
			// holding the install lock, so only an old one is a leftover.
			if isVersion || (strings.HasPrefix(base, stateName+".") && olderThan(e, staleStateAge)) {
				lay.stale = append(lay.stale, name)
			}
			continue
		}
		v, ok := parseVersionDir(name)
		if !ok {
			continue
		}
		lay.dirs = append(lay.dirs, name)
		// A version directory only exists once its staging directory was
		// completely written and renamed, so a readable manifest in it
		// marks a bundle that was fully verified on this host.
		m, err := readInstalledManifest(filepath.Join(destDir, name), v)
		if err != nil {
			continue
		}
		lay.complete[v] = m
		if v > lay.highest {
			lay.highest = v
		}
	}
	return lay, nil
}
