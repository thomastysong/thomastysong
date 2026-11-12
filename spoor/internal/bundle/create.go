package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// maxSourceEntries bounds the walk of a source tree, so pointing Create at
// the wrong directory fails quickly instead of crawling a disk.
const maxSourceEntries = 20000

// CreateOptions are the publisher-chosen fields of a bundle.
type CreateOptions struct {
	// Version must be higher than every version published before.
	Version uint64
	// Created defaults to the current time. Set it (for example from
	// SOURCE_DATE_EPOCH) to rebuild the same archive bytes later.
	Created time.Time
	// Note is free text shown to operators, at most 1024 bytes.
	Note string
}

// Create packs the bundle content found under srcDir (rules/*.yaml,
// catalog/*.yaml, lists.yaml, suppressions.yaml) together with a generated
// manifest.json and writes the gzip-compressed tar archive to w. Everything
// else under srcDir is ignored, so srcDir may be a repository root.
//
// The detached signature is not written here: the caller signs the bytes it
// received with Sign and publishes the result as <name>.sig. Create uses
// priv to prove, before writing a single byte, that the archive passes the
// same Verify the endpoints run; a bundle every sensor would refuse is an
// error at build time, not a fleet that silently stops updating.
func Create(srcDir string, version uint64, priv ed25519.PrivateKey, w io.Writer) error {
	_, err := CreateWith(srcDir, CreateOptions{Version: version}, priv, w)
	return err
}

// CreateWith is Create with a creation time and a note, and returns the
// manifest of the archive it wrote.
//
// It refuses to guess: a symlink where content is expected (in a CI checkout
// it could point at a secret and publish it), a *.yml file or a YAML file in
// a nested directory under rules/ or catalog/ (the sensor would never load
// it), and a source tree with no content at all (publishing it would wipe
// the fleet's updates) are errors, not omissions.
func CreateWith(srcDir string, o CreateOptions, priv ed25519.PrivateKey, w io.Writer) (m *Manifest, err error) {
	defer func() {
		if r := recover(); r != nil {
			m, err = nil, recovered(r)
		}
	}()
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: private key has the wrong length", ErrKey)
	}
	if w == nil {
		return nil, errors.New("bundle: nil writer")
	}
	created := o.Created
	if created.IsZero() {
		created = time.Now()
	}
	m = &Manifest{
		Version: o.Version,
		Created: created.UTC().Truncate(time.Second),
		Note:    o.Note,
		Files:   map[string]string{},
	}
	files, err := collect(srcDir)
	if err != nil {
		return nil, err
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("%w: no bundle content under %s (expected rules/*.yaml, catalog/*.yaml, lists.yaml or suppressions.yaml)", ErrManifest, srcDir)
	}
	for name, data := range files {
		sum := sha256.Sum256(data)
		m.Files[name] = hex.EncodeToString(sum[:])
	}
	if err := m.validate(); err != nil {
		return nil, err
	}
	tarball, err := pack(m, files)
	if err != nil {
		return nil, err
	}
	pub, _ := priv.Public().(ed25519.PublicKey)
	checked, err := Verify(tarball, Sign(tarball, priv), []ed25519.PublicKey{pub})
	if err != nil {
		return nil, fmt.Errorf("bundle: the archive built from %s would be refused by sensors: %w", srcDir, err)
	}
	if _, err := w.Write(tarball); err != nil {
		return nil, fmt.Errorf("bundle: write archive: %w", err)
	}
	return checked.clone(), nil
}

// pack writes manifest.json first and the content in sorted order, with
// fixed ownership, mode and time and an empty gzip header, so the bytes
// depend only on the input.
func pack(m *Manifest, files map[string][]byte) ([]byte, error) {
	manifest, err := m.encode()
	if err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return nil, err
	}
	tw := tar.NewWriter(zw)
	add := func(name string, data []byte) error {
		// FormatUSTAR makes the writer fail rather than fall back to the
		// extended headers Verify refuses.
		hdr := &tar.Header{
			Typeflag: tar.TypeReg,
			Name:     name,
			Mode:     0o644,
			Size:     int64(len(data)),
			ModTime:  m.Created,
			Format:   tar.FormatUSTAR,
		}
		if err := tw.WriteHeader(hdr); err != nil {
			return fmt.Errorf("bundle: pack %s: %w", name, err)
		}
		_, err := tw.Write(data)
		return err
	}
	if err := add(manifestName, manifest); err != nil {
		return nil, err
	}
	for _, name := range m.Paths() {
		if err := add(name, files[name]); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := zw.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// collect reads the allow-listed content under srcDir. All access goes
// through os.Root, so nothing outside srcDir can be read even if the tree
// changes while it is being walked.
func collect(srcDir string) (map[string][]byte, error) {
	root, err := os.OpenRoot(srcDir)
	if err != nil {
		return nil, fmt.Errorf("bundle: open source directory: %w", err)
	}
	defer root.Close()

	c := &collector{root: root, files: make(map[string][]byte)}
	top := make([]string, 0, len(topLevel))
	for name := range topLevel {
		top = append(top, name)
	}
	sort.Strings(top)
	for _, name := range top {
		if err := c.topFile(name); err != nil {
			return nil, err
		}
	}
	dirs := make([]string, 0, len(contentDirs))
	for dir := range contentDirs {
		dirs = append(dirs, dir)
	}
	sort.Strings(dirs)
	for _, dir := range dirs {
		if err := c.contentDir(dir); err != nil {
			return nil, err
		}
	}
	return c.files, nil
}

type collector struct {
	root    *os.Root
	files   map[string][]byte
	total   int64
	visited int
}

func (c *collector) topFile(name string) error {
	// A lists.yml next to no lists.yaml is almost certainly a typo that
	// would publish a bundle without the list.
	alt := strings.TrimSuffix(name, contentExt) + ".yml"
	if _, err := c.root.Lstat(alt); err == nil {
		return fmt.Errorf("%w: %s: rename it to %s (only *%s is loaded)", ErrNotAllowed, alt, name, contentExt)
	}
	fi, err := c.root.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("bundle: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s in the source directory", ErrNotRegular, name)
	}
	return c.read(name)
}

func (c *collector) contentDir(dir string) error {
	fi, err := c.root.Lstat(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("bundle: %w", err)
	}
	if !fi.IsDir() {
		return fmt.Errorf("%w: %s in the source directory is not a directory", ErrNotRegular, dir)
	}
	return fs.WalkDir(c.root.FS(), dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return fmt.Errorf("bundle: %w", err)
		}
		if p == dir {
			return nil
		}
		if c.visited++; c.visited > maxSourceEntries {
			return fmt.Errorf("%w: more than %d entries under the source directory", ErrTooLarge, maxSourceEntries)
		}
		name := d.Name()
		if d.IsDir() {
			// Hidden directories and Go-style test fixtures are not
			// content and may legitimately hold YAML.
			if strings.HasPrefix(name, ".") || name == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		ext := path.Ext(name)
		switch {
		case strings.EqualFold(ext, ".yml"), strings.EqualFold(ext, contentExt) && ext != contentExt:
			return fmt.Errorf("%w: %s: rename it to end in %s (nothing else is loaded)", ErrNotAllowed, p, contentExt)
		case ext != contentExt:
			return nil // README, .gitkeep and the like
		case path.Dir(p) != dir:
			return fmt.Errorf("%w: %s: content files must sit directly in %s/ (nested directories are not loaded)", ErrNotAllowed, p, dir)
		case !d.Type().IsRegular():
			return fmt.Errorf("%w: %s in the source directory", ErrNotRegular, p)
		}
		if err := checkName(p); err != nil {
			return err
		}
		return c.read(p)
	})
}

// read loads one file, checking on the open handle that it is still the
// regular file the walk saw and that the bundle stays within its limits.
func (c *collector) read(name string) error {
	if len(c.files) >= MaxFiles-1 {
		return fmt.Errorf("%w: more than %d content files", ErrTooLarge, MaxFiles-1)
	}
	f, err := c.root.Open(filepath.FromSlash(name))
	if err != nil {
		return fmt.Errorf("bundle: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return fmt.Errorf("bundle: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("%w: %s in the source directory", ErrNotRegular, name)
	}
	left := MaxBytes - c.total
	data, err := io.ReadAll(io.LimitReader(f, left+1))
	if err != nil {
		return fmt.Errorf("bundle: read %s: %w", name, err)
	}
	if int64(len(data)) > left {
		return fmt.Errorf("%w: content is larger than %d bytes", ErrTooLarge, MaxBytes)
	}
	c.total += int64(len(data))
	c.files[name] = data
	return nil
}
