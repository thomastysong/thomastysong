package catalog

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
)

// LoadOverlay layers the *.yaml and *.yml files of a directory (not
// recursive, in name order) over the catalog. Files use the same schema as
// the embedded data. A product whose id is new is added; a product whose id
// exists is overridden field by field: keys present in the overlay replace
// the shipped values, keys left out keep them. Write "replace: true" in an
// entry to discard the shipped product entirely. ambiguous_names and
// interpreters are added to the shipped lists.
//
// The combined catalog is validated as a whole before it becomes visible;
// on any error the catalog is unchanged. Calling LoadOverlay again layers on
// top of the previous result.
//
// Overlay files are executable policy for a privileged sensor, so the
// directory and each file must be regular (no symlinks) and not
// world-writable.
func (c *Catalog) LoadOverlay(dir string) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("catalog: internal error loading overlay: %v", r)
		}
	}()
	if dir == "" {
		return errors.New("catalog: overlay directory is empty")
	}
	di, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("catalog: overlay: %w", err)
	}
	if di.Mode()&os.ModeSymlink != 0 || !di.IsDir() {
		return fmt.Errorf("catalog: overlay %s: not a directory (symlinks are refused)", dir)
	}
	if worldWritable(di) {
		return fmt.Errorf("catalog: overlay %s: directory is world-writable", dir)
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("catalog: overlay: %w", err)
	}
	var names []string
	for _, e := range ents {
		ext := strings.ToLower(filepath.Ext(e.Name()))
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		// Editors and config management leave dotfiles and backups around.
		if strings.HasPrefix(e.Name(), ".") {
			continue
		}
		names = append(names, e.Name())
	}
	if len(names) > maxOverlayFile {
		return fmt.Errorf("catalog: overlay %s: more than %d files", dir, maxOverlayFile)
	}
	sort.Strings(names)

	base := c.snap.Load()
	st := base.source.copy()
	digest := sha256.New()
	io.WriteString(digest, st.overlay)
	for _, name := range names {
		path := filepath.Join(dir, name)
		b, err := readRegular(path)
		if err != nil {
			return err
		}
		df, err := parseFile(path, b)
		if err != nil {
			return err
		}
		if err := st.add(path, df, true); err != nil {
			return err
		}
		fmt.Fprintf(digest, "%s\x00%d\x00", name, len(b))
		digest.Write(b)
	}
	if len(names) == 0 {
		return nil
	}
	st.overlay = hex.EncodeToString(digest.Sum(nil))[:8]
	snap, err := st.build()
	if err != nil {
		return err
	}
	c.snap.Store(snap)
	return nil
}

// copy duplicates the state deeply enough that adding overlay files to the
// copy cannot disturb the snapshot readers are using.
func (st *state) copy() *state {
	out := &state{
		version:      st.version,
		products:     make([]Product, len(st.products)),
		byID:         make(map[string]int, len(st.byID)),
		ambiguous:    append([]string(nil), st.ambiguous...),
		interpreters: make(map[string]string, len(st.interpreters)),
		overlay:      st.overlay,
	}
	for i := range st.products {
		out.products[i] = st.products[i].clone()
	}
	for k, v := range st.byID {
		out.byID[k] = v
	}
	for k, v := range st.interpreters {
		out.interpreters[k] = v
	}
	return out
}

// readRegular reads a bounded regular file without following a symlink at
// the final path element. Lstat and the descriptor are compared so that
// swapping the file for a link between the two calls is detected.
func readRegular(path string) ([]byte, error) {
	li, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("catalog: overlay: %w", err)
	}
	if !li.Mode().IsRegular() {
		return nil, fmt.Errorf("catalog: overlay %s: not a regular file (symlinks are refused)", path)
	}
	if worldWritable(li) {
		return nil, fmt.Errorf("catalog: overlay %s: file is world-writable", path)
	}
	if li.Size() > maxFileBytes {
		return nil, fmt.Errorf("catalog: overlay %s: file is larger than %d bytes", path, maxFileBytes)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("catalog: overlay: %w", err)
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, fmt.Errorf("catalog: overlay: %w", err)
	}
	if !fi.Mode().IsRegular() || !os.SameFile(li, fi) {
		return nil, fmt.Errorf("catalog: overlay %s: file changed while it was being opened", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("catalog: overlay: %w", err)
	}
	if len(b) > maxFileBytes {
		return nil, fmt.Errorf("catalog: overlay %s: file is larger than %d bytes", path, maxFileBytes)
	}
	return b, nil
}

// worldWritable reports the POSIX "other" write bit. Windows mode bits are
// synthesized by Go and say nothing about the ACL, so the check is skipped
// there; the installer is responsible for the directory ACL.
func worldWritable(fi os.FileInfo) bool {
	if runtime.GOOS == "windows" {
		return false
	}
	return fi.Mode().Perm()&0o002 != 0
}
