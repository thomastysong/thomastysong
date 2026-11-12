package hookinstall

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/thomastysong/spoor/internal/event"
)

// ErrChanged is returned when a file no longer holds the bytes its plan
// was computed from. Another program (the agent itself, an administrator,
// a second installer) wrote it in between; the plan must be recomputed.
var ErrChanged = errors.New("the file changed after the plan was made")

// Apply carries out plans. Plans with Action unchanged or unsupported are
// skipped. Each file is replaced atomically (a temporary file in the same
// directory, then a rename) after its current bytes are compared with
// Plan.Before, and the previous content is kept as
// <name>.spoor-<UTC timestamp>.bak beside it. Missing parent directories
// are created with mode 0755; a new file gets mode 0644 and an existing one
// keeps its mode (a settings file may hold credentials, so it is never
// widened). Managed files and the directories leading to them are made
// root/Administrators-owned and not group- or world-writable. Nothing is
// written through a symbolic link.
//
// A failure on one file does not stop the others: they are independent
// agents. The returned error joins one error per failed plan.
func Apply(plans []Plan) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New("hookinstall: internal error while applying plans")
		}
	}()
	now := time.Now().UTC()
	var errs []error
	for i := range plans {
		p := &plans[i]
		switch p.Action {
		case ActionUnchanged, ActionUnsupported:
			continue
		case ActionCreate, ActionMerge, ActionAppend, ActionRemove:
		default:
			errs = append(errs, fmt.Errorf("hookinstall: %s: unknown action %q", p.AgentID, safeName(p.Action)))
			continue
		}
		if err := applyOne(p, now); err != nil {
			errs = append(errs, fmt.Errorf("hookinstall: %s %s: %w", p.AgentID, p.Path, err))
		}
	}
	return errors.Join(errs...)
}

func applyOne(p *Plan, now time.Time) error {
	if p.Path == "" || len(p.Path) > maxPathLen+len(p.root) || hasControl(p.Path) {
		return errors.New("malformed path")
	}
	path := filepath.Clean(p.Path)
	dir, name := filepath.Split(path)
	if name == "" || name == "." || name == ".." {
		return errors.New("path does not name a file")
	}
	managed := p.Scope == event.ScopeManaged || p.Scope == event.ScopeSystem
	if p.Action != ActionRemove {
		if err := checkContent(name, p.After, p.Before); err != nil {
			return err
		}
	}
	r, err := openDirChain(dir, p.root, dirPolicy{create: p.Action != ActionRemove, managed: managed})
	if err != nil {
		return err
	}
	defer r.Close()

	cur, fi, err := readIn(r, name)
	if err != nil {
		return err
	}
	exists := fi != nil
	if exists && !managed && os.Geteuid() == 0 {
		if di, err := r.Stat("."); err == nil {
			if uid, bad := thirdOwner(fi, di); bad {
				return fmt.Errorf("owned by uid %d, not by the owner of its directory", uid)
			}
		}
	}
	switch {
	case p.Action == ActionCreate && exists:
		return ErrChanged
	case p.Action != ActionCreate && (!exists || !bytes.Equal(cur, p.Before)):
		return ErrChanged
	}

	ts := now.Format("20060102T150405Z")
	if p.Action == ActionRemove {
		// Renaming the file to its backup name removes it and keeps the
		// bytes in one step.
		bak, err := freeName(r, name+"."+sensorName+"-"+ts, ".bak")
		if err != nil {
			return err
		}
		if err := r.Rename(name, bak); err != nil {
			return fmt.Errorf("cannot remove (%s)", errClass(err))
		}
		syncDir(r)
		return nil
	}

	mode := os.FileMode(0o644)
	var uid, gid int
	owned := false
	if exists {
		mode = fi.Mode().Perm()
		uid, gid, owned = ownerIDs(fi)
	} else if st, err := r.Stat("."); err == nil {
		uid, gid, owned = ownerIDs(st)
	}
	if managed {
		mode &^= 0o022
		owned = false // root keeps managed files
	}

	tmp, err := writeTemp(r, name, p.After, mode)
	if err != nil {
		return err
	}
	cleanup := func() { _ = r.Remove(tmp) }
	if owned {
		if err := giveTo(r, tmp, uid, gid); err != nil {
			cleanup()
			return fmt.Errorf("cannot set the owner (%s)", errClass(err))
		}
	}
	if exists {
		if err := backup(r, name, cur, mode, owned, uid, gid, ts); err != nil {
			cleanup()
			return err
		}
	}
	// The rename is the commit point: before it the old file is intact,
	// after it the new one is complete.
	if err := r.Rename(tmp, name); err != nil {
		cleanup()
		return fmt.Errorf("cannot replace the file (%s)", errClass(err))
	}
	if managed {
		if err := hardenIn(r, name, false); err != nil {
			return fmt.Errorf("written, but could not be secured (%s)", errClass(err))
		}
	}
	syncDir(r)
	return nil
}

// readIn reads name in r without following a link and without keeping the
// handle. fi is nil when the file does not exist.
func readIn(r *os.Root, name string) ([]byte, os.FileInfo, error) {
	li, err := r.Lstat(name)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil
	}
	if err != nil {
		return nil, nil, fmt.Errorf("cannot inspect the file (%s)", errClass(err))
	}
	switch {
	case li.Mode()&os.ModeSymlink != 0:
		return nil, nil, ErrSymlink
	case !li.Mode().IsRegular():
		return nil, nil, errors.New("not a regular file")
	case li.Size() > maxFileSize:
		return nil, nil, errors.New("larger than 4 MiB")
	}
	f, err := r.OpenFile(name, readFlags, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("cannot open the file (%s)", errClass(err))
	}
	defer f.Close()
	st := readOpen(f, li, fileState{exists: true})
	if st.refused != "" {
		return nil, nil, errors.New(st.refused)
	}
	return st.data, li, nil
}

// checkContent refuses to write bytes the agent could not load: Claude
// Code refuses to start on an invalid managed settings file, Copilot
// rejects a whole hook file over a structural error. Plans made by this
// package always pass; the check is for plans that were edited or
// assembled elsewhere.
func checkContent(name string, after, before []byte) error {
	if len(after) == 0 {
		return errors.New("refusing to write an empty file")
	}
	if len(after) > maxFileSize {
		return errors.New("new content is larger than 4 MiB")
	}
	switch strings.ToLower(filepath.Ext(name)) {
	case ".json":
		d, err := parseJSON(after)
		if err != nil {
			return fmt.Errorf("new content is not valid JSON: %w", err)
		}
		if d.comments || d.trailingCommas {
			old, err := parseJSON(before)
			if err != nil || !(old.comments || old.trailingCommas) {
				return errors.New("new content adds JSONC syntax to a strict JSON file")
			}
		}
	case ".toml":
		if _, err := parseTOML(after); err != nil {
			return fmt.Errorf("new content is %w", err)
		}
	default:
		return errors.New("only .json and .toml hook files are written")
	}
	return nil
}

// writeTemp writes data to a new hidden file beside name and returns its
// name. O_EXCL and a random suffix keep two installers from sharing it.
func writeTemp(r *os.Root, name string, data []byte, mode os.FileMode) (string, error) {
	var rnd [8]byte
	if _, err := io.ReadFull(rand.Reader, rnd[:]); err != nil {
		return "", errors.New("no randomness for a temporary name")
	}
	tmp := "." + name + "." + sensorName + "-" + hex.EncodeToString(rnd[:]) + ".tmp"
	f, err := r.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return "", fmt.Errorf("cannot create a temporary file (%s)", errClass(err))
	}
	_, werr := f.Write(data)
	serr := f.Sync()
	cerr := f.Close()
	if werr == nil {
		werr = serr
	}
	if werr == nil {
		werr = cerr
	}
	if werr == nil {
		// The umask may have narrowed the mode given to OpenFile.
		werr = r.Chmod(tmp, mode)
	}
	if werr != nil {
		_ = r.Remove(tmp)
		return "", fmt.Errorf("cannot write a temporary file (%s)", errClass(werr))
	}
	return tmp, nil
}

// backup keeps the previous bytes beside the file. The suffix does not end
// in .json, so drop-in directories that load every *.json (Claude Code
// managed-settings.d, Copilot policy.d and hooks) ignore it.
func backup(r *os.Root, name string, data []byte, mode os.FileMode, owned bool, uid, gid int, ts string) error {
	bak, err := freeName(r, name+"."+sensorName+"-"+ts, ".bak")
	if err != nil {
		return err
	}
	f, err := r.OpenFile(bak, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return fmt.Errorf("cannot create the backup (%s)", errClass(err))
	}
	_, werr := f.Write(data)
	if err := f.Close(); werr == nil {
		werr = err
	}
	if werr == nil {
		werr = r.Chmod(bak, mode)
	}
	if werr == nil && owned {
		werr = giveTo(r, bak, uid, gid)
	}
	if werr != nil {
		_ = r.Remove(bak)
		return fmt.Errorf("cannot write the backup (%s)", errClass(werr))
	}
	return nil
}

// freeName returns prefix+suffix, or prefix-N+suffix when that is taken.
func freeName(r *os.Root, prefix, suffix string) (string, error) {
	for i := 0; i < 100; i++ {
		n := prefix + suffix
		if i > 0 {
			n = fmt.Sprintf("%s-%d%s", prefix, i, suffix)
		}
		if _, err := r.Lstat(n); errors.Is(err, fs.ErrNotExist) {
			return n, nil
		}
	}
	return "", errors.New("no free backup name")
}

// syncDir makes the rename durable where the platform allows it.
func syncDir(r *os.Root) {
	if d, err := r.Open("."); err == nil {
		_ = d.Sync()
		_ = d.Close()
	}
}
