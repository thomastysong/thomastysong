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

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// ErrChanged is returned when a file no longer holds the bytes its plan
// was computed from. Another program (the agent itself, an administrator,
// a second installer) wrote it in between; the plan must be recomputed.
var ErrChanged = errors.New("the file changed after the plan was made")

// Apply carries out plans. Plans with Action unchanged or unsupported are
// skipped. Each file is replaced atomically (a temporary file in the same
// directory, then a rename) after its current bytes are compared with
// Plan.Before, and the previous content is kept as
// <name>.hawkbell-<UTC timestamp>.bak beside it. Missing parent directories
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
	pol := dirPolicy{create: p.Action != ActionRemove, managed: managed}
	var repairs []error
	if managed && p.Action != ActionRemove {
		pol.loads, pol.skip, pol.problems = p.loads, name, &repairs
	}
	r, err := openDirChain(dir, p.root, pol)
	if err != nil {
		return err
	}
	defer r.Close()

	cur, fi, dirInfo, err := readIn(r, name)
	if err != nil {
		return err
	}
	exists := fi != nil
	if exists && !managed && os.Geteuid() == 0 {
		if why := rootEditProblem(fi, dirInfo); why != "" {
			return errors.New(why)
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
	var own owner
	if exists {
		mode = fi.Mode().Perm()
		own.uid, own.gid, own.set = ownerIDs(fi)
	} else if dirInfo != nil {
		own.uid, own.gid, own.set = ownerIDs(dirInfo)
	}
	if managed {
		mode &^= 0o022
		own.set = false // root keeps managed files
	}

	tmp, err := writeNew(r, "."+name+"."+sensorName+"-", ".tmp", p.After, mode, own, true)
	if err != nil {
		return fmt.Errorf("cannot write a temporary file (%s)", errClass(err))
	}
	cleanup := func() { _ = r.Remove(tmp) }
	if exists {
		if err := backup(r, name, cur, mode, own, ts); err != nil {
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
	var errs []error
	if managed {
		if err := hardenIn(r, name, false); err != nil {
			errs = append(errs, fmt.Errorf("written, but could not be secured (%s)", errClass(err)))
		}
	}
	syncDir(r)
	errs = append(errs, repairs...)
	return errors.Join(errs...)
}

// readIn reads name in r without following a link and without keeping the
// handle. fi is nil when the file does not exist; dir is r's own lstat.
func readIn(r *os.Root, name string) (data []byte, fi, dir os.FileInfo, err error) {
	st := readAt(r, name)
	switch {
	case st.refused == refusedSymlink:
		return nil, nil, st.dir, ErrSymlink
	case st.refused != "":
		return nil, nil, st.dir, errors.New(strings.TrimPrefix(st.refused, "is "))
	case !st.exists:
		dir, _ := r.Stat(".")
		return nil, nil, dir, nil
	}
	return st.data, st.info, st.dir, nil
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

// owner is the uid and gid a new file is handed to, when set.
type owner struct {
	uid, gid int
	set      bool
}

// writeNew creates a new file named prefix+<random>+suffix in r (O_EXCL, so
// two installers never share one) and returns its name.
func writeNew(r *os.Root, prefix, suffix string, data []byte, mode os.FileMode, own owner, sync bool) (string, error) {
	var rnd [8]byte
	if _, err := io.ReadFull(rand.Reader, rnd[:]); err != nil {
		return "", errors.New("no randomness for a file name")
	}
	name := prefix + hex.EncodeToString(rnd[:]) + suffix
	return name, createFile(r, name, data, mode, own, sync)
}

// createFile creates name in r, which must not exist (O_EXCL also refuses
// to follow a link), and writes data. Mode and owner are set on the open
// descriptor before it is closed: when root edits a user's file the
// directory belongs to that user, who can replace any name in it by a hard
// link to another file between two calls, and a change made by name would
// then land on that file.
func createFile(r *os.Root, name string, data []byte, mode os.FileMode, own owner, sync bool) error {
	f, err := r.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	// The umask may have narrowed the mode given to OpenFile.
	werr := f.Chmod(mode)
	if werr == nil {
		_, werr = f.Write(data)
	}
	if werr == nil && sync {
		werr = f.Sync()
	}
	if werr == nil && own.set {
		werr = chownFile(f, own.uid, own.gid)
	}
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		_ = r.Remove(name)
	}
	return werr
}

// backup keeps the previous bytes beside the file. The suffix does not end
// in .json, so drop-in directories that load every *.json (Claude Code
// managed-settings.d, Copilot policy.d and hooks) ignore it.
func backup(r *os.Root, name string, data []byte, mode os.FileMode, own owner, ts string) error {
	bak, err := freeName(r, name+"."+sensorName+"-"+ts, ".bak")
	if err == nil {
		err = createFile(r, bak, data, mode, own, false)
	}
	if err != nil {
		return fmt.Errorf("cannot write the backup (%s)", errClass(err))
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
