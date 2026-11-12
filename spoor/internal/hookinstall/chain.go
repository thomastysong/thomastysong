package hookinstall

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// The directories above a hook file decide where a write really lands. A
// symbolic link on the way, planted by the user whose settings are being
// edited, would let a root installer write a hook file (a command every
// session runs) anywhere. Every component is therefore examined: links are
// followed only when linkTrusted says so (made by root, or by the caller
// itself when it is not root), and never below a host root, where a link
// resolves against the wrong file system.

// ErrSymlink is returned when a write would go through a symbolic link that
// is not trusted, or when the hook file itself is a link.
var ErrSymlink = errors.New("refusing to write through a symbolic link")

// errNotDir is returned when a component of the way to a file is not a
// directory.
var errNotDir = errors.New("not a directory")

// maxLinkHops bounds how many trusted links one path may traverse.
const maxLinkHops = 16

// splitComponents splits a cleaned path below its base into names.
func splitComponents(rel string) []string {
	var out []string
	for _, c := range strings.Split(filepath.ToSlash(rel), "/") {
		if c != "" && c != "." {
			out = append(out, c)
		}
	}
	return out
}

// startOf returns the directory a walk starts from and the names below it.
// With a confining root the walk starts there and the path must stay inside
// it.
func startOf(dir, confine string) (base string, comps []string, err error) {
	dir = filepath.Clean(dir)
	if !filepath.IsAbs(dir) {
		return "", nil, errors.New("not an absolute path on this system")
	}
	if confine != "" {
		confine = filepath.Clean(confine)
		rel, err := filepath.Rel(confine, dir)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", nil, errors.New("path is outside the host root")
		}
		return confine, splitComponents(rel), nil
	}
	vol := filepath.VolumeName(dir)
	base = vol + string(filepath.Separator)
	return base, splitComponents(dir[len(vol):]), nil
}

// followLink computes the path a trusted link at dir/name leads to,
// followed by the remaining components.
func followLink(dir, target string, rest []string) string {
	if !filepath.IsAbs(target) {
		target = filepath.Join(dir, target)
	}
	return filepath.Join(append([]string{target}, rest...)...)
}

// checkChain reports why the directory dir (or the part of it that exists)
// cannot be written to safely, or "". It is the read-only twin of
// openDirChain, used when a plan is computed and by Status.
func checkChain(dir, confine string) string {
	base, comps, err := startOf(dir, confine)
	if err != nil {
		return err.Error()
	}
	for hops := 0; ; hops++ {
		if hops > maxLinkHops {
			return "too many symbolic links on the way"
		}
		cur := base
		restarted := false
		for i, c := range comps {
			next := filepath.Join(cur, c)
			fi, err := os.Lstat(next)
			if errors.Is(err, fs.ErrNotExist) {
				return "" // the rest will be created
			}
			if err != nil {
				return next + " cannot be inspected (" + errClass(err) + ")"
			}
			if fi.Mode()&os.ModeIrregular != 0 {
				// Go reports Windows junctions and other reparse points
				// this way since 1.23.
				return next + " is a reparse point spoor does not follow"
			}
			if fi.Mode()&os.ModeSymlink != 0 {
				if confine != "" || !linkTrusted(next, fi) {
					return next + " is a symbolic link spoor does not follow"
				}
				target, err := os.Readlink(next)
				if err != nil {
					return next + " cannot be read (" + errClass(err) + ")"
				}
				base, comps, err = startOf(followLink(cur, target, comps[i+1:]), "")
				if err != nil {
					return next + " leads to an unusable path"
				}
				restarted = true
				break
			}
			if !fi.IsDir() {
				return next + " is not a directory"
			}
			cur = next
		}
		if !restarted {
			return ""
		}
	}
}

// dirPolicy says what openDirChain does with the directories it creates or
// passes.
type dirPolicy struct {
	create bool
	// managed hardens the directories between the system anchor and the
	// file (see managedChain).
	managed bool
}

// openDirChain opens dir as an os.Root after walking every component from
// the file-system root (or from confine) down to it, one handle at a time:
// each directory is opened relative to its parent and compared with what
// lstat saw, so a component swapped for a link between the check and the
// open is caught. Missing directories are created with mode 0755; when
// root creates one inside a user's directory it is handed to that user.
func openDirChain(dir, confine string, pol dirPolicy) (*os.Root, error) {
	base, comps, err := startOf(dir, confine)
	if err != nil {
		return nil, err
	}
	for hops := 0; hops <= maxLinkHops; hops++ {
		r, next, err := walkOnce(base, comps, confine, pol)
		if err != nil || r != nil {
			return r, err
		}
		base, comps, err = startOf(next, "")
		if err != nil {
			return nil, err
		}
	}
	return nil, errors.New("too many symbolic links on the way")
}

// walkOnce walks comps below base. It returns the opened directory, or the
// path to restart from after a trusted link.
func walkOnce(base string, comps []string, confine string, pol dirPolicy) (*os.Root, string, error) {
	harden := map[string]bool{}
	if pol.managed {
		for _, d := range managedChain(filepath.Join(append([]string{base}, append(comps, "f")...)...)) {
			harden[d] = true
		}
	}
	r, err := os.OpenRoot(base)
	if err != nil {
		return nil, "", fmt.Errorf("cannot open %s (%s)", base, errClass(err))
	}
	cur := base
	for i, c := range comps {
		next := filepath.Join(cur, c)
		fi, err := r.Lstat(c)
		if errors.Is(err, fs.ErrNotExist) && pol.create {
			if err := makeDir(r, c, pol.managed); err != nil {
				r.Close()
				return nil, "", fmt.Errorf("cannot create %s (%s)", next, errClass(err))
			}
			fi, err = r.Lstat(c)
		}
		if err != nil {
			r.Close()
			if errors.Is(err, fs.ErrNotExist) {
				return nil, "", fmt.Errorf("%s does not exist: %w", next, fs.ErrNotExist)
			}
			if isNotDir(err) {
				return nil, "", fmt.Errorf("%s: %w", next, errNotDir)
			}
			return nil, "", fmt.Errorf("cannot inspect %s (%s)", next, errClass(err))
		}
		if fi.Mode()&os.ModeIrregular != 0 {
			r.Close()
			return nil, "", fmt.Errorf("%w: %s is a reparse point", ErrSymlink, next)
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			if confine != "" || !linkTrusted(next, fi) {
				r.Close()
				return nil, "", fmt.Errorf("%w: %s", ErrSymlink, next)
			}
			target, err := r.Readlink(c)
			r.Close()
			if err != nil {
				return nil, "", fmt.Errorf("cannot read link %s (%s)", next, errClass(err))
			}
			return nil, followLink(cur, target, comps[i+1:]), nil
		}
		if !fi.IsDir() {
			r.Close()
			return nil, "", fmt.Errorf("%s: %w", next, errNotDir)
		}
		if harden[next] {
			// A standard user may have pre-created this directory (anyone
			// can under ProgramData): take it back rather than refuse.
			if err := hardenIn(r, c, true); err != nil {
				r.Close()
				return nil, "", fmt.Errorf("cannot secure %s (%s)", next, errClass(err))
			}
		}
		sub, err := r.OpenRoot(c)
		if err != nil {
			r.Close()
			return nil, "", fmt.Errorf("cannot open %s (%s)", next, errClass(err))
		}
		st, err := sub.Stat(".")
		r.Close()
		if err != nil || !os.SameFile(fi, st) {
			sub.Close()
			return nil, "", fmt.Errorf("%s changed while it was being opened", next)
		}
		r, cur = sub, next
	}
	return r, "", nil
}

// makeDir creates one directory with mode 0755 whatever the umask. A
// directory that root creates inside somebody else's directory (a user's
// home) is given to that owner, so the agent can keep managing its own
// settings directory.
func makeDir(r *os.Root, name string, managed bool) error {
	if err := r.Mkdir(name, 0o755); err != nil && !errors.Is(err, fs.ErrExist) {
		return err
	}
	if err := r.Chmod(name, 0o755); err != nil {
		return err
	}
	if managed {
		return nil
	}
	if parent, err := r.Stat("."); err == nil {
		if uid, gid, ok := ownerIDs(parent); ok {
			return giveTo(r, name, uid, gid)
		}
	}
	return nil
}

// thirdOwner reports a file owned neither by root nor by the owner of the
// directory that holds it. When root edits a user's settings, such a file
// (another user's, or a hard link to one) is not the user's to have
// edited; the check only applies where ownership is known (unix).
func thirdOwner(file, dir os.FileInfo) (uid int, bad bool) {
	fu, _, ok1 := ownerIDs(file)
	du, _, ok2 := ownerIDs(dir)
	if !ok1 || !ok2 || fu == du || fu == 0 {
		return fu, false
	}
	return fu, true
}
