package platform

import (
	"fmt"
	"os"
)

// OpenBeneath opens root/rel for reading and guarantees the file really is
// inside root: ".." and symbolic links in any component may not lead out of
// it (links that stay inside root are followed). Like OpenNoFollow it refuses
// anything that is not a regular file, and it never blocks on a FIFO.
//
// Use it when walking a user's tree as root: OpenNoFollow alone checks only
// the last component, so "~/.claude" itself being a link to /etc would pass.
func OpenBeneath(root, rel string) (*os.File, error) {
	r, err := os.OpenRoot(root)
	if err != nil {
		return nil, err
	}
	defer r.Close()
	f, err := r.OpenFile(rel, os.O_RDONLY|openNonblock, 0)
	if err != nil {
		return nil, err
	}
	fi, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		f.Close()
		return nil, &os.PathError{Op: "open", Path: rel, Err: ErrNotRegular}
	}
	return f, nil
}

// FileIDOf returns the identity of an open file (see FileID). Unlike FileID
// with a path it cannot race with a rename, so it is the right call for
// detecting that a log being tailed was rotated or replaced.
func FileIDOf(f *os.File) (string, error) {
	if f == nil {
		return "", os.ErrInvalid
	}
	id, err := fileIDOfHandle(f)
	if err != nil {
		return "", fmt.Errorf("platform: file id: %w", err)
	}
	return id, nil
}
