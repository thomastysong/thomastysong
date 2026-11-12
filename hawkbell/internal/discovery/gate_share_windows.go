//go:build windows

package discovery

import (
	"errors"
	"os"
	"strings"

	"golang.org/x/sys/windows"

	"github.com/thomastysong/thomastysong/hawkbell/internal/platform"
)

// openShared opens a regular file that rootOpener.check has just confined,
// sharing READ, WRITE and DELETE. Go's os.Open (and os.Root.Open) share
// only READ and WRITE, so while the scanner reads ~/.claude.json, Cursor's
// state.vscdb or a Codex rollout, the agent's own rename-over or delete of
// that file fails. platform.OpenNoFollow shares everything and refuses a
// final reparse point; because it resolves the intermediate components by
// path, the opened handle's final path is then compared with the root's, so
// a junction swapped in after the check cannot lead outside the root.
//
// It handles only scans of the host itself: with HostRoot the root is
// resolved through os.Root inside HostRoot, which a path-based open cannot
// reproduce, so those opens keep os.Root (handled false).
//
// UNVERIFIED: compiled for windows/amd64 and windows/arm64, not executed.
func (o *rootOpener) openShared(root, rel string, li os.FileInfo) (*os.File, bool, error) {
	if o.hostRoot != "" {
		return nil, false, nil
	}
	base, err := o.finalRoot(root)
	if err != nil {
		return nil, false, nil
	}
	full := fromLogical(joinLogical(root, rel))
	f, err := platform.OpenNoFollow(full)
	if err != nil {
		switch {
		case errors.Is(err, platform.ErrSymlink):
			return nil, true, errSymlink
		case errors.Is(err, platform.ErrNotRegular):
			return nil, true, errNotReg
		}
		return nil, true, mapRootErr(err)
	}
	got, err := finalPathOf(windows.Handle(f.Fd()))
	if err != nil || !underFinal(base, got) {
		f.Close()
		return nil, true, errEscape
	}
	fi, err := f.Stat()
	// Same swap check as the os.Root path: the file opened must be the one
	// Lstat saw inside the root.
	if err != nil || !fi.Mode().IsRegular() || fi.Size() != li.Size() || !fi.ModTime().Equal(li.ModTime()) {
		f.Close()
		return nil, true, errSymlink
	}
	return f, true, nil
}

// finalRoot returns the final (link-resolved, normalized) path of a root
// directory, cached per scan.
func (o *rootOpener) finalRoot(root string) (string, error) {
	o.mu.Lock()
	if p, ok := o.final[root]; ok {
		o.mu.Unlock()
		return p, nil
	}
	o.mu.Unlock()
	name, err := windows.UTF16PtrFromString(fromLogical(root))
	if err != nil {
		return "", err
	}
	// Access 0 reads attributes only; BACKUP_SEMANTICS opens a directory.
	// The root itself is resolved normally, exactly as os.OpenRoot did.
	h, err := windows.CreateFile(name, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return "", err
	}
	p, err := finalPathOf(h)
	windows.CloseHandle(h)
	if err != nil {
		return "", err
	}
	o.mu.Lock()
	if len(o.final) >= 128 {
		clear(o.final)
	}
	o.final[root] = p
	o.mu.Unlock()
	return p, nil
}

// finalPathOf returns the normalized DOS-volume path of an open handle
// ("\\?\C:\Users\alice\..."). Flags 0 is FILE_NAME_NORMALIZED|VOLUME_NAME_DOS.
func finalPathOf(h windows.Handle) (string, error) {
	buf := make([]uint16, 512)
	for i := 0; i < 3; i++ {
		n, err := windows.GetFinalPathNameByHandle(h, &buf[0], uint32(len(buf)), 0)
		if err != nil {
			return "", err
		}
		if int(n) < len(buf) {
			return windows.UTF16ToString(buf[:n]), nil
		}
		if n > 1<<15 {
			break
		}
		buf = make([]uint16, n+1)
	}
	return "", errBadPath
}

// underFinal reports whether p is base or lies below it. NTFS names compare
// case-insensitively; both sides come from GetFinalPathNameByHandle, so
// 8.3 short names and separators are already normalized.
func underFinal(base, p string) bool {
	if base == "" || len(p) < len(base) || !strings.EqualFold(p[:len(base)], base) {
		return false
	}
	return len(p) == len(base) || strings.HasSuffix(base, `\`) || p[len(base)] == '\\'
}
