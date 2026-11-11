//go:build windows

package transcript

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/sys/windows"
)

// statLazy: NTFS updates the size and write time stored in a directory entry
// lazily while another process holds the file open for writing, so a
// path-based stat can report a live log as unchanged. Recently active files
// are therefore re-examined through a handle on every poll.
const statLazy = true

func lstatMeta(path string) (fileMeta, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return fileMeta{}, err
	}
	mode := fi.Mode()
	return fileMeta{
		size:  fi.Size(),
		mtime: fi.ModTime().UnixNano(),
		// Junctions and other non-symlink reparse points are reported as
		// irregular; both redirect, both are refused.
		symlink: mode&(os.ModeSymlink|os.ModeIrregular) != 0,
		regular: mode.IsRegular(),
		dir:     mode.IsDir() && mode&(os.ModeSymlink|os.ModeIrregular) == 0,
	}, nil
}

// longPath lets CreateFile accept paths beyond MAX_PATH.
func longPath(p string) string {
	if len(p) < 248 || strings.HasPrefix(p, `\\`) || !filepath.IsAbs(p) {
		return p
	}
	return `\\?\` + filepath.Clean(p)
}

// openBeneath opens base/rel for reading and refuses reparse points
// (symlinks, junctions) in any component of rel. The final component is
// opened with FILE_FLAG_OPEN_REPARSE_POINT so a link is opened as itself and
// then rejected, never followed. Sharing allows write and delete so the
// agent can keep appending to, renaming or removing its log while it is read.
func openBeneath(base, rel string) (*os.File, fileMeta, error) {
	full := base
	if rel != "" {
		full = filepath.Join(base, rel)
		parts := strings.Split(filepath.ToSlash(rel), "/")
		at := base
		for _, part := range parts[:len(parts)-1] {
			if part == "" || part == "." {
				continue
			}
			at = filepath.Join(at, part)
			if part == ".." {
				return nil, fileMeta{}, &os.PathError{Op: "open", Path: at, Err: errors.New("path escapes its root")}
			}
			m, err := lstatMeta(at)
			if err != nil {
				return nil, fileMeta{}, err
			}
			if m.symlink || !m.dir {
				return nil, fileMeta{}, &os.PathError{Op: "open", Path: at, Err: errSymlink}
			}
		}
	}
	p16, err := windows.UTF16PtrFromString(longPath(full))
	if err != nil {
		return nil, fileMeta{}, &os.PathError{Op: "open", Path: full, Err: err}
	}
	h, err := windows.CreateFile(p16, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return nil, fileMeta{}, &os.PathError{Op: "open", Path: full, Err: err}
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		windows.CloseHandle(h)
		return nil, fileMeta{}, &os.PathError{Op: "stat", Path: full, Err: err}
	}
	ftype, _ := windows.GetFileType(h)
	switch {
	case info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0:
		windows.CloseHandle(h)
		return nil, fileMeta{}, &os.PathError{Op: "open", Path: full, Err: errSymlink}
	case info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0, ftype != windows.FILE_TYPE_DISK:
		windows.CloseHandle(h)
		return nil, fileMeta{}, &os.PathError{Op: "open", Path: full, Err: errNotRegular}
	}
	m := fileMeta{
		size:  int64(info.FileSizeHigh)<<32 | int64(info.FileSizeLow),
		mtime: info.LastWriteTime.Nanoseconds(),
		id: strconv.FormatUint(uint64(info.VolumeSerialNumber), 16) + ":" +
			strconv.FormatUint(uint64(info.FileIndexHigh)<<32|uint64(info.FileIndexLow), 16),
		regular: true,
	}
	if sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION); err == nil {
		if sid, _, err := sd.Owner(); err == nil && sid != nil {
			m.owner = sid.String()
		}
	}
	return os.NewFile(uintptr(h), full), m, nil
}

// ownerOK reports whether the file's owner is the expected account. Files
// created by an elevated process are owned by the Administrators group or
// SYSTEM by default; neither is an account an unprivileged user can plant
// files as, so both are accepted. An unknown owner cannot be verified and is
// refused when a check was asked for.
func ownerOK(m fileMeta, want string) bool {
	if want == "" {
		return true
	}
	switch {
	case strings.EqualFold(m.owner, want), m.owner == "S-1-5-32-544", m.owner == "S-1-5-18":
		return true
	}
	return false
}
