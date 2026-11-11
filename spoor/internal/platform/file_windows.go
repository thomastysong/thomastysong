//go:build windows

package platform

import (
	"os"
	"strconv"

	"golang.org/x/sys/windows"
)

// UNVERIFIED: this file was compiled and vetted for windows/amd64 and
// windows/arm64 but not executed in the build environment.

// Windows has no FIFO-on-open hazard for ordinary paths, so no extra flag.
const openNonblock = 0

// OpenNoFollow opens path for reading. It fails with ErrSymlink when the
// final component is a reparse point (symbolic link, junction, mount point,
// cloud placeholder) and with ErrNotRegular for directories, pipes and
// devices. Intermediate components are resolved normally; see OpenBeneath.
func OpenNoFollow(path string) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	// Share everything: the agent must stay free to append to, rename and
	// delete the transcript the sensor is reading.
	// FILE_FLAG_OPEN_REPARSE_POINT opens the link itself instead of its
	// target, so the attribute check below sees it.
	h, err := windows.CreateFile(p, windows.GENERIC_READ,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	fail := func(err error) (*os.File, error) {
		windows.CloseHandle(h)
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	if t, err := windows.GetFileType(h); err != nil || t != windows.FILE_TYPE_DISK {
		return fail(ErrNotRegular)
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return fail(err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fail(ErrSymlink)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0 {
		return fail(ErrNotRegular)
	}
	return os.NewFile(uintptr(h), path), nil
}

// FileID returns "volume serial:file index" for path, which identifies a
// file across renames on NTFS. os.FileInfo does not expose the index on
// Windows, so fi is ignored and path is required; a final reparse point is
// identified itself, not its target. It returns "" on any failure.
func FileID(fi os.FileInfo, path string) string {
	if path == "" {
		return ""
	}
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return ""
	}
	// Access 0 asks for attributes only; FILE_FLAG_BACKUP_SEMANTICS lets the
	// call open directories as well.
	h, err := windows.CreateFile(p, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)
	id, err := handleID(h)
	if err != nil {
		return ""
	}
	return id
}

func handleID(h windows.Handle) (string, error) {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return "", err
	}
	index := uint64(info.FileIndexHigh)<<32 | uint64(info.FileIndexLow)
	return strconv.FormatUint(uint64(info.VolumeSerialNumber), 10) + ":" + strconv.FormatUint(index, 10), nil
}

func fileIDOfHandle(f *os.File) (string, error) {
	return handleID(windows.Handle(f.Fd()))
}

// OwnerUID cannot answer on Windows: os.FileInfo carries no owner. Use
// PathOwner.
func OwnerUID(fi os.FileInfo) (string, bool) { return "", false }

// PathOwner returns the SID string of the owner of path.
func PathOwner(path string) (string, bool) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return "", false
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return "", false
	}
	return owner.String(), true
}

// hostIDFileTrusted has no cheap equivalent of the POSIX mode check; access
// to the config directory is governed by the ACL the installer sets.
func hostIDFileTrusted(fi os.FileInfo, system bool) bool { return true }
