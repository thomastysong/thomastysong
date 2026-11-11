//go:build windows

package sink

import (
	"errors"
	"os"

	"golang.org/x/sys/windows"
)

// shareAll lets Fluent Bit keep reading, other spoor processes keep
// appending, and pruning delete the file, all at the same time. Go's own
// os.OpenFile omits FILE_SHARE_DELETE, which would make every open handle
// block deletion with a sharing violation.
const shareAll = windows.FILE_SHARE_READ | windows.FILE_SHARE_WRITE | windows.FILE_SHARE_DELETE

// appendAccess is GENERIC_WRITE minus FILE_WRITE_DATA. With FILE_APPEND_DATA
// and without FILE_WRITE_DATA, NTFS ignores any write offset and appends
// atomically, which is the Windows equivalent of O_APPEND (and exactly what
// Go's syscall.Open requests for O_APPEND).
const appendAccess = windows.FILE_APPEND_DATA | windows.FILE_WRITE_ATTRIBUTES | windows.FILE_WRITE_EA |
	windows.STANDARD_RIGHTS_WRITE | windows.SYNCHRONIZE | windows.FILE_READ_ATTRIBUTES

// FILE_FLAG_OPEN_REPARSE_POINT opens a symlink or junction itself rather
// than its target; the caller then rejects it for not being a regular file.
const openAttrs = windows.FILE_ATTRIBUTE_NORMAL | windows.FILE_FLAG_OPEN_REPARSE_POINT

func createFile(path string, access, disposition uint32) (*os.File, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	// A nil security descriptor means the handle is not inherited by child
	// processes and the file takes the directory's ACL; FilesOptions.FileMode
	// has no Windows meaning.
	h, err := windows.CreateFile(p, access, shareAll, nil, disposition, openAttrs, 0)
	if err != nil {
		return nil, &os.PathError{Op: "open", Path: path, Err: err}
	}
	return os.NewFile(uintptr(h), path), nil
}

// openAppend opens a segment for appending, creating it when absent, and
// reports whether this call created it.
func openAppend(path string, _ os.FileMode) (f *os.File, created bool, err error) {
	for attempt := 0; attempt < 2; attempt++ {
		f, err = createFile(path, appendAccess, windows.CREATE_NEW)
		if err == nil {
			return f, true, nil
		}
		if !errors.Is(err, windows.ERROR_FILE_EXISTS) && !errors.Is(err, windows.ERROR_ALREADY_EXISTS) {
			return nil, false, err
		}
		f, err = createFile(path, appendAccess, windows.OPEN_EXISTING)
		if err == nil {
			return f, false, nil
		}
		if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) {
			return nil, false, err
		}
	}
	return nil, false, err
}

// openRead opens a segment for reading with full sharing, so a reader never
// blocks pruning.
func openRead(path string) (*os.File, error) {
	return createFile(path, windows.GENERIC_READ, windows.OPEN_EXISTING)
}

// linkCount is not checked on Windows: a file deleted while open stays in
// the delete-pending state and cannot be recreated under the same name until
// the last handle closes, so there is no silent write to a ghost file to
// detect, and creating hard links needs write access to the target.
func linkCount(os.FileInfo) uint64 { return 1 }

// syncDir is a no-op: NTFS journals the rename itself.
func syncDir(string) error { return nil }
