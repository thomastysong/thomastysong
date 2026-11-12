//go:build windows

package discovery

import "golang.org/x/sys/windows"

// quarantined reports a Zone.Identifier alternate data stream (Mark of the
// Web), which Windows attaches to downloaded files. Only the stream's
// existence is checked: it is opened for attributes only (access 0) and
// shares read, write and delete, so the agent's own rename or delete of
// the file is never blocked. Container scans (HostRoot) are not checked.
//
// UNVERIFIED: compiled for windows, not executed in the build environment.
func (s *scanner) quarantined(l loc) bool {
	if s.o.HostRoot != "" {
		return false
	}
	name, err := windows.UTF16PtrFromString(fromLogical(l.String()) + ":Zone.Identifier")
	if err != nil {
		return false
	}
	h, err := windows.CreateFile(name, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return false
	}
	windows.CloseHandle(h)
	return true
}
