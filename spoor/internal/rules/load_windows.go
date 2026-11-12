//go:build windows

package rules

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

// UNVERIFIED: compiled for windows/amd64 and windows/arm64 and the ACL
// analysis (acl.go) is unit-tested everywhere, but this file has not run on
// a Windows host in the build environment.

func readTrustedDir(dir string) (map[string][]byte, error) {
	if err := checkPath(dir, true); err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	sub := filepath.Join(dir, "rules")
	fi, err := os.Lstat(sub)
	switch {
	case err == nil && fi.IsDir() && fi.Mode()&os.ModeSymlink == 0:
		if err := checkPath(sub, true); err != nil {
			return nil, err
		}
		if err := readDirPath(sub, "rules/", files, func(string) bool { return true }); err != nil {
			return nil, err
		}
		if err := readDirPath(dir, "", files, func(n string) bool { return n == "lists.yaml" || n == "suppressions.yaml" }); err != nil {
			return nil, err
		}
	case err == nil:
		return nil, fmt.Errorf("%w: %s is not a directory", ErrInsecureDir, sub)
	case os.IsNotExist(err):
		if err := readDirPath(dir, "", files, func(string) bool { return true }); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("rules: %s: %w", sub, err)
	}
	return files, nil
}

func readDirPath(dir, prefix string, files map[string][]byte, want func(string) bool) error {
	f, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("rules: open %s: %w", dir, err)
	}
	entries, err := f.ReadDir(maxDirEntries + 1)
	f.Close()
	if err != nil && err != io.EOF {
		return fmt.Errorf("rules: list %s: %w", dir, err)
	}
	if len(entries) > maxDirEntries {
		return fmt.Errorf("rules: %s has more than %d entries", dir, maxDirEntries)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	for _, n := range sortedNames(names) {
		if !want(n) {
			continue
		}
		b, err := readChecked(filepath.Join(dir, n), fileCap(n))
		if err != nil {
			return err
		}
		files[prefix+n] = b
	}
	return nil
}

// openNoReparse opens path without following a reparse point (symlink or
// junction), sharing read, write and delete so the loader never blocks an
// updater that replaces the file.
func openNoReparse(path string, dir bool) (windows.Handle, error) {
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return windows.InvalidHandle, err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if dir {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	return windows.CreateFile(p, windows.GENERIC_READ|windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, flags, 0)
}

func checkPath(path string, dir bool) error {
	h, err := openNoReparse(path, dir)
	if err != nil {
		return fmt.Errorf("rules: open %s: %w", path, err)
	}
	defer windows.CloseHandle(h)
	return checkHandle(h, path, dir)
}

func checkHandle(h windows.Handle, name string, dir bool) error {
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return fmt.Errorf("rules: stat %s: %w", name, err)
	}
	attrs := info.FileAttributes
	if attrs&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%w: %s is a reparse point", ErrInsecureDir, name)
	}
	isDir := attrs&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if dir != isDir {
		return fmt.Errorf("%w: %s has the wrong type", ErrInsecureDir, name)
	}
	sd, err := windows.GetSecurityInfo(h, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("rules: security descriptor of %s: %w", name, err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("%w: %s has no owner", ErrInsecureDir, name)
	}
	dacl, _, err := sd.DACL()
	if err != nil && err != windows.ERROR_OBJECT_NOT_FOUND {
		return fmt.Errorf("rules: DACL of %s: %w", name, err)
	}
	var aces []aceInfo
	if dacl != nil {
		for i := uint32(0); i < uint32(dacl.AceCount); i++ {
			var ace *windows.ACCESS_ALLOWED_ACE
			if err := windows.GetAce(dacl, i, &ace); err != nil {
				return fmt.Errorf("rules: DACL of %s: %w", name, err)
			}
			info := aceInfo{
				inheritOnly: ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0,
				mask:        uint32(ace.Mask),
				typ:         ace.Header.AceType,
			}
			switch classifyACE(ace.Header.AceType) {
			case aceGrant:
				info.allow = true
				info.sid = aceTrustee(ace)
			case aceUnknown:
				info.unknown = true
			}
			aces = append(aces, info)
		}
	}
	if p := aclProblem(owner.String(), dacl == nil, aces, selfSID()); p != "" {
		return fmt.Errorf("%w: %s %s", ErrInsecureDir, name, p)
	}
	return nil
}

// aceTrustee returns the trustee SID of an access-allowed ACE of any form
// (basic, callback, object, callback object), or "" when the entry is too
// short to hold one; aclProblem treats "" as an untrusted trustee.
func aceTrustee(ace *windows.ACCESS_ALLOWED_ACE) string {
	size := int(ace.Header.AceSize)
	base := unsafe.Pointer(ace)
	off := int(unsafe.Offsetof(ace.SidStart))
	if objectACE(ace.Header.AceType) {
		if off+4 > size {
			return ""
		}
		off = objectSIDOffset(*(*uint32)(unsafe.Add(base, off)))
	}
	if off+8 > size {
		return ""
	}
	sid := unsafe.Add(base, off)
	if off+8+4*int(*(*uint8)(unsafe.Add(sid, 1))) > size {
		return ""
	}
	s := (*windows.SID)(sid)
	if !s.IsValid() {
		return ""
	}
	return s.String()
}

func selfSID() string {
	u, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || u == nil || u.User.Sid == nil {
		return ""
	}
	return u.User.Sid.String()
}

func readChecked(path string, limit int64) ([]byte, error) {
	h, err := openNoReparse(path, false)
	if err != nil {
		return nil, fmt.Errorf("rules: open %s: %w", path, err)
	}
	f := os.NewFile(uintptr(h), path)
	defer f.Close()
	if err := checkHandle(h, path, false); err != nil {
		return nil, err
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("rules: read %s: %w", path, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("rules: %s is larger than %d bytes", path, limit)
	}
	return b, nil
}
