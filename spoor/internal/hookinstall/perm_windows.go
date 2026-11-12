//go:build windows

package hookinstall

import (
	"fmt"
	"os"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

// UNVERIFIED: compiled and vetted for windows/amd64 and windows/arm64, not
// executed in the build environment. The SDDL analysis itself (sddl.go) is
// portable and unit-tested.

// Mode bits mean nothing on Windows: access is the DACL. Managed files and
// directories get a protected DACL (no inherited entries) that gives SYSTEM
// and Administrators full control and Users read and execute, which the
// agent needs to load the file, and nothing else; the owner becomes
// Administrators so that CREATOR OWNER rights cannot keep a standard user
// in control of a directory they pre-created under ProgramData.
const (
	managedFileSDDL = "O:BAD:PAI(A;;FA;;;SY)(A;;FA;;;BA)(A;;0x1200a9;;;BU)"
	managedDirSDDL  = "O:BAD:PAI(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;OICI;0x1200a9;;;BU)"
)

func ownerIDs(fi os.FileInfo) (uid, gid int, ok bool) { return 0, 0, false }

// linkCount is not available from a FileInfo here; ownership checks that
// use it do not apply (see rootEditProblem).
func linkCount(fi os.FileInfo) uint64 { return 1 }

func writableByOthers(path string, fi os.FileInfo) string {
	if fi.Mode()&os.ModeSymlink != 0 {
		return "is a reparse point"
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return "has a security descriptor that cannot be read"
	}
	return sddlProblem(sd.String())
}

// hardenIn sets the managed owner and DACL on name, a file or directory of
// the pinned directory r. The object is opened relative to r's own handle
// (NtCreateFile with RootDirectory) with FILE_OPEN_REPARSE_POINT and
// OBJ_DONT_REPARSE, checked on that handle (not a reparse point, the
// expected kind, a single link for a file) and changed through that handle
// with SetKernelObjectSecurity. Nothing is resolved by path again, so a
// component swapped for a junction after the walk cannot redirect the
// change, and no access entries are propagated to existing children (the
// files this package cares about are hardened one by one). Setting the
// owner to Administrators needs SeRestorePrivilege or ownership, which an
// elevated installer has.
func hardenIn(r *os.Root, name string, dir bool) error {
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `\/:`) {
		return fmt.Errorf("%q is not a name in the directory", name)
	}
	d, err := r.Open(".")
	if err != nil {
		return err
	}
	defer d.Close()
	h, err := openForSecurity(windows.Handle(d.Fd()), name, dir)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(h)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(h, &info); err != nil {
		return err
	}
	switch {
	case info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0:
		return fmt.Errorf("%s is a reparse point", name)
	case dir != (info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0):
		return fmt.Errorf("%s changed while it was being secured", name)
	case !dir && info.NumberOfLinks > 1:
		return fmt.Errorf("%s has more than one hard link", name)
	}
	sddl := managedFileSDDL
	if dir {
		sddl = managedDirSDDL
	}
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	// The descriptor carries SE_DACL_PROTECTED ("P" in the SDDL), which the
	// low-level call keeps, so entries inherited from ProgramData cannot
	// come back.
	return windows.SetKernelObjectSecurity(h, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION, sd)
}

// openForSecurity opens name relative to the directory handle dir for
// reading and changing its security descriptor, without following a
// reparse point anywhere in the name.
func openForSecurity(dir windows.Handle, name string, isDir bool) (windows.Handle, error) {
	objName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return windows.InvalidHandle, err
	}
	oa := &windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: dir,
		ObjectName:    objName,
		Attributes:    windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
	}
	options := uint32(windows.FILE_OPEN_REPARSE_POINT | windows.FILE_SYNCHRONOUS_IO_NONALERT | windows.FILE_OPEN_FOR_BACKUP_INTENT)
	if isDir {
		options |= windows.FILE_DIRECTORY_FILE
	} else {
		options |= windows.FILE_NON_DIRECTORY_FILE
	}
	var h windows.Handle
	var iosb windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(&h,
		windows.READ_CONTROL|windows.WRITE_DAC|windows.WRITE_OWNER|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
		oa, &iosb, nil, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN, options, 0, 0)
	if err != nil {
		return windows.InvalidHandle, err
	}
	return h, nil
}

// linkTrusted: no reparse point on the way to a hook file is followed. The
// system junctions that exist on a stock installation (Documents and
// Settings, All Users) are not on any path this package writes to.
func linkTrusted(path string, fi os.FileInfo) bool { return false }

// chownFile: ownership of a user's file is not changed on Windows (a file
// root creates in the user's profile inherits the profile's access list).
func chownFile(f *os.File, uid, gid int) error { return nil }

// fixNewDir: mode bits mean nothing here; a managed directory gets its
// access list from hardenIn.
func fixNewDir(r *os.Root, name string, uid, gid int, give bool) error { return nil }
