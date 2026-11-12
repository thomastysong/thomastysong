//go:build windows

package hookinstall

import (
	"fmt"
	"os"

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

func setSDDL(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		owner, nil, dacl, nil)
}

// hardenIn sets the managed DACL on a file of the pinned directory, or on
// the directory itself for ".". The Win32 call takes a path, so the name is
// resolved against the directory's own path.
func hardenIn(r *os.Root, name string) error {
	if name == "." {
		return hardenPath(r.Name())
	}
	fi, err := r.Lstat(name)
	if err != nil {
		return err
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s is a reparse point", name)
	}
	return setSDDL(r.Name()+`\`+name, managedFileSDDL)
}

func hardenPath(path string) error { return setSDDL(path, managedDirSDDL) }

// linkTrusted: no reparse point on the way to a hook file is followed. The
// system junctions that exist on a stock installation (Documents and
// Settings, All Users) are not on any path this package writes to.
func linkTrusted(path string, fi os.FileInfo) bool { return false }

func giveTo(r *os.Root, name string, uid, gid int) error { return nil }
