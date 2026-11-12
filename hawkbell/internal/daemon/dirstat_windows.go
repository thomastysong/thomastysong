//go:build windows

package daemon

import (
	"os"

	"golang.org/x/sys/windows"
)

// checkDir reports a directory's security descriptor. Judging an arbitrary
// DACL is left to the operator; a reparse point is refused outright.
// UNVERIFIED: compiled and vetted only.
func checkDir(name, path string, kind dirKind, ownerUID string) DirStatus {
	d := DirStatus{Name: name, Path: path, Want: "SYSTEM and Administrators full control"}
	switch kind {
	case dirBundle:
		d.Want += "; Users read"
	case dirUserSpool:
		d.Want += "; " + ownerUID + " modify"
	}
	fi, err := os.Lstat(path)
	if err != nil {
		d.Problem = "missing (the daemon creates it at start)"
		return d
	}
	d.Exists = true
	if fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		d.Problem = "is a reparse point; the daemon refuses it"
		return d
	}
	if !fi.IsDir() {
		d.Problem = "is not a directory"
		return d
	}
	d.ACL = sddlOf(path)
	d.OK = true
	return d
}

func checkStateFile(path string) DirStatus {
	d := DirStatus{Name: "state.db", Path: path}
	fi, err := os.Lstat(path)
	if err != nil {
		d.Problem = "missing (the daemon creates it at start)"
		return d
	}
	d.Exists = true
	if !fi.Mode().IsRegular() {
		d.Problem = "is not a regular file"
		return d
	}
	d.ACL = sddlOf(path)
	d.OK = true
	return d
}

func sddlOf(path string) string {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return ""
	}
	return sd.String()
}
