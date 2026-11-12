//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows access is decided by ACLs, which mode bits do not describe; the
// checks that depend on them report "skip" here.
func fileOwner(os.FileInfo) (uid, gid int, ok bool) { return 0, 0, false }

func lookupUID(name string) string {
	u, err := user.Lookup(name)
	if err != nil {
		return ""
	}
	return u.Uid
}

const permsChecked = false

type accessor struct{ name string }

func lookupAccessor(name string) (*accessor, error) {
	return nil, errors.New("--as-user is not supported on Windows (access is decided by ACLs)")
}

func (a *accessor) canRead(string, []string) (bool, string) {
	return false, "unsupported on Windows"
}

// execProblem: execute rights are ACLs on Windows; only presence is
// checked (binaryProblemAs).
func execProblem(string, *accessor) string { return "" }

func accessorForHome(string, string) *accessor { return nil }

// rewriteFlags: Windows has no FIFO-on-open hazard for ordinary paths.
const rewriteFlags = 0

// linkCount is not read on Windows: NTFS hard links need write access to
// the target, so a link the account planted reaches only files it could
// change itself.
// UNVERIFIED: compiled and vetted only.
func linkCount(os.FileInfo) uint64 { return 1 }

// prepareDataDir and prepareOutbox are no-ops on Windows: the directories
// inherit the ACL of their parent, which the installer (or the daemon, with
// explicit ACLs) sets.
// UNVERIFIED: the daemon's explicit ACLs are not applied by a daemonless
// scan.
func prepareDataDir(dataDir string) {}

func prepareOutbox(outbox, group string) []string { return nil }

// replaceKeepingACL replaces the configuration file at path with data: a
// new file beside it gets the old file's DACL, then is renamed over it, so
// a hook never reads half a file and the explicit read grant for Users the
// installer gave hawkbell.yaml (packaging/windows/install-service.ps1) stays.
// A file created in the data directory would otherwise carry only the
// inherited SYSTEM and Administrators entries, and every hook would fall
// back to built-in defaults. Inherited entries are recomputed from the
// directory (SetNamedSecurityInfo), as they were for the old file.
// UNVERIFIED: compiled and vetted only, not run on Windows.
func replaceKeepingACL(path string, data []byte) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("%s: cannot read its access control list: %w", path, err)
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("%s: no access control list to keep", path)
	}
	ctl, _, err := sd.Control()
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	info := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
	if ctl&windows.SE_DACL_PROTECTED != 0 {
		info |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	} else {
		info |= windows.UNPROTECTED_DACL_SECURITY_INFORMATION
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".hawkbell-config-*.tmp")
	if err != nil {
		return err
	}
	tmp := f.Name()
	done := false
	defer func() {
		if !done {
			os.Remove(tmp)
		}
	}()
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(tmp, windows.SE_FILE_OBJECT, info, nil, nil, dacl, nil); err != nil {
		return fmt.Errorf("%s: cannot copy the access control list: %w", tmp, err)
	}
	// A hook holding the file open (for milliseconds) makes the rename
	// fail with a sharing violation: retry briefly.
	for i := 0; ; i++ {
		err = os.Rename(tmp, path)
		if err == nil || i >= 50 || !(errors.Is(err, windows.ERROR_SHARING_VIOLATION) || errors.Is(err, windows.ERROR_ACCESS_DENIED)) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		return err
	}
	done = true
	return nil
}

// usersCanRead reports whether every interactive account can read path:
// an allow entry granting read to BUILTIN\Users, Authenticated Users,
// INTERACTIVE or Everyone, and no deny entry for them. Hooks run as the
// developer, so a configuration only SYSTEM and Administrators can read is
// a configuration no hook applies.
// UNVERIFIED: compiled and vetted only, not run on Windows.
func usersCanRead(path string) (bool, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return false, err
	}
	if dacl == nil {
		return true, nil // a NULL DACL grants everyone everything
	}
	var everyone []*windows.SID
	for _, k := range []windows.WELL_KNOWN_SID_TYPE{windows.WinBuiltinUsersSid, windows.WinAuthenticatedUserSid, windows.WinInteractiveSid, windows.WinWorldSid} {
		if sid, err := windows.CreateWellKnownSid(k); err == nil {
			everyone = append(everyone, sid)
		}
	}
	const (
		fileReadData = 0x1
		genericRead  = 0x80000000
		genericAll   = 0x10000000
		inheritOnly  = 0x08
	)
	allowed := false
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			return false, err
		}
		if ace.Header.AceFlags&inheritOnly != 0 || ace.Mask&(fileReadData|genericRead|genericAll) == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		match := false
		for _, e := range everyone {
			if sid.Equals(e) {
				match = true
				break
			}
		}
		if !match {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_DENIED_ACE_TYPE:
			return false, nil
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			allowed = true
		}
	}
	return allowed, nil
}

// hooksCannotRead says why hooks, which run as the developer, could not
// read the configuration at path, or "".
func hooksCannotRead(path string) string {
	ok, err := usersCanRead(path)
	switch {
	case err != nil:
		return "its access control list cannot be read (" + err.Error() + "), so it is unknown whether hooks can read it"
	case !ok:
		return "BUILTIN\\Users cannot read it, so no hook would apply guard mode; grant read access first: icacls \"" + path +
			"\" /grant *S-1-5-32-545:R (packaging/windows/install-service.ps1 and the Fleet install script do)"
	}
	return ""
}
