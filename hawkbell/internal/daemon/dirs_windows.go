//go:build windows

package daemon

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

// Windows permissions are ACLs; mode bits mean nothing. Every directory the
// daemon owns gets an explicit, protected DACL (no entries inherited from
// ProgramData, whose default lets Users create files): SYSTEM and
// Administrators full control, plus what each kind needs. Directories are
// also handed to Administrators as owner, which repairs one a standard user
// pre-created (ProgramData lets them). UNVERIFIED: compiled and vetted only,
// not run on Windows hardware.

const (
	sddlBase = "O:BAG:SYD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	// FILE_GENERIC_READ | FILE_GENERIC_EXECUTE for Users on the bundle:
	// hooks run as the user and read the installed rules.
	sddlUsersRX = "(A;OICI;0x1200a9;;;BU)"
	// FILE_GENERIC_READ | WRITE | EXECUTE | DELETE ("modify") for one
	// account on its own spool directory.
	modifyMask = "0x1301bf"
)

func currentUID() string {
	tok := windows.GetCurrentProcessToken()
	u, err := tok.GetTokenUser()
	if err != nil {
		return ""
	}
	return u.User.Sid.String()
}

// lookupGroup: output.group is a POSIX notion; the outbox is readable by
// SYSTEM and Administrators, which is what a Fluent Bit service runs as.
func lookupGroup(string) (int, bool) { return -1, false }

// secureDataDir creates the data directory but leaves its ACL alone: it is
// also the configuration directory the hook reads, and the installer gives
// it the ACL it needs.
func secureDataDir(path string, privileged bool) error {
	if err := os.MkdirAll(path, 0o755); err != nil {
		return err
	}
	return checkPlainDir(path)
}

func checkPlainDir(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if fi.Mode()&(os.ModeSymlink|os.ModeIrregular) != 0 {
		return errSymlinkDir
	}
	if !fi.IsDir() {
		return errors.New("not a directory")
	}
	return nil
}

func secureDir(path string, kind dirKind, privileged bool, ownerUID string, gid int) error {
	if err := os.Mkdir(path, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
		return err
	}
	if err := checkPlainDir(path); err != nil {
		return err
	}
	if !privileged {
		return nil
	}
	sddl := sddlBase
	switch kind {
	case dirBundle:
		sddl += sddlUsersRX
	case dirUserSpool:
		if _, err := windows.StringToSid(ownerUID); err != nil {
			return fmt.Errorf("account id %q is not a SID", ownerUID)
		}
		sddl += "(A;OICI;" + modifyMask + ";;;" + ownerUID + ")"
	case dirData, dirPrivate, dirOutbox, dirSpoolRoot:
	default:
		return fmt.Errorf("unknown directory kind %d", kind)
	}
	return applySDDL(path, sddl)
}

func applySDDL(path, sddl string) error {
	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return err
	}
	info := windows.SECURITY_INFORMATION(windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION)
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, owner, nil, dacl, nil); err != nil {
		// Taking ownership needs a privilege the token may not hold
		// enabled; the DACL alone still closes access.
		info = windows.DACL_SECURITY_INFORMATION | windows.PROTECTED_DACL_SECURITY_INFORMATION
		if err2 := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info, nil, nil, dacl, nil); err2 != nil {
			return fmt.Errorf("set ACL: %w", err2)
		}
	}
	return nil
}

// secureSegmentFile: segments inherit the outbox DACL.
func secureSegmentFile(string, bool, int) error { return nil }
