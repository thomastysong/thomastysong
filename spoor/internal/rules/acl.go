package rules

import "fmt"

// Windows access control analysis, kept free of Windows APIs so it is unit
// tested on every platform; load_windows.go feeds it the owner and the
// access-allowed entries of a real security descriptor.

// Well-known SIDs that may own and write rule content.
const (
	sidSystem         = "S-1-5-18"
	sidAdministrators = "S-1-5-32-544"
	sidTrustedInst    = "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464"
	sidCreatorOwner   = "S-1-3-0"
	sidOwnerRights    = "S-1-3-4"
)

// writeMask is every right that lets the holder change content or who may
// change it: write/append data (add file / add subdirectory on a
// directory), delete child, delete, write DACL, write owner, and the
// generic write/all rights.
const writeMask = 0x2 | 0x4 | 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 | 0x40000000

type aceInfo struct {
	allow       bool
	inheritOnly bool
	mask        uint32
	sid         string
}

// aclProblem describes why an object with this owner and DACL could be
// changed by someone other than the system, administrators or self, or
// returns "". nilDACL is a descriptor without a DACL, which grants
// everyone everything.
func aclProblem(owner string, nilDACL bool, aces []aceInfo, self string) string {
	trusted := func(sid string) bool {
		switch sid {
		case sidSystem, sidAdministrators, sidTrustedInst:
			return true
		}
		return self != "" && sid == self
	}
	if !trusted(owner) {
		return fmt.Sprintf("is owned by %s, not by SYSTEM, Administrators or the calling user", owner)
	}
	if nilDACL {
		return "has no DACL (everyone has full control)"
	}
	for _, a := range aces {
		if !a.allow || a.inheritOnly || a.mask&writeMask == 0 {
			continue
		}
		switch {
		case trusted(a.sid):
		case a.sid == sidCreatorOwner || a.sid == sidOwnerRights:
			// Resolves to the owner, which was checked above.
		default:
			return fmt.Sprintf("grants write access to %s", a.sid)
		}
	}
	return ""
}
