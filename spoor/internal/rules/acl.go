package rules

import "fmt"

// Windows access control analysis, kept free of Windows APIs so it is unit
// tested on every platform; load_windows.go feeds it the owner and the
// entries of a real security descriptor.

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

// aceInfo is one DACL entry as aclProblem needs it.
type aceInfo struct {
	allow       bool // an access-allowed entry of any form (basic, object, callback)
	inheritOnly bool
	mask        uint32
	sid         string // trustee of an allow entry; "" when it could not be read
	unknown     bool   // an entry type this check does not understand
	typ         uint8
}

// ACE types (winnt.h) that can appear in a DACL.
const (
	aceAllowed               = 0x00
	aceDenied                = 0x01
	aceSystemAudit           = 0x02
	aceSystemAlarm           = 0x03
	aceAllowedCompound       = 0x04
	aceAllowedObject         = 0x05
	aceDeniedObject          = 0x06
	aceSystemAuditObject     = 0x07
	aceSystemAlarmObject     = 0x08
	aceAllowedCallback       = 0x09
	aceDeniedCallback        = 0x0A
	aceAllowedCallbackObject = 0x0B
	aceDeniedCallbackObject  = 0x0C
	aceSystemAuditCallback   = 0x0D
	aceSystemAlarmCallback   = 0x0E
	aceSystemAuditCbObject   = 0x0F
	aceSystemAlarmCbObject   = 0x10
	aceSystemMandatoryLabel  = 0x11
	aceSystemResourceAttr    = 0x12
	aceSystemScopedPolicyID  = 0x13
	aceSystemProcessTrust    = 0x14
	aceSystemAccessFilter    = 0x15
)

// ACE classes for the trust check.
const (
	aceGrant   = iota // grants its mask to its trustee
	aceNoGrant        // denies, audits or labels: grants nothing
	aceUnknown        // not understood: the check fails closed on it
)

// classifyACE sorts an ACE type for the trust check. Every member of the
// access-allowed family grants rights: the callback (conditional) and object
// forms grant exactly like the basic one when their condition holds, so they
// must be read as grants. An unknown type (including the reserved compound
// type) is never assumed harmless.
func classifyACE(t uint8) int {
	switch t {
	case aceAllowed, aceAllowedObject, aceAllowedCallback, aceAllowedCallbackObject:
		return aceGrant
	case aceDenied, aceDeniedObject, aceDeniedCallback, aceDeniedCallbackObject,
		aceSystemAudit, aceSystemAlarm, aceSystemAuditObject, aceSystemAlarmObject,
		aceSystemAuditCallback, aceSystemAlarmCallback, aceSystemAuditCbObject, aceSystemAlarmCbObject,
		aceSystemMandatoryLabel, aceSystemResourceAttr, aceSystemScopedPolicyID,
		aceSystemProcessTrust, aceSystemAccessFilter:
		return aceNoGrant
	}
	return aceUnknown
}

// objectACE reports the allow forms whose trustee SID follows an object
// type header (Flags, then optional ObjectType and InheritedObjectType
// GUIDs).
func objectACE(t uint8) bool { return t == aceAllowedObject || t == aceAllowedCallbackObject }

// objectSIDOffset is the byte offset of the trustee SID inside an object
// ACE whose Flags field is flags: header (4), mask (4), flags (4), and a
// 16-byte GUID for each flag bit set.
func objectSIDOffset(flags uint32) int {
	off := 12
	if flags&0x1 != 0 { // ACE_OBJECT_TYPE_PRESENT
		off += 16
	}
	if flags&0x2 != 0 { // ACE_INHERITED_OBJECT_TYPE_PRESENT
		off += 16
	}
	return off
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
		if a.unknown && !a.inheritOnly {
			return fmt.Sprintf("has an access control entry of unsupported type %#x", a.typ)
		}
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
