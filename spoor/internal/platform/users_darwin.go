//go:build darwin

package platform

import (
	"os/user"
	"strconv"
)

var homeRoots = []string{"/Users"}

// lookupUID asks Open Directory through libSystem (os/user needs no cgo on
// macOS), so network and mobile accounts resolve too.
func lookupUID(uid uint32) (name, home string, ok bool) {
	u, err := user.LookupId(strconv.FormatUint(uint64(uid), 10))
	if err != nil {
		return "", "", false
	}
	return u.Username, u.HomeDir, true
}

// listAccounts is empty on macOS: every person's home is under /Users, and
// enumerating Open Directory would need dscl or cgo.
func listAccounts() []UserHome { return nil }
