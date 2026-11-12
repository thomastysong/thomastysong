//go:build windows

package platform

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// UNVERIFIED: this file was compiled and vetted for windows/amd64 and
// windows/arm64 but not executed in the build environment.

const profileListKey = `SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList`

var (
	privilegedOnce sync.Once
	privilegedVal  bool
	identityOnce   sync.Once
	identitySID    string
	identityHome   string
	currentOnce    sync.Once
	currentVal     UserHome
)

// IsAdmin is IsPrivileged on Windows: an elevated token both reads every
// profile and sets other accounts' ACLs.
func IsAdmin() bool { return IsPrivileged() }

// IsSystemAccount reports whether uid (Proc.UID, a SID string) is one of
// the service accounts protected processes run as (LocalSystem, LOCAL
// SERVICE, NETWORK SERVICE), or empty: an elevated monitor with
// SeDebugPrivilege that cannot read a process's token at all is looking at
// a protected process (csrss, smss, services, a PPL anti-malware service).
// UNVERIFIED: compiled, not executed in the build environment.
func IsSystemAccount(uid string) bool {
	switch uid {
	case "", "S-1-5-18", "S-1-5-19", "S-1-5-20":
		return true
	}
	return false
}

// IsPrivileged reports whether the process token is elevated (an
// administrator past UAC, or LocalSystem). Elevation cannot change during
// the life of a process, so the answer is cached.
func IsPrivileged() bool {
	privilegedOnce.Do(func() {
		var tok windows.Token
		if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok); err != nil {
			return
		}
		defer tok.Close()
		privilegedVal = tok.IsElevated()
	})
	return privilegedVal
}

// currentIdentity returns the SID and profile directory of this process's
// account using only the token and the registry. It deliberately does not
// resolve the account name: that is an LSA round trip (possibly to a domain
// controller), and this function is on the path of every hook invocation.
func currentIdentity() (sid, home string) {
	identityOnce.Do(func() {
		var tok windows.Token
		if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_QUERY, &tok); err == nil {
			defer tok.Close()
			if tu, err := tok.GetTokenUser(); err == nil && tu.User.Sid != nil {
				identitySID = tu.User.Sid.String()
			}
			if identitySID != "" {
				if k, err := registry.OpenKey(registry.LOCAL_MACHINE, profileListKey, registry.QUERY_VALUE|registry.WOW64_64KEY); err == nil {
					if p := profileImagePath(k, identitySID); p != "" && isDir(p) {
						identityHome = p
					}
					k.Close()
				}
			}
			if identityHome == "" {
				if dir, err := tok.GetUserProfileDirectory(); err == nil && isDir(dir) {
					identityHome = dir
				}
			}
		}
		if identityHome == "" {
			if h := os.Getenv("USERPROFILE"); filepath.IsAbs(h) && isDir(h) {
				identityHome = filepath.Clean(h)
			}
		}
	})
	return identitySID, identityHome
}

func currentHome() string {
	_, home := currentIdentity()
	return home
}

// CurrentUser returns the account this process runs as: bare account name
// (no domain), SID, and profile directory.
func CurrentUser() UserHome {
	currentOnce.Do(func() {
		sid, home := currentIdentity()
		u := UserHome{UID: sid, Home: home}
		if sid != "" {
			if s, err := windows.StringToSid(sid); err == nil {
				if name, _, _, err := s.LookupAccount(""); err == nil {
					u.Name = name
				}
			}
		}
		if u.Name == "" {
			u.Name = cleanAccountName(os.Getenv("USERNAME"))
		}
		currentVal = u
	})
	return currentVal
}

// Users lists accounts with an existing profile directory. An elevated
// caller gets every profile registered in ProfileList plus any other
// directory under the profiles root; anyone else gets only the current user.
func Users() (users []UserHome, err error) {
	defer guard(&err)
	cur := CurrentUser()
	var list []UserHome
	if IsPrivileged() {
		profiles, root := registryProfiles()
		list = append(list, profiles...)
		list = append(list, scanProfilesRoot(root)...)
	}
	if cur.Home != "" {
		list = append(list, cur)
	}
	users = dedupeUsers(runtime.GOOS, list)
	if len(users) == 0 {
		return nil, errors.New("platform: no user profile directory found")
	}
	return users, nil
}

// isAccountSID keeps local and domain accounts (S-1-5-21-...) and Entra ID
// accounts (S-1-12-1-...) and drops service identities such as LocalSystem
// (S-1-5-18) and IIS application pools (S-1-5-82-...).
func isAccountSID(sid string) bool {
	return strings.HasPrefix(sid, "S-1-5-21-") || strings.HasPrefix(sid, "S-1-12-1-")
}

// registryProfiles reads the SID-to-profile-directory map Windows itself
// maintains. It also returns the profiles root (normally C:\Users).
func registryProfiles() (profiles []UserHome, root string) {
	root = filepath.Join(firstNonEmpty(os.Getenv("SystemDrive"), "C:")+`\`, "Users")
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, profileListKey, registry.READ|registry.WOW64_64KEY)
	if err != nil {
		return nil, root
	}
	defer k.Close()
	if v, _, err := k.GetStringValue("ProfilesDirectory"); err == nil {
		if p, err := registry.ExpandString(v); err == nil && filepath.IsAbs(p) {
			root = filepath.Clean(p)
		}
	}
	sids, err := k.ReadSubKeyNames(-1)
	if err != nil {
		return nil, root
	}
	if len(sids) > maxHomeEntries {
		sids = sids[:maxHomeEntries]
	}
	for _, sidStr := range sids {
		if !isAccountSID(sidStr) {
			continue
		}
		home := profileImagePath(k, sidStr)
		if home == "" || skipHomeName(runtime.GOOS, filepath.Base(home)) || !isDir(home) {
			continue
		}
		u := UserHome{Name: filepath.Base(home), UID: sidStr, Home: home}
		// The profile directory name can differ from the account name
		// ("jane.CORP", "jane.000"); ask LSA, and keep the directory name when
		// the account can no longer be resolved (deleted or offline domain).
		if sid, err := windows.StringToSid(sidStr); err == nil {
			if name, _, _, err := sid.LookupAccount(""); err == nil && name != "" {
				u.Name = name
			}
		}
		profiles = append(profiles, u)
	}
	return profiles, root
}

func profileImagePath(list registry.Key, sid string) string {
	k, err := registry.OpenKey(list, sid, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue("ProfileImagePath")
	if err != nil {
		return ""
	}
	// Stored as an expandable string, normally with no variables in it.
	if p := expandSystemDrive(v, systemDrive()); p != "" {
		v = p
	} else if p, err := registry.ExpandString(v); err == nil {
		v = p
	}
	if !filepath.IsAbs(v) {
		return ""
	}
	return filepath.Clean(v)
}

// scanProfilesRoot adds profile directories that have no ProfileList entry
// (left behind by deleted accounts, or copied in). Their SID is unknown.
func scanProfilesRoot(root string) []UserHome {
	d, err := os.Open(root)
	if err != nil {
		return nil
	}
	defer d.Close()
	var out []UserHome
	for seen := 0; seen < maxHomeEntries; {
		entries, rerr := d.ReadDir(1024)
		for _, e := range entries {
			seen++
			name := e.Name()
			// Type() comes from the directory listing: junctions such as
			// "All Users" and "Default User" are reparse points, not directories.
			if skipHomeName(runtime.GOOS, name) || !e.IsDir() || e.Type()&os.ModeSymlink != 0 {
				continue
			}
			out = append(out, UserHome{Name: name, Home: filepath.Join(root, name)})
		}
		if rerr != nil {
			break
		}
	}
	return out
}
