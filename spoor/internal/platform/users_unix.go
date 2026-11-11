//go:build linux || darwin

package platform

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
)

// IsPrivileged reports whether the process runs as root.
func IsPrivileged() bool { return os.Geteuid() == 0 }

// CurrentUser returns the account this process runs as. Home is the account
// database's home directory when it exists, otherwise $HOME; it is empty when
// neither is an existing directory.
func CurrentUser() UserHome {
	uid := os.Getuid()
	u := UserHome{UID: strconv.Itoa(uid)}
	if name, home, ok := lookupUID(uint32(uid)); ok {
		u.Name = name
		// The database wins over $HOME: under sudo, HOME may still name the
		// invoking user's directory.
		if filepath.IsAbs(home) && isDir(home) {
			u.Home = filepath.Clean(home)
		}
	}
	if u.Name == "" {
		// No passwd entry (arbitrary-uid container): the environment is the
		// only source left.
		u.Name = cleanAccountName(firstNonEmpty(os.Getenv("USER"), os.Getenv("LOGNAME")))
	}
	if u.Home == "" {
		if h := os.Getenv("HOME"); filepath.IsAbs(h) && isDir(h) {
			u.Home = filepath.Clean(h)
		}
	}
	return u
}

// Users lists accounts with an existing home directory. A privileged caller
// gets every person's home on the machine; an unprivileged caller gets only
// its own. When $HOME names a different existing directory than the account
// database (CI containers do this), that directory is listed as a second
// home of the current user, because it is where an agent started from this
// environment keeps its files.
func Users() (users []UserHome, err error) {
	defer guard(&err)
	cur := CurrentUser()
	var list []UserHome
	if IsPrivileged() {
		list = append(list, listAccounts()...)
		for _, root := range homeRoots {
			list = append(list, scanHomeRoot(root)...)
		}
	}
	list = append(list, currentHomes(cur)...)
	users = dedupeUsers(runtime.GOOS, list)
	if len(users) == 0 {
		return nil, errors.New("platform: no user home directory found")
	}
	return users, nil
}

func currentHomes(cur UserHome) []UserHome {
	var out []UserHome
	if cur.Home != "" {
		out = append(out, cur)
	}
	if h := os.Getenv("HOME"); filepath.IsAbs(h) {
		if h = filepath.Clean(h); h != cur.Home && isDir(h) {
			out = append(out, UserHome{Name: cur.Name, UID: cur.UID, Home: h})
		}
	}
	return out
}

// scanHomeRoot lists the directories directly under /home or /Users. This
// catches directory-service accounts (LDAP, SSSD, mobile accounts) that have
// a home on disk but no entry in the local account database.
func scanHomeRoot(root string) []UserHome {
	d, err := os.Open(root)
	if err != nil {
		return nil
	}
	defer d.Close()
	var out []UserHome
	for seen := 0; seen < maxHomeEntries; {
		names, rerr := d.Readdirnames(1024)
		for _, name := range names {
			seen++
			if skipHomeName(runtime.GOOS, name) {
				continue
			}
			home := filepath.Join(root, name)
			// Stat, not Lstat: only an administrator can create entries in the
			// home root, so a symlinked home there is configuration, not attack.
			fi, err := os.Stat(home)
			if err != nil || !fi.IsDir() {
				continue
			}
			u := UserHome{Name: name, Home: home}
			if uid, ok := OwnerUID(fi); ok {
				u.UID = uid
				// Prefer the account name when the owner's registered home is
				// this directory; otherwise the directory name is the best label.
				if n, ok := parseUint32(uid); ok {
					if acct, h, ok := lookupUID(n); ok && filepath.IsAbs(h) && filepath.Clean(h) == home {
						u.Name = acct
					}
				}
			}
			out = append(out, u)
		}
		if rerr != nil {
			break
		}
	}
	return out
}

// userNames memoizes uid-to-name lookups for the duration of one scan.
type userNames struct{ memo map[string]string }

func newUserNames() *userNames { return &userNames{memo: make(map[string]string)} }

func (u *userNames) lookup(uid string) string {
	if name, ok := u.memo[uid]; ok {
		return name
	}
	name := ""
	if n, ok := parseUint32(uid); ok {
		name, _, _ = lookupUID(n)
	}
	u.memo[uid] = name
	return name
}
