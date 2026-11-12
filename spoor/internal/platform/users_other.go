//go:build !linux && !darwin && !windows

package platform

import (
	"errors"
	"os"
	"os/user"
	"path/filepath"
)

// IsPrivileged reports whether the process runs as root.
func IsPrivileged() bool { return os.Geteuid() == 0 }

// CurrentUser returns the account this process runs as.
func CurrentUser() UserHome {
	var u UserHome
	if cu, err := user.Current(); err == nil {
		u = UserHome{Name: cu.Username, UID: cu.Uid, Home: cu.HomeDir}
	}
	if u.Home == "" || !isDir(u.Home) {
		u.Home = ""
		if h, err := os.UserHomeDir(); err == nil && filepath.IsAbs(h) && isDir(h) {
			u.Home = h
		}
	}
	return u
}

func currentHome() string { return CurrentUser().Home }

// Users returns only the current user on this OS: enumerating other
// accounts' homes is implemented for linux, darwin and windows.
func Users() ([]UserHome, error) {
	cur := CurrentUser()
	if cur.Home == "" {
		return nil, errors.New("platform: no user home directory found")
	}
	return []UserHome{cur}, nil
}
