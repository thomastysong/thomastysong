//go:build linux

package platform

import (
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

// Paths are variables so tests can substitute fixtures.
var (
	homeRoots         = []string{"/home"}
	etcPasswdPath     = "/etc/passwd"
	etcLoginDefsPath  = "/etc/login.defs"
	rootHomePath      = "/root"
	maxPasswdFileSize = int64(8 << 20)
)

// passwdCache avoids re-reading /etc/passwd on every process scan. It is
// keyed on the file's identity and mtime, which change when an account is
// added (tools replace the file atomically).
var passwdCache struct {
	sync.Mutex
	path    string
	mtime   time.Time
	size    int64
	id      string
	loaded  bool
	entries []passwdEntry
	byUID   map[uint32]int
}

// loadPasswd reads the local account database directly. CGO is off, so there
// is no NSS: accounts that exist only in LDAP or SSSD have no name here, and
// their processes are reported with a uid and an empty User.
func loadPasswd() ([]passwdEntry, map[uint32]int) {
	c := &passwdCache
	c.Lock()
	defer c.Unlock()
	fi, err := os.Stat(etcPasswdPath)
	if err != nil {
		c.loaded, c.path, c.entries, c.byUID = true, etcPasswdPath, nil, nil
		return nil, nil
	}
	id := FileID(fi, "")
	if c.loaded && c.path == etcPasswdPath && c.size == fi.Size() && c.mtime.Equal(fi.ModTime()) && c.id == id {
		return c.entries, c.byUID
	}
	data, err := readFileLimit(etcPasswdPath, maxPasswdFileSize)
	if err != nil {
		return nil, nil
	}
	entries := parsePasswd(data)
	byUID := make(map[uint32]int, len(entries))
	for i, e := range entries {
		// getpwuid returns the first entry when several names share a uid.
		if _, dup := byUID[e.uid]; !dup {
			byUID[e.uid] = i
		}
	}
	c.loaded, c.path, c.size, c.mtime, c.id = true, etcPasswdPath, fi.Size(), fi.ModTime(), id
	c.entries, c.byUID = entries, byUID
	return entries, byUID
}

func lookupUID(uid uint32) (name, home string, ok bool) {
	entries, byUID := loadPasswd()
	i, ok := byUID[uid]
	if !ok {
		return "", "", false
	}
	return entries[i].name, entries[i].home, true
}

// listAccounts returns login accounts from /etc/passwd whose home exists.
// It finds homes outside /home (for example /var/lib/jenkins or /data/u).
func listAccounts() []UserHome {
	entries, _ := loadPasswd()
	uidMin := uint32(1000)
	if b, err := readFileLimit(etcLoginDefsPath, maxSmallFile); err == nil {
		uidMin = parseUIDMin(b)
	}
	var out []UserHome
	rootSeen := false
	for _, e := range entries {
		if !humanAccount(e, uidMin) {
			continue
		}
		home := filepath.Clean(e.home)
		if !isDir(home) {
			continue
		}
		if home == rootHomePath {
			rootSeen = true
		}
		out = append(out, UserHome{Name: e.name, UID: strconv.FormatUint(uint64(e.uid), 10), Home: home})
	}
	// An image without a passwd file still has /root.
	if !rootSeen && isDir(rootHomePath) {
		out = append(out, UserHome{Name: "root", UID: "0", Home: rootHomePath})
	}
	return out
}
