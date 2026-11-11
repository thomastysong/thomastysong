package platform

import (
	"path/filepath"
	"sort"
	"strings"
)

// skipHomeName reports whether a directory directly under the home root
// (/home, /Users, C:\Users) is known not to be a person's home.
func skipHomeName(goos, name string) bool {
	if name == "" || name[0] == '.' {
		return true
	}
	switch goos {
	case "darwin":
		return strings.EqualFold(name, "Shared") || strings.EqualFold(name, "Guest")
	case "windows":
		l := strings.ToLower(name)
		// "Default", "Default User", "defaultuser0", "DefaultAppPool": profile
		// templates and setup accounts. "All Users" is a junction to ProgramData.
		return l == "public" || l == "all users" || strings.HasPrefix(l, "default")
	default:
		return name == "lost+found"
	}
}

// dedupeUsers keeps the first entry for each home directory and returns the
// list ordered by home, so repeated scans produce the same order.
func dedupeUsers(goos string, list []UserHome) []UserHome {
	seen := make(map[string]bool, len(list))
	out := make([]UserHome, 0, len(list))
	for _, u := range list {
		if u.Home == "" {
			continue
		}
		key := u.Home
		if goos == "windows" {
			key = strings.ToLower(strings.TrimRight(key, `\/`))
		} else {
			key = filepath.ToSlash(filepath.Clean(key))
		}
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, u)
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Home < out[j].Home })
	return out
}

// cleanAccountName rejects names that could not be a real account name. It is
// applied to names taken from the environment, which the agent controls.
func cleanAccountName(s string) string {
	if s == "" || len(s) > 256 {
		return ""
	}
	for _, r := range s {
		if r < 0x20 || r == 0x7f || r == '/' || r == ':' {
			return ""
		}
	}
	return s
}

type passwdEntry struct {
	name  string
	uid   uint32
	home  string
	shell string
}

// parsePasswd parses passwd(5) text. Malformed lines are skipped: the file is
// admin-owned, but in a container image it can be anything.
func parsePasswd(data []byte) []passwdEntry {
	const maxEntries = 200_000
	var out []passwdEntry
	for len(data) > 0 && len(out) < maxEntries {
		var line []byte
		if i := indexByte(data, '\n'); i >= 0 {
			line, data = data[:i], data[i+1:]
		} else {
			line, data = data, nil
		}
		if len(line) == 0 || len(line) > 4096 || line[0] == '#' || line[0] == '+' || line[0] == '-' {
			continue
		}
		f := strings.Split(strings.TrimRight(string(line), "\r"), ":")
		if len(f) < 6 || f[0] == "" {
			continue
		}
		uid, ok := parseUint32(f[2])
		if !ok {
			continue
		}
		e := passwdEntry{name: f[0], uid: uid, home: f[5]}
		if len(f) > 6 {
			e.shell = f[6]
		}
		out = append(out, e)
	}
	return out
}

// humanAccount reports whether a passwd entry is an account a person (or
// root) logs in to, as opposed to a service account.
func humanAccount(e passwdEntry, uidMin uint32) bool {
	if !strings.HasPrefix(e.home, "/") || filepath.ToSlash(filepath.Clean(e.home)) == "/" {
		return false
	}
	if e.uid == 0 {
		return true
	}
	// 65534 is nobody; 4294967294 is the 32-bit nfsnobody.
	if e.uid < uidMin || e.uid == 65534 || e.uid >= 4294967294 {
		return false
	}
	switch filepath.Base(e.shell) {
	case "nologin", "false", "sync", "shutdown", "halt":
		return false
	}
	return true
}

// parseUIDMin reads UID_MIN from login.defs(5) text; 1000 when absent.
func parseUIDMin(data []byte) uint32 {
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Fields(line)
		if len(f) >= 2 && f[0] == "UID_MIN" {
			if v, ok := parseUint32(f[1]); ok && v > 0 && v < 65534 {
				return v
			}
		}
	}
	return 1000
}

func parseUint32(s string) (uint32, bool) {
	if s == "" || len(s) > 10 {
		return 0, false
	}
	var n uint64
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + uint64(c-'0')
	}
	if n > 0xffffffff {
		return 0, false
	}
	return uint32(n), true
}

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}
