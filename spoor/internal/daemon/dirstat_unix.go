//go:build unix

package daemon

import (
	"fmt"
	"os"
	"strconv"
	"syscall"
)

func modeString(m os.FileMode) string {
	v := uint32(m.Perm())
	if m&os.ModeSetgid != 0 {
		v |= 0o2000
	}
	if m&os.ModeSetuid != 0 {
		v |= 0o4000
	}
	if m&os.ModeSticky != 0 {
		v |= 0o1000
	}
	return fmt.Sprintf("%04o", v)
}

// checkDir compares a directory with what the daemon makes of it.
func checkDir(name, path string, kind dirKind, ownerUID string) DirStatus {
	d := DirStatus{Name: name, Path: path, Want: modeString(unixModes[kind])}
	fi, err := os.Lstat(path)
	if err != nil {
		d.Problem = "missing (the daemon creates it at start)"
		return d
	}
	d.Exists = true
	if fi.Mode()&os.ModeSymlink != 0 {
		if kind != dirData {
			d.Problem = "is a symbolic link; the daemon refuses it"
			return d
		}
		if fi, err = os.Stat(path); err != nil || !fi.IsDir() {
			d.Problem = "is a symbolic link to nothing usable"
			return d
		}
	}
	if !fi.IsDir() {
		d.Problem = "is not a directory"
		return d
	}
	d.Mode = modeString(fi.Mode())
	wantUID := strconv.Itoa(0)
	if ownerUID != "" {
		wantUID = ownerUID
	} else if os.Geteuid() != 0 {
		wantUID = strconv.Itoa(os.Geteuid())
	}
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		d.Owner = strconv.FormatUint(uint64(st.Uid), 10)
		d.Group = strconv.FormatUint(uint64(st.Gid), 10)
	}
	perm := fi.Mode().Perm()
	switch {
	case d.Owner != "" && d.Owner != wantUID:
		d.Problem = "owned by uid " + d.Owner + ", want " + wantUID
	case kind == dirData:
		d.Want = "0711 (or 0755)"
		if perm&0o022 != 0 {
			d.Problem = "writable by group or others"
		} else if perm&0o001 == 0 {
			d.Problem = "not traversable by others: hooks cannot reach their spool or read the bundle"
		}
	case d.Mode != d.Want:
		d.Problem = "mode " + d.Mode + ", want " + d.Want
	}
	d.OK = d.Problem == ""
	return d
}

// checkStateFile checks state.db: root-owned, 0600, a regular file.
func checkStateFile(path string) DirStatus {
	d := DirStatus{Name: "state.db", Path: path, Want: "0600"}
	fi, err := os.Lstat(path)
	if err != nil {
		d.Problem = "missing (the daemon creates it at start)"
		return d
	}
	d.Exists = true
	if !fi.Mode().IsRegular() {
		d.Problem = "is not a regular file"
		return d
	}
	d.Mode = modeString(fi.Mode())
	if st, ok := fi.Sys().(*syscall.Stat_t); ok {
		d.Owner = strconv.FormatUint(uint64(st.Uid), 10)
		d.Group = strconv.FormatUint(uint64(st.Gid), 10)
		if os.Geteuid() == 0 && st.Uid != 0 {
			d.Problem = "not owned by root: Fleet policies would read a file another user controls"
		}
	}
	if d.Problem == "" && fi.Mode().Perm()&0o077 != 0 {
		d.Problem = "readable or writable by group or others"
	}
	d.OK = d.Problem == ""
	return d
}
