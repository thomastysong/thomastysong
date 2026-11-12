//go:build !unix && !windows

package daemon

import "os"

func checkDir(name, path string, kind dirKind, ownerUID string) DirStatus {
	d := DirStatus{Name: name, Path: path}
	fi, err := os.Lstat(path)
	if err != nil {
		d.Problem = "missing (the daemon creates it at start)"
		return d
	}
	d.Exists = true
	d.OK = fi.IsDir()
	if !d.OK {
		d.Problem = "is not a directory"
	}
	return d
}

func checkStateFile(path string) DirStatus {
	d := DirStatus{Name: "state.db", Path: path}
	fi, err := os.Lstat(path)
	if err != nil {
		d.Problem = "missing (the daemon creates it at start)"
		return d
	}
	d.Exists = true
	d.OK = fi.Mode().IsRegular()
	return d
}
