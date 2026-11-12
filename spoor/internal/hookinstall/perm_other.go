//go:build !unix && !windows

package hookinstall

import "os"

func ownerIDs(fi os.FileInfo) (uid, gid int, ok bool) { return 0, 0, false }

func writableByOthers(path string, fi os.FileInfo) string { return "" }

func hardenIn(r *os.Root, name string, dir bool) error { return nil }

func linkTrusted(path string, fi os.FileInfo) bool { return false }

func giveTo(r *os.Root, name string, uid, gid int) error { return nil }
