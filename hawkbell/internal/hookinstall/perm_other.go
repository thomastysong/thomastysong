//go:build !unix && !windows

package hookinstall

import "os"

func ownerIDs(fi os.FileInfo) (uid, gid int, ok bool) { return 0, 0, false }

// linkCount is not available from a FileInfo here; ownership checks that
// use it do not apply (see rootEditProblem).
func linkCount(fi os.FileInfo) uint64 { return 1 }

func writableByOthers(path string, fi os.FileInfo) string { return "" }

func hardenIn(r *os.Root, name string, dir bool) error { return nil }

func linkTrusted(path string, fi os.FileInfo) bool { return false }

func chownFile(f *os.File, uid, gid int) error { return nil }

func fixNewDir(r *os.Root, name string, uid, gid int, give bool) error { return nil }
