//go:build !unix

package hookinstall

import "os"

// openNoFollow opens for reading. Windows has no O_NOFOLLOW; the caller
// compares the opened handle with its lstat result, which catches a link
// swapped in between. The handle is closed as soon as the bytes are read.
func openNoFollow(path string) (*os.File, error) { return os.Open(path) }

func isNotDir(err error) bool { return false }
