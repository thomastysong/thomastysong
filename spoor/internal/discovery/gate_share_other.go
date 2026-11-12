//go:build !windows && !linux && !darwin && !freebsd && !netbsd && !openbsd && !dragonfly

package discovery

import "os"

// openShared exists for Windows only (FILE_SHARE_DELETE); elsewhere the
// os.Root open is kept.
func (o *rootOpener) openShared(root, rel string, li os.FileInfo) (*os.File, bool, error) {
	return nil, false, nil
}
