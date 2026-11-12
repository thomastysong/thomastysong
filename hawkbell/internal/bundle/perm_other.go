//go:build !unix

package bundle

import "os"

// checkOwner does nothing where there are no Unix mode bits. On Windows the
// destination's ACL decides who can change installed content, and setting it
// is the installer's job (see the package comment, "Not supported").
func checkOwner(string, os.FileInfo) error { return nil }
