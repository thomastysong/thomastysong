//go:build !unix

package osqext

// Mode bits mean nothing on Windows; the data directory's ACL is set by the
// installer and the daemon.
func checkHostIDDir(dir string) error { return nil }
