//go:build !linux

package platform

// capPrivileged is false where privilege is not split into capabilities
// that hawkbell checks: macOS and the BSDs need uid 0, Windows an elevated
// token.
func capPrivileged() bool { return false }
