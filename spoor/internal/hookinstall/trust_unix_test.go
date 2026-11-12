//go:build unix

package hookinstall

import (
	"os"
	"testing"
)

// TestMain lets an unprivileged test run own "managed" files: production
// accepts only uid 0.
func TestMain(m *testing.M) {
	trustedUID = os.Getuid()
	os.Exit(m.Run())
}
