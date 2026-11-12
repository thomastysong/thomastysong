package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/thomastysong/thomastysong/hawkbell/internal/privacy"
)

// TestConfigTextMatchesCode: the comments `hawkbell export config` writes
// must not contradict the code. Every file the header names exists in the
// source tree (it once named docs/FLEET.md, which never existed), and the
// tenant key comment states the minimum ReadKeyFile enforces
// (privacy.MinKeyLen; it once said 32 bytes).
func TestConfigTextMatchesCode(t *testing.T) {
	refs := regexp.MustCompile(`[\w./-]+\.md\b`).FindAllString(configHeader, -1)
	if len(refs) < 3 {
		t.Fatalf("header names %d documents: %q", len(refs), refs)
	}
	for _, ref := range refs {
		if _, err := os.Stat(filepath.Join("..", "..", filepath.FromSlash(ref))); err != nil {
			t.Errorf("header names %s: %v", ref, err)
		}
	}
	key := configComments()["privacy.hmac_key_file"]
	if want := fmt.Sprintf("at least %d bytes", privacy.MinKeyLen); !strings.Contains(key, want) {
		t.Errorf("privacy.hmac_key_file comment lacks %q:\n%s", want, key)
	}
	if regexp.MustCompile(`\b\d+\+ bytes`).MatchString(key) {
		t.Errorf("privacy.hmac_key_file comment states another minimum:\n%s", key)
	}
	// ReadKeyFile checks only the group and other bits, and only on POSIX
	// systems (a 0700 file passes; the Windows script writes this comment
	// too), and the comment sits above a value operators fill in.
	for _, bad := range []string{"0600 or stricter", "names none"} {
		if strings.Contains(key, bad) {
			t.Errorf("privacy.hmac_key_file comment says %q:\n%s", bad, key)
		}
	}
}
