package platform

import (
	"os"
	"path/filepath"
	"testing"
)

func TestKillSwitch(t *testing.T) {
	dir := t.TempDir()
	if disabledIn(dir) {
		t.Fatal("disabled without the file")
	}
	if disabledIn("") {
		t.Fatal("empty config dir must not disable")
	}
	if err := os.WriteFile(filepath.Join(dir, KillSwitchName), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if !disabledIn(dir) {
		t.Fatal("kill switch file ignored")
	}
	// A dangling symlink still counts: the operator's intent is the name existing.
	dir2 := t.TempDir()
	if err := os.Symlink(filepath.Join(dir2, "nowhere"), filepath.Join(dir2, KillSwitchName)); err == nil {
		if !disabledIn(dir2) {
			t.Fatal("dangling symlink kill switch ignored")
		}
	}
}
