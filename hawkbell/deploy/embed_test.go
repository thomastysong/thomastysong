package deploy

import (
	"io/fs"
	"os"
	"path"
	"slices"
	"strings"
	"testing"
)

// TestEmbedsAllContent compares the embedded tree with deploy/ on disk:
// every file is embedded except notContent and, inside subdirectories,
// names starting with "." or "_" (go:embed directory rules). A file added
// under deploy/ without an embed pattern fails here.
func TestEmbedsAllContent(t *testing.T) {
	var want []string
	err := fs.WalkDir(os.DirFS("."), ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if p == "." {
			return nil
		}
		if !strings.Contains(p, "/") {
			// Files directly in deploy/ (this package's Go files) are not
			// content.
			return nil
		}
		hidden := strings.HasPrefix(d.Name(), ".") || strings.HasPrefix(d.Name(), "_")
		if hidden && strings.Count(p, "/") > 1 {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !d.IsDir() && !slices.Contains(notContent, p) {
			want = append(want, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	err = fs.WalkDir(content, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			got = append(got, p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range want {
		if !slices.Contains(got, p) {
			t.Errorf("%s is under deploy/ but not embedded: add it to the go:embed patterns in embed.go (or to notContent)", p)
		}
	}
	for _, p := range got {
		if !slices.Contains(want, p) {
			t.Errorf("%s is embedded but is not content", p)
		}
	}
	for _, p := range notContent {
		if _, err := os.Stat(p); err != nil {
			t.Errorf("notContent lists %s: %v", p, err)
		}
		if _, err := fs.Stat(content, p); err == nil {
			t.Errorf("%s is embedded", p)
		}
		if b := path.Base(p); b != "VERIFIED.md" && b != "verify.sh" {
			t.Errorf("notContent lists %s, which is not a verification record", p)
		}
	}
	if len(got) == 0 {
		t.Fatal("nothing embedded")
	}
}
