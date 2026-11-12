package platform

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestOpenNoFollowRegularFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	writeFile(t, path, `{"hooks":{}}`)
	f, err := OpenNoFollow(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	b, err := io.ReadAll(f)
	if err != nil || string(b) != `{"hooks":{}}` {
		t.Errorf("read %q, %v", b, err)
	}
	if f.Name() != path {
		t.Errorf("Name = %q", f.Name())
	}
	// Seeking and re-reading work: the handle is an ordinary file.
	if _, err := f.Seek(2, io.SeekStart); err != nil {
		t.Error(err)
	}
	if b, _ := io.ReadAll(f); string(b) != `hooks":{}}` {
		t.Errorf("after seek: %q", b)
	}
}

func TestOpenNoFollowRefusals(t *testing.T) {
	dir := t.TempDir()
	if _, err := OpenNoFollow(filepath.Join(dir, "missing")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: %v", err)
	}
	if f, err := OpenNoFollow(dir); err == nil {
		f.Close()
		t.Error("opened a directory")
	} else if runtime.GOOS != "windows" && !errors.Is(err, ErrNotRegular) {
		t.Errorf("directory: %v, want ErrNotRegular", err)
	}
	if f, err := OpenNoFollow(""); err == nil {
		f.Close()
		t.Error("opened the empty path")
	}
	if f, err := OpenNoFollow("a\x00b"); err == nil {
		f.Close()
		t.Error("opened a path with a NUL")
	}
}

func TestOpenBeneath(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	writeFile(t, filepath.Join(root, ".claude", "settings.json"), "inside")
	writeFile(t, filepath.Join(outside, "secret"), "outside")

	f, err := OpenBeneath(root, filepath.Join(".claude", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	b, _ := io.ReadAll(f)
	f.Close()
	if string(b) != "inside" {
		t.Errorf("read %q", b)
	}

	rel, err := filepath.Rel(root, filepath.Join(outside, "secret"))
	if err != nil {
		t.Fatal(err)
	}
	escapes := []string{
		rel, // ../<other tmp>/secret
		filepath.Join("..", filepath.Base(outside), "secret"),
		filepath.Join(".claude", "..", "..", filepath.Base(outside), "secret"),
		filepath.Join(outside, "secret"), // absolute
		"..",
		"",
	}
	for _, p := range escapes {
		if f, err := OpenBeneath(root, p); err == nil {
			b, _ := io.ReadAll(f)
			f.Close()
			t.Errorf("OpenBeneath(root, %q) escaped and read %q", p, b)
		}
	}
	if f, err := OpenBeneath(root, ".claude"); err == nil {
		f.Close()
		t.Error("opened a directory")
	} else if runtime.GOOS != "windows" && !errors.Is(err, ErrNotRegular) {
		t.Errorf("directory: %v, want ErrNotRegular", err)
	}
	if _, err := OpenBeneath(root, "nope"); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing: %v", err)
	}
	if _, err := OpenBeneath(filepath.Join(root, "no-such-root"), "x"); err == nil {
		t.Error("missing root accepted")
	}
	// ".." that stays inside the root is fine.
	if f, err := OpenBeneath(root, filepath.Join(".claude", "..", ".claude", "settings.json")); err != nil {
		t.Errorf("inner dot-dot refused: %v", err)
	} else {
		f.Close()
	}
}

func TestFileIdentity(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		if got := FileID(nil, "x"); got != "" {
			t.Errorf("FileID on %s = %q, want empty", runtime.GOOS, got)
		}
		t.Skip("file identity is not implemented on this OS")
	}
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.jsonl"), filepath.Join(dir, "b.jsonl")
	writeFile(t, a, "one")
	writeFile(t, b, "two")
	fa, err := os.Stat(a)
	if err != nil {
		t.Fatal(err)
	}
	fb, err := os.Stat(b)
	if err != nil {
		t.Fatal(err)
	}
	ida, idb := FileID(fa, a), FileID(fb, b)
	if ida == "" || idb == "" || ida == idb {
		t.Fatalf("ids %q %q must be non-empty and distinct", ida, idb)
	}
	if !strings.Contains(ida, ":") {
		t.Errorf("id %q is not volume:index", ida)
	}
	if again := FileID(fa, a); again != ida {
		t.Errorf("id not stable: %q then %q", ida, again)
	}
	// With no FileInfo the path alone is enough.
	if got := FileID(nil, a); got != ida {
		t.Errorf("FileID(nil, path) = %q, want %q", got, ida)
	}
	if got := FileID(nil, ""); got != "" {
		t.Errorf("FileID(nil, \"\") = %q", got)
	}
	if got := FileID(nil, filepath.Join(dir, "missing")); got != "" {
		t.Errorf("FileID of a missing file = %q", got)
	}

	// An open handle keeps its identity across a rename (log rotation), and
	// the path then names a different file.
	// OpenNoFollow shares delete access on Windows, so the rename below is
	// allowed while the handle is open, as it must be for a tailed log.
	f, err := OpenNoFollow(a)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	open, err := FileIDOf(f)
	if err != nil || open != ida {
		t.Fatalf("FileIDOf = %q, %v; want %q", open, err, ida)
	}
	rotated := filepath.Join(dir, "a.jsonl.1")
	if err := os.Rename(a, rotated); err != nil {
		t.Fatal(err)
	}
	writeFile(t, a, "new generation")
	if got, _ := FileIDOf(f); got != ida {
		t.Errorf("identity of the open file changed on rename: %q", got)
	}
	if got := FileID(nil, rotated); got != ida {
		t.Errorf("renamed file id = %q, want %q", got, ida)
	}
	if got := FileID(nil, a); got == ida || got == "" {
		t.Errorf("replacement file has id %q, want a new one (old %q)", got, ida)
	}
	if _, err := FileIDOf(nil); err == nil {
		t.Error("FileIDOf(nil) succeeded")
	}
}

func TestPathOwner(t *testing.T) {
	if runtime.GOOS != "linux" && runtime.GOOS != "darwin" && runtime.GOOS != "windows" {
		t.Skip("ownership is not implemented on this OS")
	}
	path := filepath.Join(t.TempDir(), "f")
	writeFile(t, path, "x")
	owner, ok := PathOwner(path)
	if !ok || owner == "" {
		t.Fatalf("PathOwner = %q %v", owner, ok)
	}
	if cur := CurrentUser(); runtime.GOOS != "windows" && owner != cur.UID {
		t.Errorf("owner %q, want current user %q", owner, cur.UID)
	}
	if _, ok := PathOwner(filepath.Join(t.TempDir(), "missing")); ok {
		t.Error("PathOwner of a missing file succeeded")
	}
	if _, ok := OwnerUID(nil); ok {
		t.Error("OwnerUID(nil) succeeded")
	}
}
