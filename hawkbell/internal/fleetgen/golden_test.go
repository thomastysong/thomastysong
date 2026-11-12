package fleetgen

import (
	"bytes"
	"flag"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
)

var update = flag.Bool("update", false, "rewrite deploy/fleet/lib from Generate")

// libDir is deploy/fleet/lib in this checkout.
func libDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("no caller information")
	}
	return filepath.Join(filepath.Dir(file), "..", "..", "deploy", "fleet", "lib")
}

// TestGolden fails when the committed deploy/fleet/lib differs from
// Generate's output, including files that Generate no longer produces.
// Run with -update to rewrite the directory.
func TestGolden(t *testing.T) {
	files, err := Generate(Options{})
	if err != nil {
		t.Fatal(err)
	}
	dir := libDir(t)
	if *update {
		if err := os.RemoveAll(dir); err != nil {
			t.Fatal(err)
		}
		for name, b := range files {
			p := filepath.Join(dir, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, b, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		t.Logf("wrote %d files to %s", len(files), dir)
	}
	have := map[string]bool{}
	err = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		rel, err := filepath.Rel(dir, p)
		if err != nil {
			return err
		}
		have[filepath.ToSlash(rel)] = true
		return nil
	})
	if err != nil {
		t.Fatalf("read %s: %v (run go test ./internal/fleetgen -run TestGolden -update)", dir, err)
	}
	var names []string
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(n)))
		if err != nil {
			t.Errorf("%s: missing from deploy/fleet/lib (run with -update)", n)
			continue
		}
		// A checkout with CRLF line endings must still compare equal.
		got = bytes.ReplaceAll(got, []byte("\r\n"), []byte("\n"))
		if !bytes.Equal(got, files[n]) {
			t.Errorf("%s: differs from Generate output (run go test ./internal/fleetgen -run TestGolden -update)\n%s",
				n, firstDiff(string(got), string(files[n])))
		}
		delete(have, n)
	}
	for n := range have {
		t.Errorf("%s: in deploy/fleet/lib but not produced by Generate (stale; run with -update)", n)
	}
}

// firstDiff shows the first differing line.
func firstDiff(a, b string) string {
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	for i := 0; i < len(al) || i < len(bl); i++ {
		var x, y string
		if i < len(al) {
			x = al[i]
		}
		if i < len(bl) {
			y = bl[i]
		}
		if x != y {
			return "line " + itoa(i+1) + ":\n  committed: " + x + "\n  generated: " + y
		}
	}
	return "(no line difference)"
}

func itoa(i int) string {
	var b [20]byte
	n := len(b)
	for i >= 10 {
		n--
		b[n] = byte('0' + i%10)
		i /= 10
	}
	n--
	b[n] = byte('0' + i)
	return string(b[n:])
}
