package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"
)

// Fixed keys keep failures reproducible. otherPriv plays the attacker who
// can produce valid signatures, just not with a trusted key.
var (
	testPriv  = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	testPub   = testPriv.Public().(ed25519.PublicKey)
	otherPriv = ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	otherPub  = otherPriv.Public().(ed25519.PublicKey)

	testCreated = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
)

func trusted() []ed25519.PublicKey { return []ed25519.PublicKey{testPub} }

// sampleFiles is a bundle with every kind of allowed content.
func sampleFiles(tag string) map[string]string {
	return map[string]string{
		"rules/core.yaml":         "rules: [] # " + tag + "\n",
		"rules/R01-bypass.yaml":   "id: R01\n",
		"catalog/overlay.yaml":    "products: []\n",
		"lists.yaml":              "lists: {}\n",
		"suppressions.yaml":       "suppressions: []\n",
		"rules/a.b_c-d.yaml":      "",
		"catalog/vendor.v2.yaml":  "version: 2\n",
		"rules/UPPER-and-9.yaml":  "x: 1\n",
		"catalog/0-leading.yaml":  "y: 2\n",
		"rules/zz-last-rule.yaml": "z: 3\n",
	}
}

// writeTree materialises files (slash paths) under a new temp directory.
func writeTree(t testing.TB, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// build makes a real bundle with Create's code path and signs it.
func build(t testing.TB, version uint64, files map[string]string) (tarball, sig []byte) {
	t.Helper()
	var buf bytes.Buffer
	if _, err := CreateWith(writeTree(t, files), CreateOptions{Version: version, Created: testCreated}, testPriv, &buf); err != nil {
		t.Fatalf("CreateWith: %v", err)
	}
	return buf.Bytes(), Sign(buf.Bytes(), testPriv)
}

// verified builds a bundle and returns it with its Verify result.
func verified(t testing.TB, version uint64, files map[string]string) ([]byte, *Manifest) {
	t.Helper()
	tarball, sig := build(t, version, files)
	m, err := Verify(tarball, sig, trusted())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	return tarball, m
}

// install builds, verifies and installs one version.
func install(t testing.TB, dest string, version uint64, files map[string]string) {
	t.Helper()
	tarball, m := verified(t, version, files)
	if err := Install(tarball, m, dest); err != nil {
		t.Fatalf("Install v%d: %v", version, err)
	}
}

// rawEntry is one hand-written tar member. Building headers by hand lets
// the tests produce archives archive/tar's Writer would refuse to write.
type rawEntry struct {
	name string
	body []byte
	typ  byte // zero means regular file
	link string
	gnu  bool // write the old GNU magic instead of POSIX ustar
}

func rawHeader(e rawEntry) []byte {
	var b [512]byte
	copy(b[0:100], e.name)
	copy(b[100:108], "0000644\x00")
	copy(b[108:116], "0000000\x00")
	copy(b[116:124], "0000000\x00")
	copy(b[124:136], fmt.Sprintf("%011o\x00", len(e.body)))
	copy(b[136:148], fmt.Sprintf("%011o\x00", testCreated.Unix()))
	typ := e.typ
	if typ == 0 {
		typ = tar.TypeReg
	}
	b[156] = typ
	copy(b[157:257], e.link)
	if e.gnu {
		copy(b[257:265], "ustar  \x00")
	} else {
		copy(b[257:263], "ustar\x00")
		copy(b[263:265], "00")
	}
	for i := 148; i < 156; i++ {
		b[i] = ' '
	}
	sum := 0
	for _, c := range b {
		sum += int(c)
	}
	copy(b[148:156], fmt.Sprintf("%06o\x00 ", sum))
	return b[:]
}

// rawTar concatenates members and the end-of-archive marker.
func rawTar(entries ...rawEntry) []byte {
	var out bytes.Buffer
	for _, e := range entries {
		out.Write(rawHeader(e))
		out.Write(e.body)
		if pad := (512 - len(e.body)%512) % 512; pad > 0 {
			out.Write(make([]byte, pad))
		}
	}
	out.Write(make([]byte, 1024))
	return out.Bytes()
}

func gz(t testing.TB, raw []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sumHex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// manifestJSON lists files with their true hashes.
func manifestJSON(t testing.TB, version uint64, files map[string][]byte) []byte {
	t.Helper()
	m := map[string]any{"version": version, "created": testCreated.Format(time.RFC3339), "files": map[string]string{}}
	for name, body := range files {
		m["files"].(map[string]string)[name] = sumHex(body)
	}
	b, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// forge packs an honest manifest for good, then appends extra members the
// manifest does not know about. It is the shape of most attacks: a valid
// looking bundle with one hostile entry.
func forge(t testing.TB, good map[string][]byte, extra ...rawEntry) []byte {
	t.Helper()
	entries := []rawEntry{{name: manifestName, body: manifestJSON(t, 7, good)}}
	names := make([]string, 0, len(good))
	for name := range good {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		entries = append(entries, rawEntry{name: name, body: good[name]})
	}
	return gz(t, rawTar(append(entries, extra...)...))
}

// forceVerified returns a manifest Install accepts for tarball without
// running Verify, so the tests can show that Install's own checks hold even
// if Verify were bypassed.
func forceVerified(tarball []byte) *Manifest {
	return &Manifest{Version: 7, Created: testCreated, Files: map[string]string{}, sum: sha256.Sum256(tarball), verified: true}
}

// listTree returns every path under dir, relative and slash-separated.
func listTree(t testing.TB, dir string) []string {
	t.Helper()
	var out []string
	err := filepath.Walk(dir, func(p string, _ os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if rel, _ := filepath.Rel(dir, p); rel != "." {
			out = append(out, filepath.ToSlash(rel))
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(out)
	return out
}
