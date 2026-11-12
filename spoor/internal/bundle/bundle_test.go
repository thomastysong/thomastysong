package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

func TestRoundTrip(t *testing.T) {
	files := sampleFiles("v1")
	src := writeTree(t, files)

	var buf bytes.Buffer
	if err := Create(src, 3, testPriv, &buf); err != nil {
		t.Fatalf("Create: %v", err)
	}
	tarball := buf.Bytes()
	sig := Sign(tarball, testPriv)
	if len(sig) != ed25519.SignatureSize {
		t.Fatalf("Sign returned %d bytes, want %d", len(sig), ed25519.SignatureSize)
	}

	m, err := Verify(tarball, sig, trusted())
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if m.Version != 3 {
		t.Errorf("Version = %d, want 3", m.Version)
	}
	if m.Created.IsZero() || m.Created.Nanosecond() != 0 || m.Created.Location().String() != "UTC" {
		t.Errorf("Created = %v, want a UTC time in whole seconds", m.Created)
	}
	if len(m.Files) != len(files) {
		t.Fatalf("manifest lists %d files, want %d", len(m.Files), len(files))
	}
	for name, body := range files {
		if got, want := m.Files[name], sumHex([]byte(body)); got != want {
			t.Errorf("hash of %s = %q, want %q", name, got, want)
		}
	}
	if !sort.StringsAreSorted(m.Paths()) || len(m.Paths()) != len(files) {
		t.Errorf("Paths() = %v", m.Paths())
	}

	dest := filepath.Join(t.TempDir(), "state", "bundle")
	if _, _, ok := Current(dest); ok {
		t.Fatal("Current reported a bundle before any install")
	}
	if _, err := Installed(dest); !errors.Is(err, ErrNotInstalled) {
		t.Fatalf("Installed before install = %v, want ErrNotInstalled", err)
	}
	if err := Install(tarball, m, dest); err != nil {
		t.Fatalf("Install: %v", err)
	}

	dir, cm, ok := Current(dest)
	if !ok {
		t.Fatal("Current: not ok after install")
	}
	if want := filepath.Join(dest, "v3"); dir != want {
		t.Errorf("Current dir = %q, want %q", dir, want)
	}
	if !cm.Equal(m) {
		t.Errorf("Current manifest differs from the verified one:\n got %+v\nwant %+v", cm, m)
	}
	if cm.Digest() != m.Digest() || len(cm.Digest()) != 64 {
		t.Errorf("Digest mismatch: %q vs %q", cm.Digest(), m.Digest())
	}
	for name, body := range files {
		got, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(name)))
		if err != nil || string(got) != body {
			t.Errorf("installed %s = %q, %v; want %q", name, got, err, body)
		}
		viaAPI, err := ReadFile(dir, cm, name)
		if err != nil || string(viaAPI) != body {
			t.Errorf("ReadFile(%s) = %q, %v; want %q", name, viaAPI, err, body)
		}
	}
	if _, err := ReadFile(dir, cm, "rules/absent.yaml"); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("ReadFile of an unlisted file = %v, want fs.ErrNotExist", err)
	}
	if _, err := Audit(dest); err != nil {
		t.Errorf("Audit: %v", err)
	}

	// The installed tree is exactly the archive: nothing staged is left.
	want := []string{".lock", "current", "v3", "v3/catalog", "v3/manifest.json", "v3/rules", "v3/lists.yaml", "v3/suppressions.yaml"}
	for name := range files {
		want = append(want, "v3/"+name)
	}
	sort.Strings(want)
	if got := listTree(t, dest); !reflect.DeepEqual(got, uniq(want)) {
		t.Errorf("destination tree:\n got %v\nwant %v", got, uniq(want))
	}

	var pt pointer
	raw, err := os.ReadFile(filepath.Join(dest, "current"))
	if err != nil || json.Unmarshal(raw, &pt) != nil {
		t.Fatalf("pointer unreadable: %q, %v", raw, err)
	}
	if pt.Version != 3 || pt.Dir != "v3" || pt.Installed.IsZero() {
		t.Errorf("pointer = %+v", pt)
	}

	if runtime.GOOS != "windows" {
		// Hook processes run as the monitored user and must be able to
		// read the content whatever umask the installer had.
		for p, wantMode := range map[string]os.FileMode{
			dest: 0o755, dir: 0o755, filepath.Join(dir, "rules"): 0o755,
			filepath.Join(dir, "manifest.json"): 0o644, filepath.Join(dir, "rules", "core.yaml"): 0o644,
			filepath.Join(dest, "current"): 0o644, filepath.Join(dest, ".lock"): 0o600,
		} {
			fi, err := os.Stat(p)
			if err != nil {
				t.Errorf("stat %s: %v", p, err)
				continue
			}
			if got := fi.Mode().Perm(); got != wantMode {
				t.Errorf("mode of %s = %04o, want %04o", p, got, wantMode)
			}
		}
	}
}

func uniq(s []string) []string {
	sort.Strings(s)
	out := s[:0]
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

func TestCreateIsDeterministicAndPlain(t *testing.T) {
	files := sampleFiles("det")
	a, _ := build(t, 9, files)
	b, _ := build(t, 9, files)
	if !bytes.Equal(a, b) {
		t.Fatal("two builds of the same input and creation time differ")
	}

	zr, err := gzip.NewReader(bytes.NewReader(a))
	if err != nil {
		t.Fatal(err)
	}
	if zr.Name != "" || !zr.ModTime.IsZero() || zr.Comment != "" {
		t.Errorf("gzip header carries metadata: name=%q mtime=%v comment=%q", zr.Name, zr.ModTime, zr.Comment)
	}
	tr := tar.NewReader(zr)
	var names []string
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, hdr.Name)
		if hdr.Typeflag != tar.TypeReg || hdr.Uid != 0 || hdr.Gid != 0 || hdr.Uname != "" || hdr.Gname != "" ||
			hdr.Mode != 0o644 || !hdr.ModTime.Equal(testCreated) || len(hdr.PAXRecords) != 0 {
			t.Errorf("header of %s is not plain: %+v", hdr.Name, hdr)
		}
	}
	if names[0] != "manifest.json" || !sort.StringsAreSorted(names[1:]) || len(names) != len(files)+1 {
		t.Errorf("entry order = %v", names)
	}
}

func TestCreateWithNoteAndManifest(t *testing.T) {
	var buf bytes.Buffer
	m, err := CreateWith(writeTree(t, sampleFiles("n")), CreateOptions{Version: 4, Note: "weekly pack\nsecond line"}, testPriv, &buf)
	if err != nil {
		t.Fatal(err)
	}
	if m.Version != 4 || m.Note != "weekly pack\nsecond line" || m.Created.IsZero() {
		t.Errorf("returned manifest = %+v", m)
	}
	vm, err := Verify(buf.Bytes(), Sign(buf.Bytes(), testPriv), trusted())
	if err != nil || !vm.Equal(m) {
		t.Fatalf("Verify = %+v, %v", vm, err)
	}
	// The manifest handed back by CreateWith is informational: it must not
	// unlock Install.
	if err := Install(buf.Bytes(), m, t.TempDir()); !errors.Is(err, ErrNotVerified) {
		t.Errorf("Install with CreateWith's manifest = %v, want ErrNotVerified", err)
	}
}

func TestCreateIgnoresEverythingElse(t *testing.T) {
	files := map[string]string{
		"rules/core.yaml":            "a: 1\n",
		"rules/README.md":            "docs",
		"rules/.gitkeep":             "",
		"rules/testdata/case.yaml":   "fixture: true\n",
		"rules/.cache/tmp.yaml":      "junk: true\n",
		"catalog/agents.yaml":        "b: 2\n",
		"go.mod":                     "module x\n",
		"internal/pkg/config.yaml":   "not: content\n",
		"deploy/fleet/policies.yaml": "not: content\n",
		"manifest.json":              `{"version": 999}`,
		"README.md":                  "hello",
	}
	tarball, m := verified(t, 2, files)
	if got, want := m.Paths(), []string{"catalog/agents.yaml", "rules/core.yaml"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("packed %v, want %v", got, want)
	}
	if m.Version != 2 {
		t.Errorf("a manifest.json in the source tree leaked into the bundle: version %d", m.Version)
	}
	if bytes.Contains(tarball, []byte("fixture")) {
		t.Error("testdata content was packed")
	}
}

func TestCreateRefuses(t *testing.T) {
	big := strings.Repeat("x", 1<<20)
	tests := []struct {
		name    string
		files   map[string]string
		prepare func(t *testing.T, dir string)
		version uint64
		priv    ed25519.PrivateKey
		want    error
	}{
		{name: "no content", files: map[string]string{"README.md": "x"}, want: ErrManifest},
		{name: "yml extension", files: map[string]string{"rules/a.yaml": "", "rules/b.yml": ""}, want: ErrNotAllowed},
		{name: "upper-case extension", files: map[string]string{"rules/a.YAML": ""}, want: ErrNotAllowed},
		{name: "lists.yml typo", files: map[string]string{"rules/a.yaml": "", "lists.yml": ""}, want: ErrNotAllowed},
		{name: "nested rule", files: map[string]string{"rules/linux/a.yaml": ""}, want: ErrNotAllowed},
		{name: "space in name", files: map[string]string{"rules/my rule.yaml": ""}, want: ErrNotAllowed},
		{name: "hidden yaml", files: map[string]string{"rules/.hidden.yaml": ""}, want: ErrNotAllowed},
		{name: "windows device name", files: map[string]string{"rules/aux.yaml": ""}, want: ErrUnsafePath},
		{name: "version zero", files: map[string]string{"rules/a.yaml": ""}, version: 0, want: ErrManifest},
		{name: "short private key", files: map[string]string{"rules/a.yaml": ""}, priv: testPriv[:10], want: ErrKey},
		{name: "nil private key", files: map[string]string{"rules/a.yaml": ""}, priv: ed25519.PrivateKey{}, want: ErrKey},
		{
			name: "symlinked rule", files: map[string]string{"rules/a.yaml": ""}, want: ErrNotRegular,
			prepare: func(t *testing.T, dir string) {
				secret := filepath.Join(t.TempDir(), "id_ed25519")
				if err := os.WriteFile(secret, []byte("PRIVATE-KEY-CANARY"), 0o600); err != nil {
					t.Fatal(err)
				}
				symlink(t, secret, filepath.Join(dir, "rules", "leak.yaml"))
			},
		},
		{
			name: "symlinked lists.yaml", files: map[string]string{"rules/a.yaml": ""}, want: ErrNotRegular,
			prepare: func(t *testing.T, dir string) {
				symlink(t, filepath.Join(dir, "rules", "a.yaml"), filepath.Join(dir, "lists.yaml"))
			},
		},
		{
			name: "symlinked rules directory", files: map[string]string{"elsewhere/a.yaml": ""}, want: ErrNotRegular,
			prepare: func(t *testing.T, dir string) {
				symlink(t, filepath.Join(dir, "elsewhere"), filepath.Join(dir, "rules"))
			},
		},
		{
			name: "too many files", want: ErrTooLarge,
			files: func() map[string]string {
				m := map[string]string{}
				for i := 0; i < MaxFiles; i++ { // plus manifest.json = MaxFiles+1
					m["rules/r"+strings.Repeat("0", 3-len(itoa(i)))+itoa(i)+".yaml"] = ""
				}
				return m
			}(),
		},
		{
			name: "content over the byte limit", want: ErrTooLarge,
			files: func() map[string]string {
				m := map[string]string{}
				for i := 0; i < 33; i++ {
					m["rules/big"+itoa(i)+".yaml"] = big
				}
				return m
			}(),
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeTree(t, tc.files)
			if tc.prepare != nil {
				tc.prepare(t, dir)
			}
			version, priv := tc.version, tc.priv
			if tc.name != "version zero" && version == 0 {
				version = 1
			}
			if priv == nil {
				priv = testPriv
			}
			var buf bytes.Buffer
			err := Create(dir, version, priv, &buf)
			if !errors.Is(err, tc.want) {
				t.Fatalf("Create = %v, want %v", err, tc.want)
			}
			if buf.Len() != 0 {
				t.Errorf("Create wrote %d bytes before failing", buf.Len())
			}
			if bytes.Contains(buf.Bytes(), []byte("CANARY")) {
				t.Error("content behind a symlink reached the archive")
			}
		})
	}
}

func TestCreateAtTheFileLimit(t *testing.T) {
	files := map[string]string{}
	for i := 0; i < MaxFiles-1; i++ {
		files["rules/r"+itoa(i)+".yaml"] = "n: " + itoa(i) + "\n"
	}
	tarball, m := verified(t, 1, files)
	if len(m.Files) != MaxFiles-1 {
		t.Fatalf("packed %d files", len(m.Files))
	}
	dest := t.TempDir()
	if err := Install(tarball, m, dest); err != nil {
		t.Fatalf("Install of a bundle at the file limit: %v", err)
	}
	if _, err := Audit(dest); err != nil {
		t.Fatal(err)
	}
}

func TestCreateMissingSource(t *testing.T) {
	err := Create(filepath.Join(t.TempDir(), "nope"), 1, testPriv, io.Discard)
	if err == nil || !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Create on a missing directory = %v", err)
	}
	if _, err := CreateWith(writeTree(t, sampleFiles("x")), CreateOptions{Version: 1}, testPriv, nil); err == nil {
		t.Fatal("CreateWith accepted a nil writer")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for ; i > 0; i /= 10 {
		b = append([]byte{byte('0' + i%10)}, b...)
	}
	return string(b)
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
}

func TestSignAndVerify(t *testing.T) {
	tarball, sig := build(t, 5, sampleFiles("sv"))
	otherTarball, otherSig := build(t, 6, sampleFiles("other"))

	flipped := append([]byte(nil), tarball...)
	flipped[len(flipped)/2] ^= 0x01
	appended := append(append([]byte(nil), tarball...), 0)
	badSig := append([]byte(nil), sig...)
	badSig[0] ^= 0x80

	tests := []struct {
		name    string
		tarball []byte
		sig     []byte
		pubs    []ed25519.PublicKey
		want    error // nil means success
	}{
		{"valid", tarball, sig, trusted(), nil},
		{"valid, second of two keys", tarball, sig, []ed25519.PublicKey{otherPub, testPub}, nil},
		{"valid, malformed keys skipped", tarball, sig, []ed25519.PublicKey{nil, testPub[:5], make(ed25519.PublicKey, 32), testPub}, nil},
		{"hex signature", tarball, []byte(hex.EncodeToString(sig) + "\n"), trusted(), nil},
		{"base64 signature", tarball, []byte(base64.StdEncoding.EncodeToString(sig)), trusted(), nil},
		{"raw url base64 signature with spaces", tarball, []byte("  " + base64.RawURLEncoding.EncodeToString(sig) + "\r\n"), trusted(), nil},
		{"one bit flipped in the tarball", flipped, sig, trusted(), ErrSignature},
		{"byte appended to the tarball", appended, sig, trusted(), ErrSignature},
		{"one bit flipped in the signature", tarball, badSig, trusted(), ErrSignature},
		{"signature of another bundle", tarball, otherSig, trusted(), ErrSignature},
		{"tarball of another bundle", otherTarball, sig, trusted(), ErrSignature},
		{"signed by an untrusted key", tarball, Sign(tarball, otherPriv), trusted(), ErrSignature},
		{"wrong key configured", tarball, sig, []ed25519.PublicKey{otherPub}, ErrSignature},
		{"empty signature", tarball, nil, trusted(), ErrSignature},
		{"truncated signature", tarball, sig[:63], trusted(), ErrSignature},
		{"oversized signature", tarball, bytes.Repeat([]byte("A"), 4096), trusted(), ErrSignature},
		{"signature is text garbage", tarball, []byte("not a signature"), trusted(), ErrSignature},
		{"no keys", tarball, sig, nil, ErrNoKeys},
		{"only malformed keys", tarball, sig, []ed25519.PublicKey{nil, testPub[:31], make(ed25519.PublicKey, 32)}, ErrNoKeys},
		{"empty tarball", nil, Sign(nil, testPriv), trusted(), ErrFormat},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := Verify(tc.tarball, tc.sig, tc.pubs)
			if tc.want == nil {
				if err != nil || m == nil {
					t.Fatalf("Verify = %v, %v; want success", m, err)
				}
				return
			}
			if !errors.Is(err, tc.want) || m != nil {
				t.Fatalf("Verify = %v, %v; want %v and no manifest", m, err, tc.want)
			}
		})
	}
}

// The signature is checked on the raw bytes before anything is decompressed
// or parsed: an unsigned blob must never reach the gzip and tar readers.
func TestVerifyChecksSignatureFirst(t *testing.T) {
	garbage := []byte("this is not a gzip stream at all")
	if _, err := Verify(garbage, bytes.Repeat([]byte{1}, 64), trusted()); !errors.Is(err, ErrSignature) {
		t.Errorf("unsigned garbage: %v, want ErrSignature", err)
	}
	if _, err := Verify(garbage, Sign(garbage, testPriv), trusted()); !errors.Is(err, ErrFormat) {
		t.Errorf("signed garbage: %v, want ErrFormat", err)
	}
	// A hostile archive without a valid signature is reported as a
	// signature failure, not by whatever its content would trip.
	hostile := forge(t, nil, rawEntry{name: "../../etc/cron.d/x.yaml", body: []byte("x")})
	if _, err := Verify(hostile, Sign(hostile, otherPriv), trusted()); !errors.Is(err, ErrSignature) {
		t.Errorf("hostile archive signed by a stranger: %v, want ErrSignature", err)
	}
}

func TestSignWithBadKeyDoesNotPanic(t *testing.T) {
	for _, priv := range []ed25519.PrivateKey{nil, {}, testPriv[:63], append(append(ed25519.PrivateKey{}, testPriv...), 0)} {
		if sig := Sign([]byte("x"), priv); sig != nil {
			t.Errorf("Sign with a %d-byte key returned %d bytes", len(priv), len(sig))
		}
	}
}

func TestManifestEqualAndDigest(t *testing.T) {
	_, a := verified(t, 1, sampleFiles("a"))
	_, a2 := verified(t, 1, sampleFiles("a"))
	_, b := verified(t, 1, sampleFiles("b"))
	_, c := verified(t, 2, sampleFiles("a"))
	if !a.Equal(a2) || a.Digest() != a2.Digest() {
		t.Error("identical bundles are not Equal")
	}
	if a.Equal(b) || a.Digest() == b.Digest() {
		t.Error("different content compares Equal")
	}
	if a.Equal(c) || a.Digest() == c.Digest() {
		t.Error("different versions compare Equal")
	}
	var nilM *Manifest
	if !nilM.Equal(nil) || nilM.Equal(a) || a.Equal(nil) || nilM.Digest() != "" || nilM.Paths() != nil {
		t.Error("nil manifests are not handled")
	}
}

func TestReasonAndVersionError(t *testing.T) {
	tests := []struct {
		err  error
		want string
	}{
		{nil, ""},
		{ErrSignature, "signature"},
		{ErrNoKeys, "no_keys"},
		{&VersionError{Installed: 5, Offered: 4}, "downgrade"},
		{&VersionError{Installed: 5, Offered: 5}, "downgrade"},
		{&VersionError{Installed: 5, Offered: 5, Identical: true}, "already_installed"},
		{ErrNotVerified, "not_verified"},
		{ErrTooLarge, "too_large"},
		{ErrUnsafePath, "unsafe_path"},
		{ErrNotRegular, "not_regular"},
		{ErrNotAllowed, "not_allowed"},
		{ErrManifest, "manifest"},
		{ErrMismatch, "mismatch"},
		{ErrFormat, "format"},
		{ErrInsecure, "insecure_permissions"},
		{ErrBusy, "busy"},
		{ErrCorrupt, "corrupt"},
		{ErrNotInstalled, "not_installed"},
		{ErrURL, "url"},
		{ErrFetch, "fetch"},
		{ErrRejected, "rejected"},
		{ErrKey, "key"},
		{errors.New("something else"), "error"},
	}
	for _, tc := range tests {
		if got := Reason(tc.err); got != tc.want {
			t.Errorf("Reason(%v) = %q, want %q", tc.err, got, tc.want)
		}
	}
	down := error(&VersionError{Installed: 5, Offered: 4})
	same := error(&VersionError{Installed: 5, Offered: 5, Identical: true})
	if !errors.Is(down, ErrDowngrade) || errors.Is(down, ErrAlreadyInstalled) {
		t.Error("a lower version must match ErrDowngrade only")
	}
	if !errors.Is(same, ErrAlreadyInstalled) || errors.Is(same, ErrDowngrade) {
		t.Error("the identical bundle must match ErrAlreadyInstalled only")
	}
	for _, e := range []error{down, same, &VersionError{Installed: 5, Offered: 5}} {
		if e.Error() == "" || !strings.HasPrefix(e.Error(), "bundle: ") {
			t.Errorf("unhelpful message %q", e.Error())
		}
	}
}
