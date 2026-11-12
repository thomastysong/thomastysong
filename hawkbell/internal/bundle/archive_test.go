package bundle

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var goodFiles = map[string][]byte{
	"rules/core.yaml": []byte("rules: []\n"),
	"lists.yaml":      []byte("lists: {}\n"),
}

// hostile is one malicious or malformed archive and the error it must
// produce. Every case is exercised three ways: through Verify with a valid
// signature from a trusted key (the stolen-key scenario), through the
// archive checker directly, and through Install with a manifest that claims
// to be verified (so Install's own defences are shown to hold).
type hostile struct {
	name    string
	tarball func(t *testing.T) []byte
	want    error
}

func withExtra(extra ...rawEntry) func(t *testing.T) []byte {
	return func(t *testing.T) []byte { return forge(t, goodFiles, extra...) }
}

func withManifest(manifest string, files ...rawEntry) func(t *testing.T) []byte {
	return func(t *testing.T) []byte {
		return gz(t, rawTar(append([]rawEntry{{name: manifestName, body: []byte(manifest)}}, files...)...))
	}
}

func viaTarWriter(write func(tw *tar.Writer) error) func(t *testing.T) []byte {
	return func(t *testing.T) []byte {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		tw := tar.NewWriter(zw)
		body := manifestJSON(t, 7, nil)
		if err := tw.WriteHeader(&tar.Header{Name: manifestName, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		tw.Write(body)
		if err := write(tw); err != nil {
			t.Fatal(err)
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		zw.Close()
		return buf.Bytes()
	}
}

func hostileArchives() []hostile {
	const created = `"created":"2026-11-11T12:00:00Z"`
	zeros := func(n int) []byte { return make([]byte, n) }
	return []hostile{
		// Path traversal and absolute paths.
		{"parent traversal", withExtra(rawEntry{name: "../evil.yaml", body: []byte("x")}), ErrUnsafePath},
		{"deep traversal", withExtra(rawEntry{name: "../../../../etc/cron.d/evil.yaml", body: []byte("x")}), ErrUnsafePath},
		{"traversal through an allowed directory", withExtra(rawEntry{name: "rules/../../evil.yaml", body: []byte("x")}), ErrUnsafePath},
		{"traversal that stays inside", withExtra(rawEntry{name: "rules/../rules/x.yaml", body: []byte("x")}), ErrUnsafePath},
		{"absolute path", withExtra(rawEntry{name: "/etc/cron.d/evil.yaml", body: []byte("x")}), ErrUnsafePath},
		{"absolute allowed-looking path", withExtra(rawEntry{name: "/rules/x.yaml", body: []byte("x")}), ErrUnsafePath},
		{"windows traversal", withExtra(rawEntry{name: `..\..\evil.yaml`, body: []byte("x")}), ErrUnsafePath},
		{"windows separator", withExtra(rawEntry{name: `rules\x.yaml`, body: []byte("x")}), ErrUnsafePath},
		{"windows drive", withExtra(rawEntry{name: "C:/Windows/x.yaml", body: []byte("x")}), ErrUnsafePath},
		{"alternate data stream", withExtra(rawEntry{name: "rules/x.yaml:evil", body: []byte("x")}), ErrUnsafePath},
		{"dot segment", withExtra(rawEntry{name: "./rules/x.yaml", body: []byte("x")}), ErrUnsafePath},
		{"empty segment", withExtra(rawEntry{name: "rules//x.yaml", body: []byte("x")}), ErrUnsafePath},
		{"empty name", withExtra(rawEntry{name: "", body: []byte("x")}), ErrUnsafePath},
		{"invalid UTF-8 name", withExtra(rawEntry{name: "rules/\xff\xfe.yaml", body: []byte("x")}), ErrUnsafePath},
		{"windows device name", withExtra(rawEntry{name: "rules/NUL.yaml", body: []byte("x")}), ErrUnsafePath},
		{"windows device name with suffix", withExtra(rawEntry{name: "catalog/com1.overlay.yaml", body: []byte("x")}), ErrUnsafePath},

		// Entries that are not regular files.
		{"symlink entry", withExtra(rawEntry{name: "rules/x.yaml", typ: tar.TypeSymlink, link: "/etc/passwd"}), ErrNotRegular},
		{"symlink then write through it", withExtra(
			rawEntry{name: "rules", typ: tar.TypeSymlink, link: "/tmp"},
			rawEntry{name: "rules/x.yaml", body: []byte("x")}), ErrNotRegular},
		{"relative symlink out of the tree", withExtra(rawEntry{name: "catalog/x.yaml", typ: tar.TypeSymlink, link: "../../../etc/shadow"}), ErrNotRegular},
		{"hard link entry", withExtra(rawEntry{name: "rules/x.yaml", typ: tar.TypeLink, link: "/etc/passwd"}), ErrNotRegular},
		{"directory entry", withExtra(rawEntry{name: "rules/", typ: tar.TypeDir}), ErrNotRegular},
		{"character device", withExtra(rawEntry{name: "rules/x.yaml", typ: tar.TypeChar}), ErrNotRegular},
		{"block device", withExtra(rawEntry{name: "rules/x.yaml", typ: tar.TypeBlock}), ErrNotRegular},
		{"fifo", withExtra(rawEntry{name: "rules/x.yaml", typ: tar.TypeFifo}), ErrNotRegular},
		{"GNU sparse file", withExtra(rawEntry{name: "rules/x.yaml", typ: tar.TypeGNUSparse, gnu: true}), ErrNotRegular},
		{"sparse flag in a POSIX header", withExtra(rawEntry{name: "rules/x.yaml", typ: tar.TypeGNUSparse}), ErrFormat},
		{"unknown type flag", withExtra(rawEntry{name: "rules/x.yaml", typ: 'Z'}), ErrNotRegular},

		// Well-formed names that are not bundle content.
		{"shell script", withExtra(rawEntry{name: "rules/x.sh", body: []byte("#!/bin/sh\n")}), ErrNotAllowed},
		{"binary", withExtra(rawEntry{name: "bin/hawkbell", body: []byte("ELF")}), ErrNotAllowed},
		{"config file", withExtra(rawEntry{name: "config.yaml", body: []byte("x")}), ErrNotAllowed},
		{"nested rule", withExtra(rawEntry{name: "rules/sub/x.yaml", body: []byte("x")}), ErrNotAllowed},
		{"other directory", withExtra(rawEntry{name: "hooks/x.yaml", body: []byte("x")}), ErrNotAllowed},
		{"yml extension", withExtra(rawEntry{name: "rules/x.yml", body: []byte("x")}), ErrNotAllowed},
		{"hidden file", withExtra(rawEntry{name: "rules/.x.yaml", body: []byte("x")}), ErrNotAllowed},
		{"bare extension", withExtra(rawEntry{name: "rules/.yaml", body: []byte("x")}), ErrNotAllowed},
		{"space in name", withExtra(rawEntry{name: "rules/a b.yaml", body: []byte("x")}), ErrNotAllowed},
		{"non-ASCII name", withExtra(rawEntry{name: "rules/règle.yaml", body: []byte("x")}), ErrNotAllowed},
		{"pointer file", withExtra(rawEntry{name: "current", body: []byte("x")}), ErrNotAllowed},
		{"file named like a directory", withExtra(rawEntry{name: "rules", body: []byte("x")}), ErrNotAllowed},
		{"long name through a PAX header", viaTarWriter(func(tw *tar.Writer) error {
			name := "rules/" + strings.Repeat("a", 300) + ".yaml"
			if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: 1}); err != nil {
				return err
			}
			_, err := tw.Write([]byte("x"))
			return err
		}), ErrNotAllowed},

		// Structural tricks.
		{"extended attributes", viaTarWriter(func(tw *tar.Writer) error {
			hdr := &tar.Header{Name: "rules/x.yaml", Typeflag: tar.TypeReg, Mode: 0o644, Size: 1, Format: tar.FormatPAX,
				PAXRecords: map[string]string{"SCHILY.xattr.security.capability": "x"}}
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			_, err := tw.Write([]byte("x"))
			return err
		}), ErrFormat},
		{"global extended header", viaTarWriter(func(tw *tar.Writer) error {
			return tw.WriteHeader(&tar.Header{Typeflag: tar.TypeXGlobalHeader, Name: "pax_global_header", PAXRecords: map[string]string{"comment": "x"}})
		}), ErrNotRegular},
		{"duplicate entry", withExtra(rawEntry{name: "rules/core.yaml", body: []byte("rules: [evil]\n")}), ErrFormat},
		{"duplicate that differs only in case", withExtra(rawEntry{name: "rules/CORE.yaml", body: []byte("x")}), ErrFormat},
		{"second manifest", withExtra(rawEntry{name: manifestName, body: []byte(`{"version":99}`)}), ErrFormat},
		{"data after the end-of-archive marker", func(t *testing.T) []byte {
			raw := rawTar(rawEntry{name: manifestName, body: manifestJSON(t, 7, nil)})
			return gz(t, append(raw, rawTar(rawEntry{name: "rules/hidden.yaml", body: []byte("x")})...))
		}, ErrFormat},
		{"second gzip member", func(t *testing.T) []byte {
			return append(forge(t, goodFiles), gz(t, rawTar(rawEntry{name: "rules/second.yaml", body: []byte("x")}))...)
		}, ErrFormat},
		{"bytes after the gzip stream", func(t *testing.T) []byte { return append(forge(t, goodFiles), "trailing"...) }, ErrFormat},
		{"truncated gzip stream", func(t *testing.T) []byte { b := forge(t, goodFiles); return b[:len(b)-12] }, ErrFormat},
		{"corrupt gzip checksum", func(t *testing.T) []byte { b := forge(t, goodFiles); b[len(b)-6] ^= 0xff; return b }, ErrFormat},
		{"truncated tar stream", func(t *testing.T) []byte {
			raw := rawTar(rawEntry{name: manifestName, body: manifestJSON(t, 7, nil)}, rawEntry{name: "rules/x.yaml", body: zeros(4096)})
			return gz(t, raw[:len(raw)-3000])
		}, ErrFormat},
		{"bad header checksum", func(t *testing.T) []byte {
			raw := rawTar(rawEntry{name: manifestName, body: manifestJSON(t, 7, nil)})
			raw[150] ^= 0x01
			return gz(t, raw)
		}, ErrFormat},
		{"plain tar, not gzip", func(t *testing.T) []byte { return rawTar(rawEntry{name: manifestName, body: manifestJSON(t, 7, nil)}) }, ErrFormat},
		{"zip file", func(t *testing.T) []byte { return []byte("PK\x03\x04 not what we accept") }, ErrFormat},
		{"empty input", func(t *testing.T) []byte { return nil }, ErrFormat},

		// Manifest problems.
		{"no manifest", func(t *testing.T) []byte { return gz(t, rawTar(rawEntry{name: "rules/x.yaml", body: []byte("x")})) }, ErrManifest},
		{"empty archive", func(t *testing.T) []byte { return gz(t, rawTar()) }, ErrManifest},
		{"manifest is not JSON", withManifest("version: 7"), ErrManifest},
		{"manifest is a JSON array", withManifest(`[1,2,3]`), ErrManifest},
		{"manifest with trailing data", withManifest(`{"version":7,` + created + `,"files":{}} {"version":8}`), ErrManifest},
		{"manifest is invalid UTF-8", withManifest("{\"version\":7,\"note\":\"\xff\"}"), ErrManifest},
		{"version zero", withManifest(`{"version":0,` + created + `,"files":{}}`), ErrManifest},
		{"version missing", withManifest(`{` + created + `,"files":{}}`), ErrManifest},
		{"negative version", withManifest(`{"version":-1,` + created + `,"files":{}}`), ErrManifest},
		{"fractional version", withManifest(`{"version":7.5,` + created + `,"files":{}}`), ErrManifest},
		{"version overflow", withManifest(`{"version":18446744073709551616,` + created + `,"files":{}}`), ErrManifest},
		{"created missing", withManifest(`{"version":7,"files":{}}`), ErrManifest},
		{"created malformed", withManifest(`{"version":7,"created":"yesterday","files":{}}`), ErrManifest},
		{"created before 1970", withManifest(`{"version":7,"created":"1969-12-31T23:59:59Z","files":{}}`), ErrManifest},
		{"note with terminal escape", withManifest(`{"version":7,` + created + `,"files":{},"note":"\u001b[2J"}`), ErrManifest},
		{"note too long", withManifest(`{"version":7,` + created + `,"files":{},"note":"` + strings.Repeat("n", 2000) + `"}`), ErrManifest},
		{"hash of the wrong shape", withManifest(`{"version":7,`+created+`,"files":{"rules/x.yaml":"abc"}}`, rawEntry{name: "rules/x.yaml", body: []byte("x")}), ErrManifest},
		{"upper-case hash", withManifest(`{"version":7,`+created+`,"files":{"rules/x.yaml":"`+strings.ToUpper(sumHex([]byte("x")))+`"}}`, rawEntry{name: "rules/x.yaml", body: []byte("x")}), ErrManifest},
		{"manifest lists a traversal path", withManifest(`{"version":7,` + created + `,"files":{"../x.yaml":"` + sumHex(nil) + `"}}`), ErrUnsafePath},
		{"manifest lists a foreign path", withManifest(`{"version":7,` + created + `,"files":{"bin/sh":"` + sumHex(nil) + `"}}`), ErrNotAllowed},
		{"manifest lists itself", withManifest(`{"version":7,` + created + `,"files":{"manifest.json":"` + sumHex(nil) + `"}}`), ErrNotAllowed},
		{"manifest names collide by case", withManifest(`{"version":7,` + created + `,"files":{"rules/a.yaml":"` + sumHex(nil) + `","rules/A.yaml":"` + sumHex(nil) + `"}}`), ErrManifest},
		{"manifest deeply nested", withManifest(`{"version":7,"files":` + strings.Repeat("[", 200000) + strings.Repeat("]", 200000) + `}`), ErrManifest},
		{"manifest over one megabyte", withManifest(`{"version":7,` + created + `,"files":{},"x":"` + strings.Repeat("a", 1<<20) + `"}`), ErrManifest},
		{"manifest lists too many files", func(t *testing.T) []byte {
			files := map[string]string{}
			for i := 0; i < MaxFiles; i++ {
				files["rules/r"+itoa(i)+".yaml"] = sumHex(nil)
			}
			b, _ := json.Marshal(map[string]any{"version": 7, "created": testCreated, "files": files})
			return gz(t, rawTar(rawEntry{name: manifestName, body: b}))
		}, ErrTooLarge},

		// Content that disagrees with the manifest.
		{"file not listed", withExtra(rawEntry{name: "rules/extra.yaml", body: []byte("x")}), ErrMismatch},
		{"listed file missing", withManifest(`{"version":7,` + created + `,"files":{"rules/x.yaml":"` + sumHex([]byte("x")) + `"}}`), ErrMismatch},
		{"content changed after hashing", withManifest(`{"version":7,`+created+`,"files":{"rules/x.yaml":"`+sumHex([]byte("x"))+`"}}`, rawEntry{name: "rules/x.yaml", body: []byte("y")}), ErrMismatch},

		// Resource exhaustion.
		{"more entries than allowed", func(t *testing.T) []byte {
			entries := []rawEntry{{name: manifestName, body: manifestJSON(t, 7, nil)}}
			for i := 0; i < MaxFiles; i++ {
				entries = append(entries, rawEntry{name: "rules/r" + itoa(i) + ".yaml"})
			}
			return gz(t, rawTar(entries...))
		}, ErrTooLarge},
		{"one file over the byte limit", withExtra(rawEntry{name: "rules/bomb.yaml", body: zeros(MaxBytes + 1)}), ErrTooLarge},
		{"files adding up over the byte limit", withExtra(
			rawEntry{name: "rules/a.yaml", body: zeros(12 << 20)},
			rawEntry{name: "rules/b.yaml", body: zeros(12 << 20)},
			rawEntry{name: "rules/c.yaml", body: zeros(12 << 20)}), ErrTooLarge},
		{"padding bomb", func(t *testing.T) []byte {
			raw := rawTar(rawEntry{name: manifestName, body: manifestJSON(t, 7, nil)})
			return gz(t, append(raw, zeros(maxStreamBytes)...))
		}, ErrTooLarge},
		{"compressed archive over the byte limit", func(t *testing.T) []byte {
			b := make([]byte, MaxBytes+1)
			rand.Read(b)
			copy(b, []byte{0x1f, 0x8b, 8})
			return b
		}, ErrTooLarge},
	}
}

func TestHostileArchives(t *testing.T) {
	for _, tc := range hostileArchives() {
		t.Run(tc.name, func(t *testing.T) {
			tarball := tc.tarball(t)

			if m, err := Verify(tarball, Sign(tarball, testPriv), trusted()); !errors.Is(err, tc.want) || m != nil {
				t.Errorf("Verify = %v, %v; want %v and no manifest", m, err, tc.want)
			}
			if m, err := checkArchive(tarball); !errors.Is(err, tc.want) || m != nil {
				t.Errorf("checkArchive = %v, %v; want %v", m, err, tc.want)
			}

			// Even with a manifest that claims to be verified, Install
			// must refuse, write nothing outside the destination and
			// leave nothing behind inside it.
			outer := t.TempDir()
			dest := filepath.Join(outer, "bundle")
			if err := Install(tarball, forceVerified(tarball), dest); !errors.Is(err, tc.want) {
				t.Errorf("Install = %v, want %v", err, tc.want)
			}
			if _, _, ok := Current(dest); ok {
				t.Error("a hostile archive became current")
			}
			if got := listTree(t, outer); len(got) != 0 {
				for _, p := range got {
					if p != "bundle" && p != "bundle/.lock" {
						t.Errorf("Install left %q behind", p)
					}
				}
			}
		})
	}
}

// A hostile archive must not disturb a bundle that is already installed.
func TestHostileArchiveKeepsCurrentBundle(t *testing.T) {
	dest := t.TempDir()
	install(t, dest, 3, sampleFiles("good"))
	before := listTree(t, dest)
	for _, tc := range hostileArchives() {
		tarball := tc.tarball(t)
		if err := Install(tarball, forceVerified(tarball), dest); err == nil {
			t.Fatalf("%s: Install succeeded", tc.name)
		}
	}
	if after := listTree(t, dest); strings.Join(after, "\n") != strings.Join(before, "\n") {
		t.Errorf("destination changed:\nbefore %v\nafter  %v", before, after)
	}
	if info, err := Audit(dest); err != nil || info.Manifest.Version != 3 {
		t.Errorf("Audit after hostile installs = %+v, %v", info, err)
	}
}

// Archives written by ordinary tools, with their usual padding, are fine as
// long as they follow the layout.
func TestAcceptsForeignButWellFormedArchives(t *testing.T) {
	files := map[string][]byte{"rules/x.yaml": []byte("a: 1\n"), "catalog/y.yaml": []byte("b: 2\n")}
	tests := map[string][]byte{
		"manifest last": gz(t, rawTar(
			rawEntry{name: "rules/x.yaml", body: files["rules/x.yaml"]},
			rawEntry{name: "catalog/y.yaml", body: files["catalog/y.yaml"]},
			rawEntry{name: manifestName, body: manifestJSON(t, 7, files)})),
		"padded to a 10 KiB record": gz(t, append(rawTar(
			rawEntry{name: manifestName, body: manifestJSON(t, 7, files)},
			rawEntry{name: "rules/x.yaml", body: files["rules/x.yaml"]},
			rawEntry{name: "catalog/y.yaml", body: files["catalog/y.yaml"]}), make([]byte, 10240)...)),
		"no end-of-archive marker": func() []byte {
			raw := rawTar(rawEntry{name: manifestName, body: manifestJSON(t, 7, nil)})
			return gz(t, raw[:len(raw)-1024])
		}(),
		"unknown manifest fields": gz(t, rawTar(rawEntry{name: manifestName,
			body: []byte(`{"version":7,"created":"2026-11-11T12:00:00+01:00","files":{},"min_sensor":"9.9","future":{"a":[1,2]}}`)})),
	}
	for name, tarball := range tests {
		t.Run(name, func(t *testing.T) {
			m, err := Verify(tarball, Sign(tarball, testPriv), trusted())
			if err != nil {
				t.Fatalf("Verify: %v", err)
			}
			dest := t.TempDir()
			if err := Install(tarball, m, dest); err != nil {
				t.Fatalf("Install: %v", err)
			}
			if _, err := Audit(dest); err != nil {
				t.Fatalf("Audit: %v", err)
			}
			if m.Created.Location() != time.UTC {
				t.Errorf("Created not normalised to UTC: %v", m.Created)
			}
		})
	}
}

// os.Root is the second line of defence behind the name checks: even if a
// bad name reached the writer it could not leave the staging directory.
func TestWriteFileCannotEscapeStage(t *testing.T) {
	outer := t.TempDir()
	stage := filepath.Join(outer, "stage")
	if err := os.Mkdir(stage, 0o755); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(stage)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	for _, name := range []string{"../escape.yaml", "../../escape.yaml", filepath.Join(outer, "abs.yaml")} {
		if _, err := writeFile(root, name, strings.NewReader("x")); err == nil {
			t.Errorf("writeFile(%q) succeeded", name)
		}
	}
	// An existing name is never written through, be it a file or a link.
	target := filepath.Join(outer, "target")
	os.WriteFile(target, []byte("original"), 0o644)
	if err := os.Symlink(target, filepath.Join(stage, "link.yaml")); err == nil {
		if _, err := writeFile(root, "link.yaml", strings.NewReader("overwritten")); err == nil {
			t.Error("writeFile followed a symlink")
		}
	}
	if b, _ := os.ReadFile(target); string(b) != "original" {
		t.Errorf("file outside the stage was modified: %q", b)
	}
	if got := listTree(t, outer); len(got) > 3 {
		t.Errorf("unexpected files: %v", got)
	}
}

func TestCheckName(t *testing.T) {
	good := []string{
		"lists.yaml", "suppressions.yaml", "rules/a.yaml", "rules/R01-agent_bypass.v2.yaml", "catalog/0.yaml",
		"catalog/" + strings.Repeat("a", maxNameLen-len("catalog/")-len(".yaml")) + ".yaml",
		"rules/console.yaml", "rules/com10.yaml", "rules/nul-rule.yaml",
	}
	for _, name := range good {
		if err := checkName(name); err != nil {
			t.Errorf("checkName(%q) = %v, want nil", name, err)
		}
	}
	bad := map[string]error{
		"":                    ErrUnsafePath,
		"..":                  ErrUnsafePath,
		"rules/..":            ErrUnsafePath,
		"rules/./a.yaml":      ErrUnsafePath,
		"/lists.yaml":         ErrUnsafePath,
		"rules/a.yaml/":       ErrUnsafePath,
		"rules/a\x00.yaml":    ErrUnsafePath,
		"rules/con.yaml":      ErrUnsafePath,
		"rules/PRN.a.yaml":    ErrUnsafePath,
		"rules/LPT9.yaml":     ErrUnsafePath,
		"Lists.yaml":          ErrNotAllowed,
		"lists.yaml.bak":      ErrNotAllowed,
		"manifest.json":       ErrNotAllowed,
		"rules":               ErrNotAllowed,
		"rules/a":             ErrNotAllowed,
		"rules/a.yaml.sig":    ErrNotAllowed,
		"rules/-a.yaml":       ErrNotAllowed,
		"rules/a$(id).yaml":   ErrNotAllowed,
		"rules/a;b.yaml":      ErrNotAllowed,
		"rules/a*.yaml":       ErrNotAllowed,
		"Rules/a.yaml":        ErrNotAllowed,
		"catalog/a/b.yaml":    ErrNotAllowed,
		"suppressions.yaml/x": ErrNotAllowed,
		"rules/" + strings.Repeat("a", maxNameLen) + ".yaml": ErrNotAllowed,
	}
	for name, want := range bad {
		if err := checkName(name); !errors.Is(err, want) {
			t.Errorf("checkName(%q) = %v, want %v", name, err, want)
		}
	}
	// Error text must stay short and printable whatever the name is.
	err := checkName("rules/" + strings.Repeat("\x1b[31m", 100000) + ".sh")
	if err == nil || len(err.Error()) > 600 || strings.ContainsRune(err.Error(), 0x1b) {
		t.Errorf("error for a huge hostile name is not bounded or not escaped (%d bytes)", len(err.Error()))
	}
}
