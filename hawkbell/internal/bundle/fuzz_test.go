package bundle

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzArchive throws arbitrary bytes at the archive reader and at Install.
// Whatever happens, there must be no panic, an accepted archive must satisfy
// every invariant the rest of the package relies on, and nothing may ever be
// written outside the destination.
//
// With wrap set the input is taken as a tar stream and compressed by the
// harness. Mutating compressed bytes almost always just breaks the gzip
// checksum; mutating the tar stream is what reaches the header and manifest
// checks.
func FuzzArchive(f *testing.F) {
	good, _ := build(f, 3, sampleFiles("fuzz"))
	f.Add(good, false)
	f.Add(forge(f, goodFiles), false)
	f.Add([]byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0}, false)
	f.Add([]byte{}, false)
	manifest := rawEntry{name: manifestName, body: manifestJSON(f, 7, goodFiles)}
	rule := rawEntry{name: "rules/core.yaml", body: goodFiles["rules/core.yaml"]}
	lists := rawEntry{name: "lists.yaml", body: goodFiles["lists.yaml"]}
	f.Add(rawTar(manifest, lists, rule), true)
	f.Add(rawTar(rule, lists, manifest), true)
	f.Add(rawTar(manifest, lists, rule, rawEntry{name: "../x.yaml", body: []byte("x")}), true)
	f.Add(rawTar(manifest, lists, rule, rawEntry{name: "rules/x.yaml", typ: '2', link: "/etc/passwd"}), true)
	f.Add(rawTar(manifest, lists, rule, rawEntry{name: "rules/x.yaml", typ: 'S', gnu: true}), true)
	f.Add(rawTar(rawEntry{name: manifestName, body: []byte(`{"version":1,"created":"2026-11-11T12:00:00Z","files":{}}`)}), true)
	f.Add([]byte("not a tar stream"), true)

	f.Fuzz(func(t *testing.T, data []byte, wrap bool) {
		if wrap {
			data = gz(t, data)
		}
		m, err := checkArchive(data)
		if err != nil {
			if m != nil {
				t.Fatal("checkArchive returned a manifest together with an error")
			}
			if Reason(err) == "error" {
				t.Fatalf("unclassified error: %v", err)
			}
		} else {
			if m.Version == 0 || m.Created.IsZero() || len(m.Files) >= MaxFiles {
				t.Fatalf("accepted an invalid manifest: %+v", m)
			}
			for name, sum := range m.Files {
				if checkName(name) != nil || !isHexSum(sum) {
					t.Fatalf("accepted file %q with hash %q", name, sum)
				}
			}
		}

		outer := t.TempDir()
		dest := filepath.Join(outer, "bundle")
		forged := &Manifest{sum: sha256.Sum256(data), verified: true}
		ierr := Install(data, forged, dest)
		if (ierr == nil) != (err == nil) {
			t.Fatalf("checkArchive said %v but Install said %v", err, ierr)
		}
		for _, p := range listTree(t, outer) {
			if p != "bundle" && !strings.HasPrefix(p, "bundle/") {
				t.Fatalf("Install wrote outside the destination: %s", p)
			}
		}
		if ierr != nil {
			if _, _, ok := Current(dest); ok {
				t.Fatal("a refused archive became current")
			}
			return
		}
		info, aerr := Audit(dest)
		if aerr != nil || !info.Manifest.Equal(m) {
			t.Fatalf("installed bundle does not match what was checked: %v", aerr)
		}
	})
}

// FuzzVerify checks that nothing unsigned ever yields a manifest, whatever
// the bytes and the signature look like.
func FuzzVerify(f *testing.F) {
	good, sig := build(f, 3, sampleFiles("fuzz"))
	f.Add(good, sig)
	f.Add(good, []byte("AAAA"))
	f.Add([]byte("x"), bytes.Repeat([]byte{0}, 64))
	f.Fuzz(func(t *testing.T, data, sig []byte) {
		m, err := Verify(data, sig, trusted())
		if bytes.Equal(data, good) {
			return // the one input a valid signature exists for
		}
		if err == nil || m != nil {
			t.Fatalf("Verify accepted %d unsigned bytes", len(data))
		}
		if !errors.Is(err, ErrSignature) && !errors.Is(err, ErrTooLarge) {
			t.Fatalf("unsigned input was parsed before the signature check: %v", err)
		}
	})
}

func FuzzParseKeys(f *testing.F) {
	f.Add(EncodePublicKey(testPub))
	f.Add(EncodePrivateKey(testPriv))
	f.Add("-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----")
	f.Add("ed25519:")
	f.Fuzz(func(t *testing.T, s string) {
		if pub, err := ParsePublicKey(s); err == nil {
			if len(pub) != 32 || allZero(pub) {
				t.Fatalf("accepted a bad public key: %x", pub)
			}
		} else if !errors.Is(err, ErrKey) {
			t.Fatalf("unclassified error: %v", err)
		}
		if priv, err := ParsePrivateKey(s); err == nil {
			if len(priv) != 64 || Sign([]byte("x"), priv) == nil {
				t.Fatalf("accepted a bad private key (%d bytes)", len(priv))
			}
		} else if !errors.Is(err, ErrKey) {
			t.Fatalf("unclassified error: %v", err)
		}
	})
}

func FuzzCheckName(f *testing.F) {
	for _, s := range []string{"rules/a.yaml", "../a.yaml", "lists.yaml", "rules/con.yaml", "catalog/\x00.yaml", ""} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, name string) {
		if checkName(name) != nil {
			return
		}
		// Anything accepted is a plain relative path of at most two
		// elements that means the same on every supported OS.
		if filepath.IsAbs(name) || strings.ContainsAny(name, "\\:\x00") || strings.Contains(name, "..") && strings.Contains(name, "/..") ||
			len(name) > maxNameLen || strings.Count(name, "/") > 1 || !strings.HasSuffix(name, ".yaml") {
			t.Fatalf("checkName accepted %q", name)
		}
		for _, c := range []byte(name) {
			if c <= ' ' || c >= 0x7f {
				t.Fatalf("checkName accepted a non-printable or non-ASCII name: %q", name)
			}
		}
	})
}
