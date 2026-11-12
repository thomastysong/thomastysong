package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBundleLifecycle(t *testing.T) {
	dir := t.TempDir()
	cfg, data := testConfig(t, "")
	ta := newTestApp(t)
	keyPrefix := filepath.Join(dir, "keys", "signing")

	ta.mustRun(t, exitUsage, "bundle", "keygen")
	ta.mustRun(t, exitOK, "bundle", "keygen", "--out", keyPrefix)
	fi, err := os.Stat(keyPrefix + ".key")
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("private key mode: %v %v", fi, err)
	}
	if strings.Contains(ta.out.String(), mustRead(t, keyPrefix+".key")) {
		t.Fatal("the private key was printed")
	}
	ta.mustRun(t, exitError, "bundle", "keygen", "--out", keyPrefix) // never overwrites

	src := filepath.Join(dir, "src")
	writeTestFile(t, filepath.Join(src, "rules", "zz.yaml"), testPack, 0o644)
	arch := filepath.Join(dir, "out", "bundle.tar.gz")
	ta.env["SOURCE_DATE_EPOCH"] = "1700000000"
	ta.mustRun(t, exitUsage, "bundle", "create", "--src", src)
	ta.mustRun(t, exitOK, "bundle", "create", "--src", src, "--version", "3", "--key", keyPrefix+".key", "--out", arch, "--note", "test")
	if _, err := os.Stat(arch + ".sig"); err != nil {
		t.Fatal(err)
	}
	// Reproducible with SOURCE_DATE_EPOCH.
	arch2 := filepath.Join(dir, "out", "again.tar.gz")
	ta.mustRun(t, exitOK, "bundle", "create", "--src", src, "--version", "3", "--key", keyPrefix+".key", "--out", arch2, "--note", "test")
	if mustRead(t, arch) != mustRead(t, arch2) {
		t.Error("the same source and SOURCE_DATE_EPOCH gave different archives")
	}

	pub := keyPrefix + ".pub"
	out := ta.mustRun(t, exitOK, "bundle", "verify", "--pub", pub, arch)
	if !strings.Contains(out, "OK: version 3") || !strings.Contains(out, "rules/zz.yaml") {
		t.Fatalf("verify:\n%s", out)
	}
	// Another key does not verify it.
	other := filepath.Join(dir, "other")
	ta.mustRun(t, exitOK, "bundle", "keygen", "--out", other)
	ta.mustRun(t, exitCheck, "bundle", "verify", "--pub", other+".pub", arch)
	// Tampering is detected.
	tampered := filepath.Join(dir, "tampered.tar.gz")
	b := []byte(mustRead(t, arch))
	b[len(b)/2] ^= 0xff
	writeTestFile(t, tampered, string(b), 0o644)
	writeTestFile(t, tampered+".sig", mustRead(t, arch+".sig"), 0o644)
	ta.mustRun(t, exitCheck, "bundle", "verify", "--pub", pub, tampered)

	// Install from a local file, then it is current; rules list sees it.
	ta.mustRun(t, exitError, "bundle", "pull", "--config", cfg, "--file", arch) // no trusted key
	out = ta.mustRun(t, exitOK, "bundle", "pull", "--config", cfg, "--file", arch, "--pub", pub)
	if !strings.Contains(out, "installed bundle version 3") {
		t.Fatalf("pull:\n%s", out)
	}
	if fi, err := os.Stat(filepath.Join(data, "bundle")); err != nil || fi.Mode().Perm()&0o005 != 0o005 {
		t.Fatalf("bundle dir must be readable by unprivileged hooks: %v %v", fi, err)
	}
	out = ta.mustRun(t, exitOK, "bundle", "pull", "--config", cfg, "--file", arch, "--pub", pub)
	if !strings.Contains(out, "is current") {
		t.Fatalf("second pull:\n%s", out)
	}
	var list struct {
		Source ruleInfo `json:"source"`
	}
	decodeJSON(t, ta.mustRun(t, exitOK, "rules", "list", "--config", cfg, "--json"), &list)
	if list.Source.BundleVersion != 3 {
		t.Fatalf("rules do not include the bundle: %+v", list.Source)
	}
	// An older bundle is refused loudly.
	old := filepath.Join(dir, "old.tar.gz")
	ta.mustRun(t, exitOK, "bundle", "create", "--src", src, "--version", "2", "--key", keyPrefix+".key", "--out", old)
	ta.mustRun(t, exitError, "bundle", "pull", "--config", cfg, "--file", old, "--pub", pub)

	// A correctly signed bundle whose rules do not load is never
	// installed: the version in force stays 3.
	brokenSrc := filepath.Join(dir, "broken")
	writeTestFile(t, filepath.Join(brokenSrc, "rules", "zz.yaml"), "pack: [unclosed\n", 0o644)
	bad := filepath.Join(dir, "bad.tar.gz")
	if code := ta.run("bundle", "create", "--src", brokenSrc, "--version", "9", "--key", keyPrefix+".key", "--out", bad); code != exitOK {
		t.Logf("bundle create refused unparsable rules itself: %s", ta.errb.String())
	} else {
		ta.mustRun(t, exitError, "bundle", "pull", "--config", cfg, "--file", bad, "--pub", pub)
		decodeJSON(t, ta.mustRun(t, exitOK, "rules", "list", "--config", cfg, "--json"), &list)
		if list.Source.BundleVersion != 3 {
			t.Fatalf("a broken bundle replaced a working one: %+v", list.Source)
		}
	}
}

func TestBundleKeyPermissions(t *testing.T) {
	dir := t.TempDir()
	ta := newTestApp(t)
	ta.mustRun(t, exitOK, "bundle", "keygen", "--out", filepath.Join(dir, "k"))
	if err := os.Chmod(filepath.Join(dir, "k.key"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(dir, "src")
	writeTestFile(t, filepath.Join(src, "rules", "zz.yaml"), testPack, 0o644)
	ta.mustRun(t, exitError, "bundle", "create", "--src", src, "--version", "1", "--key", filepath.Join(dir, "k.key"), "--out", filepath.Join(dir, "b.tgz"))
	if !strings.Contains(ta.errb.String(), "chmod 600") {
		t.Fatalf("stderr: %s", ta.errb.String())
	}
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
