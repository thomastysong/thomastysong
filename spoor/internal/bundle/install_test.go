package bundle

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func currentVersion(t *testing.T, dest string) uint64 {
	t.Helper()
	info, err := Installed(dest)
	if err != nil {
		t.Fatalf("Installed: %v", err)
	}
	return info.Manifest.Version
}

func TestInstallRequiresVerify(t *testing.T) {
	tarball, m := verified(t, 5, sampleFiles("a"))
	otherTarball, otherM := verified(t, 6, sampleFiles("b"))
	dest := t.TempDir()

	handBuilt := &Manifest{Version: m.Version, Created: m.Created, Files: m.Files}
	copied := *m
	copied.verified = false
	tests := map[string]struct {
		tarball []byte
		m       *Manifest
	}{
		"nil manifest":                    {tarball, nil},
		"hand-built manifest":             {tarball, handBuilt},
		"manifest decoded from JSON":      {tarball, mustParse(t, m)},
		"manifest of another tarball":     {tarball, otherM},
		"tarball swapped after Verify":    {otherTarball, m},
		"tarball modified after Verify":   {append(append([]byte(nil), tarball...), 0), m},
		"clone of a verified manifest":    {tarball, m.clone()},
		"verified flag cleared":           {tarball, &copied},
		"empty tarball with any manifest": {nil, m},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if err := Install(tc.tarball, tc.m, dest); !errors.Is(err, ErrNotVerified) {
				t.Fatalf("Install = %v, want ErrNotVerified", err)
			}
		})
	}
	if got := listTree(t, dest); len(got) != 0 {
		t.Errorf("refused installs touched the destination: %v", got)
	}

	// The manifest Current returns describes installed content; it is not
	// a licence to install.
	if err := Install(tarball, m, dest); err != nil {
		t.Fatal(err)
	}
	_, cm, _ := Current(dest)
	if err := Install(tarball, cm, t.TempDir()); !errors.Is(err, ErrNotVerified) {
		t.Errorf("Install with Current's manifest = %v, want ErrNotVerified", err)
	}
	if err := Install(tarball, m, ""); err == nil {
		t.Error("Install accepted an empty destination")
	}
}

func mustParse(t *testing.T, m *Manifest) *Manifest {
	t.Helper()
	b, err := m.encode()
	if err != nil {
		t.Fatal(err)
	}
	out, err := parseManifest(b)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// Whatever the caller does to the manifest after Verify, what gets
// installed is what was signed.
func TestInstallIgnoresManifestMutation(t *testing.T) {
	tarball, m := verified(t, 5, sampleFiles("a"))
	m.Version = 99
	m.Files = map[string]string{"rules/evil.yaml": sumHex([]byte("evil"))}
	m.Note = "mutated"
	dest := t.TempDir()
	if err := Install(tarball, m, dest); err != nil {
		t.Fatal(err)
	}
	dir, cm, ok := Current(dest)
	if !ok || cm.Version != 5 || filepath.Base(dir) != "v5" || cm.Note != "" || len(cm.Files) != len(sampleFiles("a")) {
		t.Fatalf("installed %+v in %s", cm, dir)
	}
}

func TestNoDowngrade(t *testing.T) {
	dest := t.TempDir()
	v4, m4 := verified(t, 4, sampleFiles("v4"))
	v5, m5 := verified(t, 5, sampleFiles("v5"))
	v5b, m5b := verified(t, 5, sampleFiles("v5-different"))
	v6, m6 := verified(t, 6, sampleFiles("v6"))
	v7, m7 := verified(t, 7, sampleFiles("v7"))

	if err := Install(v5, m5, dest); err != nil {
		t.Fatal(err)
	}

	err := Install(v4, m4, dest)
	var ve *VersionError
	if !errors.Is(err, ErrDowngrade) || !errors.As(err, &ve) || ve.Installed != 5 || ve.Offered != 4 || ve.Identical {
		t.Fatalf("older version: %v (%+v)", err, ve)
	}
	err = Install(v5, m5, dest)
	if !errors.Is(err, ErrAlreadyInstalled) || errors.Is(err, ErrDowngrade) {
		t.Fatalf("same bundle again: %v, want ErrAlreadyInstalled", err)
	}
	err = Install(v5b, m5b, dest)
	if !errors.Is(err, ErrDowngrade) || errors.Is(err, ErrAlreadyInstalled) {
		t.Fatalf("version reused for different content: %v, want ErrDowngrade", err)
	}
	if got := currentVersion(t, dest); got != 5 {
		t.Fatalf("current = v%d after refused installs, want v5", got)
	}
	if _, err := Audit(dest); err != nil {
		t.Fatalf("refused installs damaged the current bundle: %v", err)
	}
	data, err := ReadFile(filepath.Join(dest, "v5"), m5, "rules/core.yaml")
	if err != nil || !strings.Contains(string(data), "v5\n") {
		t.Fatalf("content of v5 changed: %q, %v", data, err)
	}

	if err := Install(v6, m6, dest); err != nil {
		t.Fatal(err)
	}
	// The previous version stays for readers that resolved it a moment ago.
	if _, err := os.Stat(filepath.Join(dest, "v5")); err != nil {
		t.Errorf("previous version was removed too early: %v", err)
	}
	if err := Install(v7, m7, dest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dest, "v5")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("v5 not pruned after two newer installs: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dest, "v6")); err != nil {
		t.Errorf("v6 should be kept as the previous version: %v", err)
	}
	for _, old := range []struct {
		tarball []byte
		m       *Manifest
	}{{v4, m4}, {v5, m5}, {v6, m6}} {
		if err := Install(old.tarball, old.m, dest); !errors.Is(err, ErrDowngrade) {
			t.Errorf("replay of v%d after v7 = %v, want ErrDowngrade", old.m.Version, err)
		}
	}
	if got := currentVersion(t, dest); got != 7 {
		t.Fatalf("current = v%d, want v7", got)
	}
}

// A crash can leave a staging directory, a temporary pointer, or a complete
// version directory the pointer never reached. None of them may block or
// corrupt the next install.
func TestInstallAfterInterruptedInstall(t *testing.T) {
	dest := t.TempDir()
	install(t, dest, 5, sampleFiles("v5"))

	// Leftovers of an install of v8 that died while extracting.
	stage := filepath.Join(dest, "v8.tmp")
	os.MkdirAll(filepath.Join(stage, "rules"), 0o755)
	os.WriteFile(filepath.Join(stage, "rules", "half.yaml"), []byte("partial"), 0o644)
	os.WriteFile(filepath.Join(dest, "current.tmp"), []byte(`{"version":8`), 0o644)
	if got := currentVersion(t, dest); got != 5 {
		t.Fatalf("leftovers changed the current version to v%d", got)
	}

	install(t, dest, 8, sampleFiles("v8"))
	if got := currentVersion(t, dest); got != 8 {
		t.Fatalf("current = v%d, want v8", got)
	}
	if _, err := Audit(dest); err != nil {
		t.Fatalf("Audit: %v", err)
	}
	for _, p := range listTree(t, dest) {
		if strings.Contains(p, ".tmp") || strings.Contains(p, "half") {
			t.Errorf("leftover survived: %s", p)
		}
	}

	// An install of v10 that died between the directory rename and the
	// pointer update: v10 is complete on disk, the pointer still says v8.
	install(t, dest, 10, sampleFiles("v10"))
	if err := writePointer(dest, pointer{Version: 8, Dir: "v8", Installed: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if got := currentVersion(t, dest); got != 8 {
		t.Fatalf("current = v%d, want v8", got)
	}
	// v9 was superseded on this host: accepting it now would be a rollback
	// relative to content that was already verified here.
	v9, m9 := verified(t, 9, sampleFiles("v9"))
	if err := Install(v9, m9, dest); !errors.Is(err, ErrDowngrade) {
		t.Errorf("v9 below a completed v10 = %v, want ErrDowngrade", err)
	}
	// A different bundle under the same number is refused as well.
	v10b, m10b := verified(t, 10, sampleFiles("v10-other"))
	if err := Install(v10b, m10b, dest); !errors.Is(err, ErrDowngrade) {
		t.Errorf("different v10 = %v, want ErrDowngrade", err)
	}
	install(t, dest, 10, sampleFiles("v10"))
	if got := currentVersion(t, dest); got != 10 {
		t.Fatalf("current = v%d, want v10", got)
	}
	if _, err := Audit(dest); err != nil {
		t.Fatalf("Audit: %v", err)
	}
}

func TestInstallRepairsDamagedState(t *testing.T) {
	t.Run("pointer", func(t *testing.T) {
		for name, damage := range map[string]func(dest string){
			"garbage":   func(dest string) { os.WriteFile(filepath.Join(dest, "current"), []byte("\x00\x01garbage"), 0o644) },
			"truncated": func(dest string) { os.WriteFile(filepath.Join(dest, "current"), nil, 0o644) },
			"deleted":   func(dest string) { os.Remove(filepath.Join(dest, "current")) },
			"oversized": func(dest string) {
				os.WriteFile(filepath.Join(dest, "current"), []byte(strings.Repeat(" ", 4096)+`{"version":5,"dir":"v5"}`), 0o644)
			},
		} {
			t.Run(name, func(t *testing.T) {
				dest := t.TempDir()
				install(t, dest, 4, sampleFiles("v4"))
				install(t, dest, 5, sampleFiles("v5"))
				damage(dest)
				if _, _, ok := Current(dest); ok {
					t.Fatal("Current trusted a damaged pointer")
				}
				// The floor survives the damage: the host still refuses
				// anything older than what it had.
				v4, m4 := verified(t, 4, sampleFiles("v4"))
				if err := Install(v4, m4, dest); !errors.Is(err, ErrDowngrade) {
					t.Errorf("v4 after pointer damage = %v, want ErrDowngrade", err)
				}
				install(t, dest, 5, sampleFiles("v5"))
				if got := currentVersion(t, dest); got != 5 {
					t.Fatalf("current = v%d, want v5", got)
				}
			})
		}
	})

	t.Run("content", func(t *testing.T) {
		dest := t.TempDir()
		tarball, m := verified(t, 5, sampleFiles("v5"))
		if err := Install(tarball, m, dest); err != nil {
			t.Fatal(err)
		}
		victim := filepath.Join(dest, "v5", "rules", "core.yaml")
		if err := os.WriteFile(victim, []byte("rules: [] # tampered\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Audit(dest); !errors.Is(err, ErrMismatch) {
			t.Fatalf("Audit after tampering = %v, want ErrMismatch", err)
		}
		dir, cm, _ := Current(dest)
		if _, err := ReadFile(dir, cm, "rules/core.yaml"); !errors.Is(err, ErrMismatch) {
			t.Fatalf("ReadFile of a tampered file = %v, want ErrMismatch", err)
		}
		// Installing the same bundle again repairs it instead of
		// answering "already installed".
		if err := Install(tarball, m, dest); err != nil {
			t.Fatalf("repair install: %v", err)
		}
		if _, err := Audit(dest); err != nil {
			t.Fatalf("Audit after repair: %v", err)
		}
	})

	t.Run("manifest", func(t *testing.T) {
		dest := t.TempDir()
		tarball, m := verified(t, 5, sampleFiles("v5"))
		if err := Install(tarball, m, dest); err != nil {
			t.Fatal(err)
		}
		os.WriteFile(filepath.Join(dest, "v5", "manifest.json"), []byte("{"), 0o644)
		if _, err := Installed(dest); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Installed with a broken manifest = %v, want ErrCorrupt", err)
		}
		if err := Install(tarball, m, dest); err != nil {
			t.Fatalf("repair install: %v", err)
		}
		if _, err := Audit(dest); err != nil {
			t.Fatal(err)
		}
	})
}

func TestAuditFindsPlantedAndMissingFiles(t *testing.T) {
	plant := map[string]func(dir string) error{
		"extra rule": func(dir string) error {
			return os.WriteFile(filepath.Join(dir, "rules", "planted.yaml"), []byte("x"), 0o644)
		},
		"extra top-level": func(dir string) error { return os.WriteFile(filepath.Join(dir, "extra.txt"), []byte("x"), 0o644) },
		"extra directory": func(dir string) error { return os.Mkdir(filepath.Join(dir, "rules", "sub"), 0o755) },
		"missing file":    func(dir string) error { return os.Remove(filepath.Join(dir, "lists.yaml")) },
		"file became a dir": func(dir string) error {
			os.Remove(filepath.Join(dir, "lists.yaml"))
			return os.Mkdir(filepath.Join(dir, "lists.yaml"), 0o755)
		},
		"file became a symlink": func(dir string) error {
			p := filepath.Join(dir, "rules", "core.yaml")
			b, _ := os.ReadFile(p)
			outside := filepath.Join(filepath.Dir(filepath.Dir(dir)), "outside.yaml")
			os.WriteFile(outside, b, 0o644) // same bytes: only the link betrays it
			os.Remove(p)
			return os.Symlink(outside, p)
		},
	}
	for name, do := range plant {
		t.Run(name, func(t *testing.T) {
			dest := filepath.Join(t.TempDir(), "bundle")
			install(t, dest, 5, sampleFiles("v5"))
			dir, m, _ := Current(dest)
			if err := do(dir); err != nil {
				t.Skipf("cannot set up: %v", err)
			}
			if _, err := Audit(dest); !errors.Is(err, ErrMismatch) {
				t.Fatalf("Audit = %v, want ErrMismatch", err)
			}
			if name == "file became a symlink" {
				if _, err := ReadFile(dir, m, "rules/core.yaml"); !errors.Is(err, ErrMismatch) {
					t.Errorf("ReadFile followed a symlink: %v", err)
				}
			}
		})
	}
}

func TestReadFileRefusesBadNames(t *testing.T) {
	dest := t.TempDir()
	install(t, dest, 5, sampleFiles("v5"))
	dir, m, _ := Current(dest)
	os.WriteFile(filepath.Join(dest, "secret"), []byte("s"), 0o600)

	if _, err := ReadFile(dir, nil, "lists.yaml"); err == nil {
		t.Error("ReadFile accepted a nil manifest")
	}
	for _, name := range []string{"../secret", "manifest.json", "current", "rules/../lists.yaml", "/etc/passwd", ""} {
		if _, err := ReadFile(dir, m, name); !errors.Is(err, fs.ErrNotExist) {
			t.Errorf("ReadFile(%q) = %v, want fs.ErrNotExist", name, err)
		}
	}
	// A manifest edited by the caller to list a hostile path still cannot
	// make ReadFile leave the directory.
	evil := m.clone()
	evil.Files["../secret"] = sumHex([]byte("s"))
	if _, err := ReadFile(dir, evil, "../secret"); !errors.Is(err, ErrUnsafePath) {
		t.Errorf("ReadFile with a forged manifest entry = %v, want ErrUnsafePath", err)
	}
	if _, err := ReadFile(filepath.Join(dest, "nope"), m, "lists.yaml"); !errors.Is(err, ErrCorrupt) {
		t.Errorf("ReadFile from a missing directory = %v, want ErrCorrupt", err)
	}
}

func TestValidateGatesTheSwitch(t *testing.T) {
	dest := t.TempDir()
	install(t, dest, 5, sampleFiles("v5"))
	before := listTree(t, dest)
	tarball, m := verified(t, 6, sampleFiles("v6"))

	broken := errors.New("rule R01: unknown field")
	tests := map[string]func(dir string, m *Manifest) error{
		"error": func(string, *Manifest) error { return broken },
		"panic": func(string, *Manifest) error { panic("validator bug") },
	}
	for name, validate := range tests {
		t.Run(name, func(t *testing.T) {
			err := InstallWith(tarball, m, dest, InstallOptions{Validate: validate})
			if !errors.Is(err, ErrRejected) {
				t.Fatalf("InstallWith = %v, want ErrRejected", err)
			}
			if name == "error" && !errors.Is(err, broken) {
				t.Errorf("the validator's own error is not reachable: %v", err)
			}
			if got := currentVersion(t, dest); got != 5 {
				t.Fatalf("current = v%d, want v5", got)
			}
			if after := listTree(t, dest); !reflect.DeepEqual(after, before) {
				t.Errorf("a rejected bundle left traces:\nbefore %v\nafter  %v", before, after)
			}
		})
	}

	// A passing validator sees the complete, verified content before the
	// switch, and the bundle that was current stays current meanwhile.
	called := false
	err := InstallWith(tarball, m, dest, InstallOptions{Validate: func(dir string, vm *Manifest) error {
		called = true
		if vm.Version != 6 || !vm.Equal(m) {
			return fmt.Errorf("validator got manifest %+v", vm)
		}
		for _, name := range vm.Paths() {
			if _, err := ReadFile(dir, vm, name); err != nil {
				return err
			}
		}
		if got := currentVersion(t, dest); got != 5 {
			return fmt.Errorf("v%d became current before validation finished", got)
		}
		vm.Files["rules/injected.yaml"] = "x" // must not affect the install
		return nil
	}})
	if err != nil || !called {
		t.Fatalf("InstallWith = %v, validator called = %v", err, called)
	}
	if got := currentVersion(t, dest); got != 6 {
		t.Fatalf("current = v%d, want v6", got)
	}
	if _, err := Audit(dest); err != nil {
		t.Fatal(err)
	}
}

func TestPointerCannotLeadOutside(t *testing.T) {
	outer := t.TempDir()
	dest := filepath.Join(outer, "bundle")
	install(t, dest, 5, sampleFiles("v5"))
	// A complete, valid bundle directory outside the destination.
	elsewhere := filepath.Join(outer, "elsewhere")
	install(t, elsewhere, 5, sampleFiles("attacker"))

	pointers := map[string]string{
		"relative escape":  `{"version":5,"dir":"../elsewhere/v5"}`,
		"absolute path":    `{"version":5,"dir":"` + filepath.ToSlash(filepath.Join(elsewhere, "v5")) + `"}`,
		"version mismatch": `{"version":6,"dir":"v5"}`,
		"padded name":      `{"version":5,"dir":"v05"}`,
		"dot":              `{"version":5,"dir":"."}`,
		"no dir":           `{"version":5}`,
		"version zero":     `{"version":0,"dir":"v0"}`,
		"missing target":   `{"version":77,"dir":"v77"}`,
		"not json":         `v5`,
	}
	for name, content := range pointers {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(dest, "current"), []byte(content), 0o644); err != nil {
				t.Fatal(err)
			}
			if dir, _, ok := Current(dest); ok {
				t.Fatalf("Current followed the pointer to %s", dir)
			}
			if _, err := Installed(dest); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("Installed = %v, want ErrCorrupt", err)
			}
		})
	}

	t.Run("pointer is a symlink", func(t *testing.T) {
		os.Remove(filepath.Join(dest, "current"))
		symlink(t, filepath.Join(elsewhere, "current"), filepath.Join(dest, "current"))
		if _, err := Installed(dest); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Installed = %v, want ErrCorrupt", err)
		}
	})
	t.Run("version directory is a symlink", func(t *testing.T) {
		os.Remove(filepath.Join(dest, "current"))
		if err := writePointer(dest, pointer{Version: 5, Dir: "v5"}); err != nil {
			t.Fatal(err)
		}
		os.RemoveAll(filepath.Join(dest, "v5"))
		symlink(t, filepath.Join(elsewhere, "v5"), filepath.Join(dest, "v5"))
		if _, err := Installed(dest); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Installed = %v, want ErrCorrupt", err)
		}
		// A later install never writes through the link.
		install(t, dest, 6, sampleFiles("v6"))
		if _, err := Audit(elsewhere); err != nil {
			t.Errorf("the directory behind the symlink was modified: %v", err)
		}
	})
	t.Run("manifest is a symlink", func(t *testing.T) {
		d := filepath.Join(t.TempDir(), "bundle")
		install(t, d, 5, sampleFiles("v5"))
		os.Remove(filepath.Join(d, "v5", "manifest.json"))
		symlink(t, filepath.Join(elsewhere, "v5", "manifest.json"), filepath.Join(d, "v5", "manifest.json"))
		if _, err := Installed(d); !errors.Is(err, ErrCorrupt) {
			t.Fatalf("Installed = %v, want ErrCorrupt", err)
		}
	})
}

func TestInsecurePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no mode bits on Windows")
	}
	tarball, m := verified(t, 6, sampleFiles("v6"))

	targets := map[string]func(dest string) string{
		"destination":       func(dest string) string { return dest },
		"version directory": func(dest string) string { return filepath.Join(dest, "v5") },
		"pointer":           func(dest string) string { return filepath.Join(dest, "current") },
		"manifest":          func(dest string) string { return filepath.Join(dest, "v5", "manifest.json") },
	}
	for name, target := range targets {
		for _, bits := range []os.FileMode{0o020, 0o002} {
			t.Run(fmt.Sprintf("%s +%03o", name, bits), func(t *testing.T) {
				dest := filepath.Join(t.TempDir(), "bundle")
				install(t, dest, 5, sampleFiles("v5"))
				p := target(dest)
				fi, _ := os.Stat(p)
				if err := os.Chmod(p, fi.Mode().Perm()|bits); err != nil {
					t.Fatal(err)
				}
				if _, _, ok := Current(dest); ok {
					t.Error("Current loaded from a location others can write")
				}
				if _, err := Installed(dest); !errors.Is(err, ErrInsecure) {
					t.Errorf("Installed = %v, want ErrInsecure", err)
				}
				if name == "destination" {
					if err := Install(tarball, m, dest); !errors.Is(err, ErrInsecure) {
						t.Errorf("Install into a writable-by-others destination = %v, want ErrInsecure", err)
					}
				}
			})
		}
	}

	t.Run("owned by another user", func(t *testing.T) {
		if os.Geteuid() != 0 {
			t.Skip("needs root to change ownership")
		}
		dest := filepath.Join(t.TempDir(), "bundle")
		install(t, dest, 5, sampleFiles("v5"))
		if err := os.Chown(dest, 12345, 12345); err != nil {
			t.Skipf("chown: %v", err)
		}
		if _, err := Installed(dest); !errors.Is(err, ErrInsecure) {
			t.Errorf("Installed = %v, want ErrInsecure", err)
		}
		if err := Install(tarball, m, dest); !errors.Is(err, ErrInsecure) {
			t.Errorf("Install = %v, want ErrInsecure", err)
		}
	})

	// The modes Install sets do not depend on the umask of the installer.
	t.Run("restrictive umask", func(t *testing.T) {
		dest := filepath.Join(t.TempDir(), "bundle")
		withUmask(t, 0o077, func() { install(t, dest, 5, sampleFiles("v5")) })
		for p, want := range map[string]os.FileMode{
			dest: 0o755, filepath.Join(dest, "v5"): 0o755, filepath.Join(dest, "v5", "catalog"): 0o755,
			filepath.Join(dest, "current"): 0o644, filepath.Join(dest, "v5", "lists.yaml"): 0o644,
		} {
			if fi, err := os.Stat(p); err != nil || fi.Mode().Perm() != want {
				t.Errorf("%s: mode %v, %v; want %04o", p, fi.Mode().Perm(), err, want)
			}
		}
	})
	t.Run("permissive umask", func(t *testing.T) {
		dest := filepath.Join(t.TempDir(), "bundle")
		withUmask(t, 0, func() { install(t, dest, 5, sampleFiles("v5")) })
		if _, err := Installed(dest); err != nil {
			t.Errorf("an install under umask 0 is not loadable: %v", err)
		}
	})
}

func TestInstallIntoAFile(t *testing.T) {
	tarball, m := verified(t, 5, sampleFiles("v5"))
	notDir := filepath.Join(t.TempDir(), "file")
	os.WriteFile(notDir, []byte("x"), 0o644)
	if err := Install(tarball, m, notDir); err == nil {
		t.Fatal("Install into a regular file succeeded")
	}
	if _, err := Installed(notDir); !errors.Is(err, ErrCorrupt) {
		t.Errorf("Installed on a regular file = %v, want ErrCorrupt", err)
	}
	if _, _, ok := Current(""); ok {
		t.Error("Current(\"\") reported a bundle")
	}
}

func TestParseVersionDir(t *testing.T) {
	good := map[string]uint64{"v1": 1, "v42": 42, "v18446744073709551615": 1<<64 - 1}
	for name, want := range good {
		if v, ok := parseVersionDir(name); !ok || v != want {
			t.Errorf("parseVersionDir(%q) = %d, %v", name, v, ok)
		}
	}
	for _, name := range []string{"", "v", "v0", "v01", "v-1", "v+1", "v1 ", " v1", "V1", "v1.tmp", "v18446744073709551616", "v1e3", "v٣", "current", "1"} {
		if v, ok := parseVersionDir(name); ok {
			t.Errorf("parseVersionDir(%q) = %d, accepted", name, v)
		}
	}
}

func TestConcurrentInstallSameVersion(t *testing.T) {
	dest := t.TempDir()
	tarball, _ := build(t, 5, sampleFiles("v5"))
	sig := Sign(tarball, testPriv)

	const n = 16
	errs := make([]error, n)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			m, err := Verify(tarball, sig, trusted())
			if err != nil {
				errs[i] = err
				return
			}
			<-start
			errs[i] = Install(tarball, m, dest)
		}(i)
	}
	close(start)
	wg.Wait()

	wins := 0
	for i, err := range errs {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, ErrAlreadyInstalled):
		default:
			t.Errorf("installer %d: %v", i, err)
		}
	}
	if wins != 1 {
		t.Errorf("%d installers reported success, want exactly 1", wins)
	}
	if _, err := Audit(dest); err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if got, want := listTree(t, dest), 3+1+len(sampleFiles(""))+2; len(got) != want {
		t.Errorf("destination has %d entries, want %d: %v", len(got), want, got)
	}
}

func TestConcurrentInstallManyVersions(t *testing.T) {
	dest := t.TempDir()
	const n = 24
	type job struct {
		tarball []byte
		m       *Manifest
	}
	jobs := make([]job, n)
	for i := range jobs {
		jobs[i].tarball, jobs[i].m = verified(t, uint64(i+1), sampleFiles(fmt.Sprintf("v%d", i+1)))
	}
	rand.New(rand.NewSource(1)).Shuffle(n, func(i, j int) { jobs[i], jobs[j] = jobs[j], jobs[i] })

	// Readers run alongside the installers. Whatever they observe must be a
	// complete bundle, and the version they see never goes backwards.
	stop := make(chan struct{})
	var readers sync.WaitGroup
	var observed atomic.Int64
	for r := 0; r < 4; r++ {
		readers.Add(1)
		go func() {
			defer readers.Done()
			var last uint64
			for {
				select {
				case <-stop:
					return
				default:
				}
				dir, m, ok := Current(dest)
				if !ok {
					continue
				}
				observed.Add(1)
				if m.Version < last {
					t.Errorf("reader saw v%d after v%d", m.Version, last)
				}
				last = m.Version
				if filepath.Base(dir) != versionDir(m.Version) {
					t.Errorf("Current returned dir %s for v%d", dir, m.Version)
				}
				// A read either succeeds with verified bytes or fails
				// because the directory was pruned two installs later;
				// it never returns content of another version.
				if b, err := ReadFile(dir, m, "rules/core.yaml"); err == nil {
					if want := fmt.Sprintf("rules: [] # v%d\n", m.Version); string(b) != want {
						t.Errorf("v%d served %q", m.Version, b)
					}
				}
			}
		}()
	}

	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range jobs {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs[i] = Install(jobs[i].tarball, jobs[i].m, dest)
		}(i)
	}
	wg.Wait()
	close(stop)
	readers.Wait()

	installedTop := false
	for i, err := range errs {
		switch {
		case err == nil:
			if jobs[i].m.Version == n {
				installedTop = true
			}
		case errors.Is(err, ErrDowngrade):
		default:
			t.Errorf("install of v%d: %v", jobs[i].m.Version, err)
		}
	}
	if !installedTop {
		t.Error("the highest version did not install")
	}
	info, err := Audit(dest)
	if err != nil {
		t.Fatalf("Audit: %v", err)
	}
	if info.Manifest.Version != n {
		t.Fatalf("current = v%d, want v%d: a lower version won a race", info.Manifest.Version, n)
	}
	entries, _ := os.ReadDir(dest)
	dirs := 0
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("staging leftover %s", e.Name())
		}
		if _, ok := parseVersionDir(e.Name()); ok {
			dirs++
		}
	}
	if dirs > 2 {
		t.Errorf("%d version directories kept, want at most 2 (current and previous)", dirs)
	}
	if observed.Load() == 0 {
		t.Log("readers never observed a bundle (installs finished too quickly); ordering checks did not run")
	}
}

func TestInstallLockTimeout(t *testing.T) {
	dest := t.TempDir()
	tarball, m := verified(t, 5, sampleFiles("v5"))
	release, err := acquire(filepath.Join(dest, lockName), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	err = InstallWith(tarball, m, dest, InstallOptions{LockTimeout: 150 * time.Millisecond})
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("InstallWith while locked = %v, want ErrBusy", err)
	}
	if waited := time.Since(start); waited < 100*time.Millisecond || waited > 5*time.Second {
		t.Errorf("waited %v for the lock, want about 150ms", waited)
	}
	if _, _, ok := Current(dest); ok {
		t.Error("something was installed without the lock")
	}
	release()
	if err := InstallWith(tarball, m, dest, InstallOptions{LockTimeout: time.Second}); err != nil {
		t.Fatalf("InstallWith after release: %v", err)
	}
}

// The lock must exclude other processes, and it must not outlive a process
// that dies holding it: an installer killed mid-flight cannot be allowed to
// block content updates until someone cleans up by hand.
func TestLockAcrossProcesses(t *testing.T) {
	if os.Getenv("SPOOR_BUNDLE_LOCK_HELPER") != "" {
		lockHelper()
		return
	}
	switch runtime.GOOS {
	case "linux", "darwin", "freebsd", "netbsd", "openbsd", "dragonfly", "windows":
	default:
		t.Skip("no cross-process lock on this platform")
	}
	lock := filepath.Join(t.TempDir(), lockName)
	cmd := exec.Command(os.Args[0], "-test.run=^TestLockAcrossProcesses$")
	cmd.Env = append(os.Environ(), "SPOOR_BUNDLE_LOCK_HELPER="+lock)
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Skipf("cannot start a helper process: %v", err)
	}
	defer cmd.Process.Kill()
	line, _ := bufio.NewReader(out).ReadString('\n')
	if strings.TrimSpace(line) != "locked" {
		t.Fatalf("helper said %q", line)
	}

	if _, err := acquire(lock, 200*time.Millisecond); !errors.Is(err, ErrBusy) {
		t.Fatalf("acquire while another process holds the lock = %v, want ErrBusy", err)
	}
	cmd.Process.Kill()
	cmd.Wait()
	release, err := acquire(lock, 5*time.Second)
	if err != nil {
		t.Fatalf("acquire after the holder was killed: %v", err)
	}
	release()
}

func lockHelper() {
	release, err := acquire(os.Getenv("SPOOR_BUNDLE_LOCK_HELPER"), time.Second)
	if err != nil {
		fmt.Println("error:", err)
		os.Exit(1)
	}
	fmt.Println("locked")
	time.Sleep(time.Minute) // killed by the parent long before this
	release()               // also keeps the lock's file handle reachable until here
	os.Exit(0)
}

func TestForceVerifiedHelperMatchesVerify(t *testing.T) {
	// Guards the test helper itself: if the binding between Verify and
	// Install changes, the hostile-archive tests must not silently stop
	// reaching Install's checks.
	tarball, m := verified(t, 7, sampleFiles("x"))
	forced := forceVerified(tarball)
	if forced.sum != m.sum || forced.verified != m.verified || m.sum != sha256.Sum256(tarball) {
		t.Fatal("forceVerified no longer mirrors what Verify sets")
	}
}
