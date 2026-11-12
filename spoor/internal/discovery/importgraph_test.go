package discovery

import (
	"go/build"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const modulePath = "github.com/thomastysong/spoor"

// TestNoExecInScanPath enforces decision 7: no package in the scan path may
// import os/exec. It walks the import graph of discovery for every target
// OS, through module-internal and third-party packages alike. The only
// package allowed to reach os/exec is internal/platform (fixed absolute
// system binaries for host identity). The packages named in the spec
// (catalog, mcpconf, transcript) are checked as roots too.
func TestNoExecInScanPath(t *testing.T) {
	if testing.Short() {
		t.Skip("walks the import graph")
	}
	modRoot := moduleRoot(t)
	roots := []string{"internal/discovery", "internal/catalog", "internal/mcpconf", "internal/transcript", "internal/classify", "internal/shellx"}
	allowed := map[string]bool{modulePath + "/internal/platform": true}
	dirs := map[string]string{}
	sawAllowed := false
	for _, goos := range []string{"linux", "darwin", "windows"} {
		for _, goarch := range []string{"amd64", "arm64"} {
			ctx := build.Default
			ctx.GOOS, ctx.GOARCH, ctx.CgoEnabled = goos, goarch, false
			seen := map[string]bool{}
			var visit func(path string, chain []string)
			visit = func(path string, chain []string) {
				if seen[path] || path == "C" || path == "unsafe" {
					return
				}
				seen[path] = true
				dir, ok := dirs[path]
				if !ok {
					dir = resolveDir(t, path, modRoot)
					dirs[path] = dir
				}
				if dir == "" {
					return
				}
				pkg, err := ctx.ImportDir(dir, 0)
				if err != nil {
					if _, ok := err.(*build.NoGoError); ok {
						return
					}
					t.Fatalf("%s/%s: %s: %v", goos, goarch, path, err)
				}
				for _, imp := range pkg.Imports {
					if imp == "os/exec" && allowed[path] {
						sawAllowed = true
					}
					if imp == "os/exec" && !allowed[path] {
						t.Errorf("%s/%s: %s imports os/exec (via %s)", goos, goarch, path, strings.Join(append(chain, path), " -> "))
					}
					if strings.HasPrefix(imp, "internal/") || imp == "os/exec" {
						continue
					}
					if allowed[path] {
						continue
					}
					visit(imp, append(chain, path))
				}
			}
			for _, r := range roots {
				visit(modulePath+"/"+r, nil)
			}
		}
	}
	// internal/platform execs ioreg on darwin for host identity; seeing
	// that import proves the walk really reached the dependency graph.
	if !sawAllowed {
		t.Error("the walk never saw internal/platform's os/exec import: the check is not live")
	}
}

func moduleRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for d := wd; d != filepath.Dir(d); d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
	}
	t.Fatal("go.mod not found")
	return ""
}

// resolveDir finds a package's directory without running the go tool for
// module-internal and standard-library packages.
func resolveDir(t *testing.T, path, modRoot string) string {
	if strings.HasPrefix(path, modulePath+"/") {
		return filepath.Join(modRoot, filepath.FromSlash(strings.TrimPrefix(path, modulePath+"/")))
	}
	if !strings.Contains(strings.Split(path, "/")[0], ".") {
		d := filepath.Join(runtime.GOROOT(), "src", filepath.FromSlash(path))
		if _, err := os.Stat(d); err == nil {
			return d
		}
		d = filepath.Join(runtime.GOROOT(), "src", "vendor", filepath.FromSlash(path))
		if _, err := os.Stat(d); err == nil {
			return d
		}
		return ""
	}
	pkg, err := build.Default.Import(path, modRoot, build.FindOnly)
	if err != nil {
		t.Logf("cannot locate %s: %v", path, err)
		return ""
	}
	return pkg.Dir
}
