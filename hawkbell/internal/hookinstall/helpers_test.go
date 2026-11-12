package hookinstall

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/thomastysong/thomastysong/hawkbell/internal/catalog"
	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

var (
	catOnce sync.Once
	catVal  *catalog.Catalog
	catErr  error
)

func testCatalog(t testing.TB) *catalog.Catalog {
	t.Helper()
	catOnce.Do(func() { catVal, catErr = catalog.Load() })
	if catErr != nil {
		t.Fatalf("catalog.Load: %v", catErr)
	}
	return catVal
}

const (
	unixBin = "/usr/local/bin/hawkbell"
	winBin  = `C:\Program Files\hawkbell\hawkbell.exe`
)

func binFor(goos string) string {
	if goos == "windows" {
		return winBin
	}
	return unixBin
}

func homeFor(goos string) string {
	switch goos {
	case "windows":
		return `C:\Users\dev`
	case "darwin":
		return "/Users/dev"
	}
	return "/home/dev"
}

// opts returns Options for one agent rendered under a fresh fake root.
func opts(t testing.TB, goos string, scope event.Scope, agents ...string) Options {
	t.Helper()
	return Options{
		Binary: binFor(goos), Scope: scope, Agents: agents,
		Root: t.TempDir(), Home: homeFor(goos), GOOS: goos,
	}
}

func mustPlan(t testing.TB, c *catalog.Catalog, o Options) []Plan {
	t.Helper()
	plans, err := PlanInstall(c, o)
	if err != nil {
		t.Fatalf("PlanInstall: %v", err)
	}
	return plans
}

func mustUnplan(t testing.TB, c *catalog.Catalog, o Options) []Plan {
	t.Helper()
	plans, err := PlanUninstall(c, o)
	if err != nil {
		t.Fatalf("PlanUninstall: %v", err)
	}
	return plans
}

func mustApply(t testing.TB, plans []Plan) {
	t.Helper()
	if err := Apply(plans); err != nil {
		t.Fatalf("Apply: %v", err)
	}
}

// only returns the single plan for agent, failing when there is not
// exactly one.
func only(t testing.TB, plans []Plan, agent string) Plan {
	t.Helper()
	var out []Plan
	for _, p := range plans {
		if p.AgentID == agent {
			out = append(out, p)
		}
	}
	if len(out) != 1 {
		t.Fatalf("want one plan for %s, got %d: %+v", agent, len(out), summarize(plans))
	}
	return out[0]
}

func summarize(plans []Plan) string {
	var b strings.Builder
	for _, p := range plans {
		b.WriteString(p.AgentID + " " + string(p.Scope) + " " + p.Action + " " + p.Path + " :: " + p.Note + "\n")
	}
	return b.String()
}

// targetPath is where PlanInstall puts agent's file for these options.
func targetPath(t testing.TB, c *catalog.Catalog, o Options, agent string) string {
	t.Helper()
	return only(t, mustPlan(t, c, o), agent).Path
}

func writeFile(t testing.TB, path string, data []byte, mode os.FileMode) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

func readBytes(t testing.TB, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func exists(path string) bool {
	_, err := os.Lstat(path)
	return err == nil
}

// leftovers lists temporary files Apply may have left in dir.
func leftovers(t testing.TB, dir string) []string {
	t.Helper()
	ents, err := os.ReadDir(dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".tmp") {
			out = append(out, e.Name())
		}
	}
	return out
}

func backups(t testing.TB, dir string) []string {
	t.Helper()
	ents, _ := os.ReadDir(dir)
	var out []string
	for _, e := range ents {
		if strings.HasSuffix(e.Name(), ".bak") {
			out = append(out, filepath.Join(dir, e.Name()))
		}
	}
	return out
}

func states(t testing.TB, c *catalog.Catalog, o Options) []State {
	t.Helper()
	st, err := Status(c, o)
	if err != nil {
		t.Fatalf("Status: %v", err)
	}
	return st
}

func stateOf(t testing.TB, c *catalog.Catalog, o Options, agent string) State {
	t.Helper()
	var out []State
	for _, s := range states(t, c, o) {
		if s.AgentID == agent {
			out = append(out, s)
		}
	}
	if len(out) != 1 {
		t.Fatalf("want one state for %s, got %+v", agent, out)
	}
	return out[0]
}

func contains(b []byte, s string) bool { return bytes.Contains(b, []byte(s)) }

// allocDuring reports how many bytes f allocated.
func allocDuring(f func()) uint64 {
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	f()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc
}
