package mcpconf

import (
	"os"
	"os/exec"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// builtAtInit records whether anything built the tables before the first
// test ran, i.e. during package init.
var builtAtInit bool

// envInitOnly makes the test binary exit right after package init, so a
// child run under GODEBUG=inittrace=1 reports this package's init cost.
const envInitOnly = "SPOOR_MCPCONF_INIT_ONLY"

func TestMain(m *testing.M) {
	if os.Getenv(envInitOnly) == "1" {
		os.Exit(0)
	}
	builtAtInit = tablesBuilt()
	os.Exit(m.Run())
}

// TestPackageInitIsLazy pins the start-up contract: linking the package
// builds nothing; the first use of a table builds them all.
func TestPackageInitIsLazy(t *testing.T) {
	if builtAtInit {
		t.Fatal("tables were built during package init; they must be built on first use (tables.go)")
	}
	ss, err := Parse("/a/.mcp.json", []byte(`{"mcpServers":{"x":{"command":"npx","args":["-y","pkg@1.2.3"]}}}`), FormatAuto)
	if err != nil || len(ss) != 1 {
		t.Fatalf("parse: %v %v", ss, err)
	}
	// A plain JSON declaration needs no table to parse; reading its launch
	// line does.
	if m := Normalize(ss[0]); m.Package != "pkg" || !tablesBuilt() {
		t.Fatalf("tables built %v after Normalize; package %q", tablesBuilt(), m.Package)
	}
}

// TestTablesComplete checks that buildTables fills every table: a field a
// builder forgot reads as an empty map or panics as a nil regexp.
func TestTablesComplete(t *testing.T) {
	v := reflect.ValueOf(tab()).Elem()
	for i := 0; i < v.NumField(); i++ {
		f, name := v.Field(i), v.Type().Field(i).Name
		switch f.Kind() {
		case reflect.Pointer:
			if f.IsNil() {
				t.Errorf("%s is nil", name)
			}
		case reflect.Map, reflect.Slice:
			if f.Len() == 0 {
				t.Errorf("%s is empty", name)
			}
		default:
			t.Errorf("%s: unexpected kind %s", name, f.Kind())
		}
	}
}

// TestPackageInitAllocs runs this test binary up to the end of package init
// under GODEBUG=inittrace=1 and reads the package's line. Before the tables
// were made lazy it read 2,691 allocations; the bound leaves room for test
// files' own package variables, which run in the same init.
func TestPackageInitAllocs(t *testing.T) {
	if testing.Short() {
		t.Skip("starts a subprocess")
	}
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), envInitOnly+"=1", "GODEBUG=inittrace=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	// Compiled here, not at package level: a test file's package variables
	// run in the init being measured.
	reInitLine := regexp.MustCompile(`init github\.com/thomastysong/spoor/internal/mcpconf @\S+ ms, \S+ ms clock, (\d+) bytes, (\d+) allocs`)
	m := reInitLine.FindSubmatch(out)
	if m == nil {
		if !strings.Contains(string(out), "init ") {
			t.Skip("this runtime does not print an init trace")
		}
		// No line at all means the package has no init work left.
		return
	}
	allocs, _ := strconv.Atoi(string(m[2]))
	bytes, _ := strconv.Atoi(string(m[1]))
	t.Logf("package init (with test files): %d allocs, %d bytes", allocs, bytes)
	if allocs > 32 || bytes > 8<<10 {
		t.Errorf("package init does %d allocations, %d bytes; tables must be built on first use", allocs, bytes)
	}
}
