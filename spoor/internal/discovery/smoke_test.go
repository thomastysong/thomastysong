package discovery

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/catalog"
	"github.com/thomastysong/spoor/internal/platform"
)

// TestSmokeLocal scans the machine running the test and prints every
// record. It is a manual check (SPOOR_SMOKE=1), never part of CI: its output
// depends on what is installed.
func TestSmokeLocal(t *testing.T) {
	if os.Getenv("SPOOR_SMOKE") == "" {
		t.Skip("set SPOOR_SMOKE=1")
	}
	cat, err := catalog.Load()
	if err != nil {
		t.Fatal(err)
	}
	procs, _ := platform.Processes()
	start := time.Now()
	res, err := Scan(context.Background(), Options{Catalog: cat, Projects: true, Processes: procs})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("scan took %v, %d events", time.Since(start), len(res.Events))
	for _, e := range res.Events {
		b, _ := e.MarshalLine()
		fmt.Print(string(b))
	}
	l := res.Ledger
	fmt.Printf("ledger roots=%d files=%d denied=%d skipped=%d errors=%d trunc=%v\n", l.Roots, l.Files, l.Denied, l.Skipped, l.Errors, l.Truncated)
	for _, n := range l.Notes {
		fmt.Println("note:", n)
	}
}
