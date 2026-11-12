package probe

import (
	"strings"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/classify"
)

func TestProbe(t *testing.T) {
	for _, a := range [][]string{
		{"npm exec deploy --password=hunter2 --api-key s3cr3tvalue"},
		{"npm", "exec", "deploy", "--password=hunter2", "--api-key", "s3cr3tvalue"},
		{"--password=hunt"},
		{"ghp_R8x2Kq9LmZ4"},
		{"node"},
	} {
		t.Logf("%q -> %q", a, classify.RedactArgs(a))
	}
	big := []string{"claude", "--mcp-config", `{"a":"` + strings.Repeat("x", 250<<10) + `"}`}
	t0 := time.Now()
	for i := 0; i < 10; i++ {
		classify.RedactArgs(big)
	}
	t.Logf("256KiB: %v per call", time.Since(t0)/10)
	many := make([]string, 4096)
	for i := range many {
		many[i] = strings.Repeat("y", 60)
	}
	t0 = time.Now()
	for i := 0; i < 10; i++ {
		classify.RedactArgs(many)
	}
	t.Logf("4096x60: %v per call", time.Since(t0)/10)
	t0 = time.Now()
	for i := 0; i < 10000; i++ {
		classify.RedactArgs([]string{"node"})
	}
	t.Logf("short name: %v per call", time.Since(t0)/10000)
	t0 = time.Now()
	for i := 0; i < 10000; i++ {
		classify.Redact("node")
	}
	t.Logf("Redact short: %v per call", time.Since(t0)/10000)
}
