package hookinstall

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/event"
)

func TestZZTomlPlan(t *testing.T) {
	c := testCatalog(t)
	for _, n := range []int{3000, 6000, 12000} {
		o := opts(t, "linux", event.ScopeUser, "codex")
		path := targetPath(t, c, o, "codex")
		writeFile(t, filepath.Join(filepath.Dir(path), "config.toml"), []byte("a = "+strings.Repeat("{b=", n)+"1"+strings.Repeat("}", n)+"\n"), 0o644)
		start := time.Now()
		p := only(t, mustPlan(t, c, o), "codex")
		st, _ := os.ReadFile("/proc/self/status")
		hwm := regexp.MustCompile(`VmHWM:\s+\d+ kB`).Find(st)
		t.Logf("n=%d size=%d %s %v %s", n, 8*n, p.Action, time.Since(start), hwm)
	}
}
