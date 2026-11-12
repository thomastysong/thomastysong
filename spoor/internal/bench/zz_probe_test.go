package bench

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/features"
)

// go test ./internal/bench -run TestZZProbe -v  with PROBE=<file of commands>
func TestZZProbe(t *testing.T) {
	f := os.Getenv("PROBE")
	if f == "" {
		t.Skip()
	}
	fh, err := os.Open(f)
	if err != nil {
		t.Fatal(err)
	}
	sc := bufio.NewScanner(fh)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		ev := &event.Event{V: 1, Kind: event.KindActivity, Type: event.TypeToolPre, Source: event.SourceHook,
			Tool: &event.Tool{Name: "Bash", Kind: event.ToolShell}, Target: &event.Target{Command: line},
			Session: &event.Session{ID: "s", CWD: "/home/tester/project"}, User: &event.User{ID: "1000"}, Agent: &event.Agent{ID: "claude-code"}}
		if strings.HasPrefix(line, "{") {
			ev = &event.Event{}
			if err := json.Unmarshal([]byte(line), ev); err != nil {
				t.Fatal(err)
			}
			ev.Kind = event.KindActivity
		}
		features.Compute(ev, features.Context{Home: "/home/tester", OS: "linux"})
		fmt.Printf("=== %s\n", line)
		keys := make([]string, 0)
		for k := range ev.Feat {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := ev.Feat[k]
			if b, ok := v.(bool); ok && !b {
				continue
			}
			if k == "shell.cmds" || k == "shell.install_entries" {
				b, _ := json.Marshal(v)
				fmt.Printf("   %s = %s\n", k, b)
				continue
			}
			fmt.Printf("   %s = %v\n", k, v)
		}
	}
}
