package bench

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/transcript"
)

func TestZZSurvey(t *testing.T) {
	if os.Getenv("SURVEY") == "" {
		t.Skip()
	}
	p, _ := transcript.ForFormat(transcript.FormatClaude)
	var files []string
	filepath.Walk("/root/.claude/projects", func(path string, info os.FileInfo, err error) error {
		if err == nil && info.Mode().IsRegular() && strings.HasSuffix(path, ".jsonl") {
			files = append(files, path)
		}
		return nil
	})
	types := map[string]int{}
	kinds := map[string]int{}
	names := map[string]int{}
	sess := map[string]int{}
	subs := map[string]bool{}
	pm := map[string]int{}
	for _, f := range files {
		evs, _, err := transcript.ReadFile(f, p, event.User{Name: "root", ID: "0"}, 0)
		if err != nil {
			t.Logf("%s: %v", f, err)
			continue
		}
		for _, e := range evs {
			types[e.Type]++
			if e.Session != nil {
				sess[e.Session.ID]++
				if e.Session.SubagentID != "" {
					subs[e.Session.ID+"/"+e.Session.SubagentID] = true
				}
				pm[e.Session.PermissionMode]++
			}
			if e.Type == event.TypeToolPre && e.Tool != nil {
				kinds[string(e.Tool.Kind)]++
				names[e.Tool.Name]++
			}
		}
	}
	fmt.Println("files", len(files), "sessions", len(sess), "subagent threads", len(subs))
	dump := func(m map[string]int) {
		ks := make([]string, 0, len(m))
		for k := range m {
			ks = append(ks, k)
		}
		sort.Slice(ks, func(i, j int) bool { return m[ks[i]] > m[ks[j]] })
		for _, k := range ks {
			fmt.Printf("  %6d %s\n", m[k], k)
		}
	}
	dump(types)
	dump(kinds)
	dump(names)
	dump(pm)
}
