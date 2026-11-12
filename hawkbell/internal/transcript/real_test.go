package transcript

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// TestRealTranscripts runs the parsers over real session logs and prints
// content-free statistics: record counts, event types, tool kinds and the
// record types no parser recognized. It reads the files named by
// HAWKBELL_TRANSCRIPT_GLOB (a Root glob, "**" allowed) and is skipped without
// it. It fails when a log yields no events at all or is mostly not
// understood, which is what schema drift looks like.
func TestRealTranscripts(t *testing.T) {
	glob := os.Getenv("HAWKBELL_TRANSCRIPT_GLOB")
	if glob == "" {
		t.Skip("set HAWKBELL_TRANSCRIPT_GLOB to check real session logs")
	}
	cands := expandGlob(t.Context(), 0, glob)
	if len(cands) == 0 {
		t.Fatalf("no files match %s", glob)
	}
	events := map[string]int{}
	kinds := map[string]int{}
	outcomes := map[string]int{}
	unknownTypes := map[string]int{}
	var files, lines, unknown, malformed, total int
	for _, c := range cands {
		p, ok := ForPath(c.path)
		if !ok || c.symlink {
			continue
		}
		files++
		st := &FileState{Path: c.path}
		f, err := os.Open(c.path)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 1<<20), 64<<20)
		n := 0
		for sc.Scan() {
			before := st.Unknown
			evs, _ := p.ParseLine(sc.Bytes(), st)
			if st.Unknown != before {
				var head struct {
					Type    string `json:"type"`
					Subtype string `json:"subtype"`
					Payload struct {
						Type string `json:"type"`
					} `json:"payload"`
				}
				json.Unmarshal(sc.Bytes(), &head)
				unknownTypes[p.AgentID()+" "+head.Type+"/"+head.Subtype+"/"+head.Payload.Type]++
			}
			for _, e := range evs {
				n++
				events[e.Type]++
				if e.Tool != nil && e.Type == event.TypeToolPre {
					kinds[string(e.Tool.Kind)]++
				}
				if e.Outcome != nil && e.Type == event.TypeToolPost {
					outcomes[e.Outcome.Status]++
				}
				if _, err := e.MarshalLine(); err != nil {
					t.Fatalf("%s: marshal: %v", c.path, err)
				}
			}
		}
		f.Close()
		lines += int(st.Lines)
		unknown += int(st.Unknown)
		malformed += int(st.Malformed)
		total += n
		t.Logf("%-14s lines=%-6d events=%-6d unknown=%-4d malformed=%-3d pending=%-3d %s",
			p.AgentID(), st.Lines, n, st.Unknown, st.Malformed, len(st.Pending), filepath.Base(c.path))
		if st.Lines >= driftMinLines && (st.Unknown+st.Malformed)*2 > st.Lines {
			t.Errorf("%s: schema drift: unknown=%d malformed=%d of %d lines", c.path, st.Unknown, st.Malformed, st.Lines)
		}
	}
	dump := func(title string, m map[string]int) {
		keys := make([]string, 0, len(m))
		for k := range m {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var sb strings.Builder
		for _, k := range keys {
			fmt.Fprintf(&sb, " %s=%d", k, m[k])
		}
		t.Logf("%s:%s", title, sb.String())
	}
	t.Logf("files=%d lines=%d events=%d unknown=%d malformed=%d", files, lines, total, unknown, malformed)
	dump("events", events)
	dump("tool kinds", kinds)
	dump("outcomes", outcomes)
	dump("unknown record types", unknownTypes)
	if total == 0 {
		t.Errorf("no events from %d files", files)
	}

	// The same files through the Tailer: discovery, safe opens, checkpoints.
	// Live logs may grow between the two passes, so only a floor is checked.
	tl := NewTailer(TailerOptions{
		Roots:       func() []Root { return []Root{{Glob: glob}} },
		StateFile:   filepath.Join(t.TempDir(), "state.json"),
		FromStart:   true,
		MaxBackfill: 100 * 365 * 24 * time.Hour,
	})
	tailed := 0
	for i := 0; i < 1000; i++ {
		evs, probs, err := tl.Poll(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		for _, p := range probs {
			t.Errorf("problem: %s %s (%s)", p.Kind, filepath.Base(p.Path), p.Detail)
		}
		if len(evs) == 0 {
			break
		}
		tailed += len(evs)
	}
	t.Logf("tailer: files=%d events=%d", len(tl.Checkpoints()), tailed)
	if tailed < total {
		t.Errorf("tailer produced %d events, direct parsing %d", tailed, total)
	}
}
