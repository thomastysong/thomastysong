package privacy

import (
	"strconv"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
)

// benchCommands are ordinary agent shell commands (the engine benchmark's
// corpus: builds, tests, git, search, package installs, an occasional
// download-and-execute).
var benchCommands = []string{
	"git status",
	"go test ./internal/engine/... -run TestScenarios -count=1",
	"ls -la /home/dev/proj/internal",
	"grep -rn \"func New\" --include=*.go internal | head -50",
	"cat /home/dev/proj/go.mod",
	"npm install --save-dev typescript@5.6.3",
	"git diff --stat HEAD~1 && git log --oneline -5",
	"cd /home/dev/proj && go build ./... 2>&1 | tail -20",
	"python3 -c 'import json,sys; print(json.load(open(\"package.json\"))[\"version\"])'",
	"docker build -t app:dev . && docker run --rm app:dev --help",
	"rm -rf build/ dist/ && mkdir -p build",
	"curl -s https://api.github.com/repos/golang/go/releases | jq '.[0].tag_name'",
	"sed -i 's/v1.2.3/v1.2.4/' VERSION && git add VERSION",
	"find . -name '*.tmp' -mtime +7 -delete",
	"kubectl get pods -n default -o wide",
	"curl -fsSL https://get.example.dev/install.sh | sh",
}

// benchShell is a hook record of a shell call, shaped like the engine's.
func benchShell(src event.Source, typ, use, cmd string) *event.Event {
	e := event.New(event.KindActivity, typ, src)
	e.Host = &event.Host{ID: "host-1", Name: "ws-17", OS: "linux", Arch: "amd64"}
	e.User = &event.User{Name: "dev", ID: "1000"}
	e.Agent = &event.Agent{ID: "claude-code", Version: "2.1.0"}
	e.Session = &event.Session{ID: "sess-1", CWD: "/home/dev/proj"}
	e.Tool = &event.Tool{Name: "Bash", Kind: event.ToolShell, UseID: use}
	e.Target = &event.Target{Command: cmd}
	e.Content = &event.Content{ToolInput: map[string]any{"command": cmd}}
	if typ == event.TypeToolPost {
		e.Content.ToolOutput = "ok\n"
	}
	return e
}

// benchCall returns the records of call i: the hook pre and post records
// and, for every other call, the transcript twin of the pre record, as the
// engine sees them when both surfaces are on. unique makes every call's
// command distinct, so nothing repeats across calls.
func benchCall(i int, unique bool) []*event.Event {
	cmd := benchCommands[i%len(benchCommands)]
	if unique {
		cmd = uniqueCmd(cmd, i)
	}
	use := "toolu_" + strconv.Itoa(i)
	out := []*event.Event{benchShell(event.SourceHook, event.TypeToolPre, use, cmd)}
	if i%2 == 0 {
		out = append(out, benchShell(event.SourceTranscript, event.TypeToolPre, use, cmd))
	}
	return append(out, benchShell(event.SourceHook, event.TypeToolPost, use, cmd))
}

// uniqueCmd makes a command distinct the way agents' commands differ: the
// working directory they cd into first.
func uniqueCmd(cmd string, i int) string {
	return "cd /home/dev/proj/w" + strconv.Itoa(i) + " && " + cmd
}

// benchPool is the number of records a BenchmarkEmitShell mode cycles
// through.
const benchPool = 4096

// benchStream is the record stream of one BenchmarkEmitShell mode.
type benchStream struct {
	mode string
	pass int
	evs  []*event.Event
}

func newBenchStream(mode string) *benchStream {
	s := &benchStream{mode: mode}
	s.fill(0)
	return s
}

// fill builds the pool for one pass over it. In unique mode every pass
// has calls of its own (the working directory numbers go on), so a
// command recurs only within its call however many passes b.N needs; the
// pool alone would fit the memo and turn every later pass into repeats.
func (s *benchStream) fill(pass int) {
	s.pass = pass
	var evs []*event.Event
	for i := 0; len(evs) < benchPool; i++ {
		evs = append(evs, benchCall(pass*benchPool+i, s.mode != "repeat")...)
	}
	evs = evs[:benchPool]
	if s.mode == "cold" {
		for i, e := range evs {
			c := uniqueCmd(benchCommands[i%len(benchCommands)], i)
			e.Target.Command = c
			e.Content.ToolInput["command"] = c
		}
	}
	s.evs = evs
}

// stale reports that record i belongs to a pass the pool does not hold.
func (s *benchStream) stale(i int) bool { return s.mode == "unique" && i/benchPool != s.pass }

func (s *benchStream) at(i int) *event.Event { return s.evs[i%benchPool] }

// BenchmarkEmitShell measures Emit per record on realistic shell records.
//
//	repeat  the engine benchmark's stream: 16 commands cycling, each call
//	        written as pre, post and (every other call) transcript twin.
//	unique  the same stream with every call's command made distinct, so
//	        only the twins of one call share a command text: the pool is
//	        rebuilt with new calls for every pass, outside the timer.
//	cold    every record's command distinct and the memo cleared before
//	        each record: the cost when nothing can be reused.
func BenchmarkEmitShell(b *testing.B) {
	for _, prof := range []Profile{ProfileStandard, ProfileFull} {
		p := &Policy{Profile: prof, Key: testKey, KeyID: "k1"}
		for _, mode := range []string{"repeat", "unique", "cold"} {
			b.Run(string(prof)+"/"+mode, func(b *testing.B) {
				resetCommandMemo()
				s := newBenchStream(mode)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if s.stale(i) {
						b.StopTimer()
						s.fill(i / benchPool)
						b.StartTimer()
					}
					if mode == "cold" {
						resetCommandMemo()
					}
					if _, _, ok := p.Emit(s.at(i)); !ok {
						b.Fatal("dropped")
					}
				}
				_, _, hits, misses := commandMemo.stats()
				if hits+misses > 0 {
					b.ReportMetric(100*float64(hits)/float64(hits+misses), "%memo-hits")
				}
			})
		}
	}
}

// TestBenchStreamModes: the benchmark modes measure what they say over
// any number of iterations: in unique mode only the twins of one call hit
// the memo (at most two hits per miss), in repeat mode nearly everything
// does, and in cold mode nothing does.
func TestBenchStreamModes(t *testing.T) {
	defer resetCommandMemo()
	p := &Policy{Profile: ProfileStandard, Key: testKey, KeyID: "k1"}
	const n = 3*benchPool + 500 // several passes, like b.N at ~50us/op
	for _, mode := range []string{"repeat", "unique", "cold"} {
		resetCommandMemo()
		s := newBenchStream(mode)
		var hits, misses uint64
		for i := 0; i < n; i++ {
			if s.stale(i) {
				s.fill(i / benchPool)
			}
			if mode == "cold" {
				_, _, h, m := commandMemo.stats()
				hits, misses = hits+h, misses+m
				resetCommandMemo()
			}
			if _, _, ok := p.Emit(s.at(i)); !ok {
				t.Fatal("dropped")
			}
		}
		_, _, h, m := commandMemo.stats()
		hits, misses = hits+h, misses+m
		rate := float64(hits) / float64(hits+misses)
		t.Logf("%s: %d hits, %d misses over %d records (%.0f%% hits)", mode, hits, misses, n, 100*rate)
		switch mode {
		case "unique":
			if hits > 2*misses || hits == 0 {
				t.Errorf("unique mode: %d hits, %d misses; only twins should share", hits, misses)
			}
		case "repeat":
			if rate < 0.95 {
				t.Errorf("repeat mode: only %.0f%% hits", 100*rate)
			}
		case "cold":
			if hits != 0 {
				t.Errorf("cold mode: %d hits", hits)
			}
		}
	}
}

// BenchmarkRedactCommand is the structural redactor alone, uncached.
func BenchmarkRedactCommand(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		redactCommandUncached(benchCommands[i%len(benchCommands)], "")
	}
}
