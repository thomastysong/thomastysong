package engine

import (
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/config"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/rules"
	"github.com/thomastysong/spoor/internal/sink"
)

// countSink counts records without keeping them, so the benchmark measures
// the pipeline rather than the test's memory.
type countSink struct{ n atomic.Int64 }

func (c *countSink) Name() string { return "count" }
func (c *countSink) Write(b []*event.Event) error {
	c.n.Add(int64(len(b)))
	return nil
}
func (c *countSink) Flush() error { return nil }
func (c *countSink) Close() error { return nil }

// benchCommands are ordinary agent shell commands (taken from the kinds of
// calls in the replayed agent sessions: builds, tests, git, search, package
// installs), with an occasional download-and-execute.
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

// benchEvents returns n records starting at call number from: the hook
// pre and post records of each call, and a transcript twin of every other
// call's pre record, as when both surfaces are on.
func benchEvents(from, n int, t0 time.Time) []*event.Event {
	out := make([]*event.Event, 0, n+2)
	for i := from; len(out) < n; i++ {
		cmd := benchCommands[i%len(benchCommands)]
		use := "toolu_" + strconv.Itoa(i)
		sess := "sess-" + strconv.Itoa(i/200)
		ts := at(t0.Add(time.Duration(i) * 50 * time.Millisecond))
		out = append(out, hook(event.TypeToolPre, sess, ts, shell(use, cmd)))
		if i%2 == 0 {
			out = append(out, transcript(event.TypeToolPre, sess, ts, shell(use, cmd)))
		}
		out = append(out, hook(event.TypeToolPost, sess, ts, shell(use, cmd), output("ok\n")))
	}
	return out[:n]
}

// run feeds b.N records in chunks (generated outside the timer, then
// dropped, so the live heap stays what a running daemon holds).
func runChunks(b *testing.B, feed func([]*event.Event)) {
	const chunk = 256
	t0 := newClock().now()
	b.ReportAllocs()
	b.ResetTimer()
	var spent time.Duration
	for done, call := 0, 0; done < b.N; {
		n := min(chunk, b.N-done)
		b.StopTimer()
		evs := benchEvents(call, n, t0)
		call += n / 2
		b.StartTimer()
		start := time.Now()
		feed(evs)
		spent += time.Since(start)
		done += n
	}
	b.ReportMetric(float64(b.N)/spent.Seconds(), "events/s")
}

func benchPipeline(b *testing.B, mode string, out sink.Sink) (*Pipeline, *fakeClock) {
	set, err := rules.LoadEmbedded()
	if err != nil {
		b.Fatal(err)
	}
	clk := newClock()
	cfg := config.Default(b.TempDir())
	p, err := New(Options{
		Config: cfg, Rules: set, Outbox: out, Local: &countSink{},
		Host: event.Host{ID: "host-1", OS: "linux"}, Mode: mode, Integrity: event.IntegrityRoot,
		Now: clk.now, Disabled: func() bool { return false },
		HomeOf: func(uid, name string) string { return testHome },
	})
	if err != nil {
		b.Fatal(err)
	}
	return p, clk
}

// BenchmarkIngest measures end-to-end throughput (normalize, correlate,
// features, default rule set, privacy, write) on realistic shell events.
func BenchmarkIngest(b *testing.B) {
	b.Run("detect-sync", func(b *testing.B) {
		p, _ := benchPipeline(b, ModeDetect, &countSink{})
		defer p.Close()
		runChunks(b, func(evs []*event.Event) { p.Ingest(evs...) })
	})
	b.Run("daemon-queue", func(b *testing.B) {
		p, clk := benchPipeline(b, ModeDaemon, &countSink{})
		defer p.Close()
		runChunks(b, func(evs []*event.Event) {
			p.Ingest(evs...)
			clk.add(12 * time.Second)
			p.Tick(clk.now())
		})
	})
	b.Run("daemon-files-standard", func(b *testing.B) {
		files, err := sink.NewFiles(sink.FilesOptions{Dir: b.TempDir(), MaxLineBytes: 16 << 10})
		if err != nil {
			b.Fatal(err)
		}
		p, clk := benchPipeline(b, ModeDaemon, files)
		p.pol.Profile = "standard"
		defer p.Close()
		runChunks(b, func(evs []*event.Event) {
			p.Ingest(evs...)
			clk.add(12 * time.Second)
			p.Tick(clk.now())
		})
	})
}
