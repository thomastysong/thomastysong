package sink

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

func benchEvent() *event.Event {
	e := testEvent("019a7a00-0000-7000-8000-000000000001", 120)
	e.Session = &event.Session{ID: "3f6c1f0e-1111-4222-8333-444455556666", CWD: "/home/alice/src/app", Model: "claude-sonnet-4-5"}
	e.User = &event.User{Name: "alice", ID: "1000"}
	e.Tool.Input = map[string]any{"command": e.Target.Command, "timeout": 120000, "description": "run the tests"}
	return e
}

// BenchmarkFilesWrite is the cost of the durable path per event: encode,
// fstat, one write(2).
func BenchmarkFilesWrite(b *testing.B) {
	for _, f := range []string{FormatNative, FormatOCSF} {
		b.Run(f, func(b *testing.B) {
			s, err := NewFiles(FilesOptions{Dir: b.TempDir(), Format: f, RetainBytes: -1})
			if err != nil {
				b.Fatal(err)
			}
			defer s.Close()
			batch := []*event.Event{benchEvent()}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := s.Write(batch); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkFilesOpenAndWrite is what a hook process pays: a fresh sink that
// lists a directory already holding a week of segments, writes one event
// and closes.
func BenchmarkFilesOpenAndWrite(b *testing.B) {
	dir := b.TempDir()
	now := time.Now()
	for h := 0; h < 7*24; h++ {
		for _, stream := range event.Streams {
			name := SegmentName(stream, now.Add(-time.Duration(h)*time.Hour), 1)
			if err := os.WriteFile(filepath.Join(dir, name), []byte("{}\n"), 0o640); err != nil {
				b.Fatal(err)
			}
		}
	}
	batch := []*event.Event{benchEvent()}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s, err := NewFiles(FilesOptions{Dir: dir, RetainBytes: -1, RetainAge: -1})
		if err != nil {
			b.Fatal(err)
		}
		if err := s.Write(batch); err != nil {
			b.Fatal(err)
		}
		s.Close()
	}
}

func BenchmarkForwardPackEntry(b *testing.B) {
	e := benchEvent()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := packEntry(e); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkParseLine(b *testing.B) {
	line, _ := benchEvent().MarshalLine()
	line = line[:len(line)-1]
	b.SetBytes(int64(len(line)))
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if parseLine(line) == nil {
			b.Fatal("rejected")
		}
	}
}

func BenchmarkFitLineOversize(b *testing.B) {
	e := benchEvent()
	e.Tool.Output = string(make([]byte, 1<<20))
	e.Target.Command = fmt.Sprintf("%0200000d", 1)
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := fitLine(e, FormatNative, defaultMaxLineBytes); err != nil {
			b.Fatal(err)
		}
	}
}
