package sink_test

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/thomastysong/thomastysong/hawkbell/internal/config"
	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/sink"
)

// longestLine writes one event with a 1 MiB command and returns the length
// of the line written, newline included.
func longestLine(t *testing.T, maxLine int) int {
	t.Helper()
	dir := t.TempDir()
	s, err := sink.NewFiles(sink.FilesOptions{Dir: dir, MaxLineBytes: maxLine})
	if err != nil {
		t.Fatal(err)
	}
	e := event.New(event.KindActivity, "x", event.SourceSensor)
	e.Type = event.TypeToolPre
	e.Target = &event.Target{Command: strings.Repeat("a", 1<<20)}
	if err := s.Write([]*event.Event{e}); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	m, _ := filepath.Glob(filepath.Join(dir, "activity-*.ndjson"))
	if len(m) != 1 {
		t.Fatalf("segments: %v", m)
	}
	f, err := os.Open(m[0])
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1<<20), 2<<20)
	longest := 0
	for sc.Scan() {
		longest = max(longest, len(sc.Bytes())+1)
	}
	return longest
}

// The zero value's line cap is the operator default, output.max_line_bytes.
func TestFilesDefaultLineCapIsOperatorDefault(t *testing.T) {
	want := config.Default(t.TempDir()).Output.MaxLine
	if got := longestLine(t, 0); got > want {
		t.Errorf("default cap wrote a %d-byte line; output.max_line_bytes defaults to %d", got, want)
	}
	// The same record under the largest accepted cap is longer: the default,
	// not the record, limited it.
	if got := longestLine(t, 64<<10); got <= want {
		t.Errorf("a 64 KiB cap wrote only %d bytes", got)
	}
}
