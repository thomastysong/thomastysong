package sink

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
)

// countingWriter records each Write call separately.
type countingWriter struct {
	writes [][]byte
	err    error
}

func (w *countingWriter) Write(p []byte) (int, error) {
	if w.err != nil {
		return 0, w.err
	}
	w.writes = append(w.writes, append([]byte(nil), p...))
	return len(p), nil
}

func TestStdout(t *testing.T) {
	w := &countingWriter{}
	s := NewStdout(w, "")
	if s.Name() != "stdout" {
		t.Errorf("Name = %q", s.Name())
	}
	e := testEvent("a", 10)
	e.Target.Command = "line1\nline2\r\n "
	if err := s.Write([]*event.Event{e, nil, testEvent("b", 3)}); err != nil {
		t.Fatal(err)
	}
	if len(w.writes) != 2 {
		t.Fatalf("want one Write call per event, got %d", len(w.writes))
	}
	for _, line := range w.writes {
		if bytes.Count(line, []byte("\n")) != 1 || line[len(line)-1] != '\n' || bytes.ContainsRune(line, '\r') {
			t.Errorf("not one clean line: %q", line)
		}
		var got event.Event
		if err := json.Unmarshal(line, &got); err != nil {
			t.Fatal(err)
		}
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	o := &countingWriter{}
	if err := NewStdout(o, FormatOCSF).Write([]*event.Event{kindEvent(event.KindDetection, "d")}); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(o.writes[0], []byte(`"class_uid":2004`)) {
		t.Errorf("ocsf line: %s", o.writes[0])
	}

	if err := NewStdout(w, "xml").Write([]*event.Event{e}); err == nil || !strings.Contains(err.Error(), "unknown format") {
		t.Errorf("unknown format: %v", err)
	}
	if err := NewStdout(nil, "").Write([]*event.Event{e}); err == nil {
		t.Error("nil writer must be an error, not a panic")
	}
	boom := errors.New("pipe closed")
	if err := NewStdout(&countingWriter{err: boom}, "").Write([]*event.Event{e}); !errors.Is(err, boom) {
		t.Errorf("write error not reported: %v", err)
	}

	// Flush reaches a buffered writer.
	var buf bytes.Buffer
	bw := bufio.NewWriter(&buf)
	bs := NewStdout(bw, "")
	bs.Write([]*event.Event{e})
	if buf.Len() != 0 {
		t.Fatal("test assumption: bufio holds the line")
	}
	if err := bs.Flush(); err != nil || buf.Len() == 0 {
		t.Errorf("Flush did not reach the writer: %v", err)
	}
}
