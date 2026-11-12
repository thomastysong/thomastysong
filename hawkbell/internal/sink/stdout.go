package sink

import (
	"fmt"
	"io"
	"sync"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// stdoutSink writes one line per event to a writer it does not own.
type stdoutSink struct {
	mu     sync.Mutex
	w      io.Writer
	format string
	err    error // invalid format, reported on every Write
}

// NewStdout returns a sink that writes one NDJSON line per event to w, in
// the native or ocsf format. It is meant for containers, where the runtime
// collects stdout, and for piping into jq.
//
// Each event is written with a single Write call so lines stay whole when w
// is a pipe shared with other writers. Flush calls w.Flush or w.Sync when w
// has one. Close flushes but does not close w, which the caller owns. An
// unknown format is reported by Write, since this constructor has no error
// result.
func NewStdout(w io.Writer, format string) Sink {
	f, err := checkFormat(format)
	return &stdoutSink{w: w, format: f, err: err}
}

func (s *stdoutSink) Name() string { return "stdout" }

func (s *stdoutSink) Write(batch []*event.Event) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("sink stdout: %v", r)
		}
	}()
	if s.err != nil {
		return s.err
	}
	if s.w == nil {
		return fmt.Errorf("sink stdout: nil writer")
	}
	var first error
	for _, e := range batch {
		if e == nil {
			continue
		}
		line, werr := encodeLine(e, s.format)
		if werr == nil {
			_, werr = s.w.Write(line)
		}
		if werr != nil && first == nil {
			first = werr
		}
	}
	if first != nil {
		return fmt.Errorf("sink stdout: %w", first)
	}
	return nil
}

func (s *stdoutSink) Flush() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch w := s.w.(type) {
	case interface{ Flush() error }:
		return w.Flush()
	case interface{ Sync() error }:
		// Sync fails on pipes and terminals (EINVAL); that is not a lost
		// write, so it is not reported.
		_ = w.Sync()
	}
	return nil
}

func (s *stdoutSink) Close() error { return s.Flush() }
