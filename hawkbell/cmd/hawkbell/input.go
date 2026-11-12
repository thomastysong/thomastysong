package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/thomastysong/thomastysong/hawkbell/internal/adapter"
	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/sink"
	"github.com/thomastysong/thomastysong/hawkbell/internal/spool"
)

// Input formats of `hawkbell detect`.
const (
	formatAuto   = "auto"   // per line, as adapter.Detect says
	formatNative = "native" // hawkbell events: outbox, local ring, spool records
	formatNumbat = "numbat" // perplexityai/numbat records
)

// maxInputLine bounds one NDJSON line. adapter.Detect reports anything
// longer as unknown, so nothing longer could be read anyway.
const maxInputLine = adapter.MaxDetectLine

// inputStats is the coverage statement of a detect run: every line that
// was not evaluated is counted under a reason, so "no findings" can be told
// apart from "nothing read".
type inputStats struct {
	Files     int            `json:"files"`
	Lines     int            `json:"lines"`
	Evaluated int            `json:"evaluated"`
	Formats   map[string]int `json:"formats,omitempty"`
	Skipped   map[string]int `json:"skipped,omitempty"`
}

func newInputStats() *inputStats {
	return &inputStats{Formats: map[string]int{}, Skipped: map[string]int{}}
}

// eventReader turns NDJSON streams into events for the engine.
type eventReader struct {
	format string
	stats  *inputStats
}

// spoolRecord mirrors one line of a hook spool (internal/spool's record):
// the event plus the local content detection needs, which the event's own
// JSON never carries. internal/spool does not export a decoder for
// daemonless consumers, so this is the adapter.
type spoolRecord struct {
	V       int          `json:"v"`
	Event   *event.Event `json:"event"`
	Content *struct {
		PromptText  string         `json:"prompt_text"`
		ToolInput   map[string]any `json:"tool_input"`
		ToolOutput  string         `json:"tool_output"`
		FileContent string         `json:"file_content"`
	} `json:"content"`
}

// readPaths reads files, directories (their *.ndjson files, oldest segment
// first) and "-" for stdin.
func (r *eventReader) readPaths(paths []string, stdin io.Reader, emit func(*event.Event)) error {
	if len(paths) == 0 {
		paths = []string{"-"}
	}
	for _, p := range paths {
		if p == "-" {
			r.stats.Files++
			if err := r.readStream(stdin, emit); err != nil {
				return fmt.Errorf("stdin: %w", err)
			}
			continue
		}
		files, err := expandInput(p)
		if err != nil {
			return err
		}
		for _, f := range files {
			if err := r.readFile(f, emit); err != nil {
				return err
			}
		}
	}
	return nil
}

func (r *eventReader) readFile(path string, emit func(*event.Event)) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		// A FIFO would block the run and a device is never an event log.
		return fmt.Errorf("%s: not a regular file", path)
	}
	r.stats.Files++
	if err := r.readStream(f, emit); err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	return nil
}

// expandInput returns path itself, or for a directory its NDJSON files in
// segment order (stream files of one hour together, oldest hour first).
func expandInput(path string) ([]string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return []string{path}, nil
	}
	ents, err := os.ReadDir(path)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, e := range ents {
		if e.Type().IsRegular() && strings.HasSuffix(e.Name(), ".ndjson") {
			names = append(names, e.Name())
		}
	}
	sort.Slice(names, func(i, j int) bool {
		ki, kj := segmentOrder(names[i]), segmentOrder(names[j])
		if ki != kj {
			return ki < kj
		}
		return names[i] < names[j]
	})
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = filepath.Join(path, n)
	}
	return out, nil
}

// segmentOrder sorts <stream>-<YYYYMMDD>-<HH>-<n>.ndjson (outbox and local
// ring) and <stream>-<YYYYMMDD>.ndjson (spool) by time, not by stream.
func segmentOrder(name string) string {
	if _, ok := sink.ParseSegmentName(name); ok {
		if i := strings.IndexByte(name, '-'); i >= 0 {
			return name[i+1:]
		}
	}
	base := strings.TrimSuffix(name, ".ndjson")
	if i := strings.LastIndexByte(base, '-'); i >= 0 {
		return base[i+1:]
	}
	return name
}

// readStream reads lines up to maxInputLine; a longer line is skipped to
// its end and counted, never split into pieces that could parse.
func (r *eventReader) readStream(rd io.Reader, emit func(*event.Event)) error {
	br := bufio.NewReaderSize(rd, 64<<10)
	var line []byte
	oversize := false
	for {
		chunk, err := br.ReadSlice('\n')
		if len(chunk) > 0 && !oversize {
			if len(line)+len(chunk) > maxInputLine+1 {
				oversize, line = true, line[:0]
			} else {
				line = append(line, chunk...)
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if len(line) > 0 || oversize {
			r.stats.Lines++
			if oversize {
				r.stats.Skipped["oversize"]++
			} else {
				r.decode(bytes.TrimSpace(line), emit)
			}
		}
		line, oversize = line[:0], false
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
	}
}

func (r *eventReader) decode(line []byte, emit func(*event.Event)) {
	if len(line) == 0 {
		r.stats.Lines--
		return
	}
	format := r.format
	if format == formatAuto || format == "" {
		switch adapter.Detect(line) {
		case adapter.FormatHawkbell:
			format = formatNative
		case adapter.FormatNumbat:
			format = formatNumbat
		case adapter.FormatOsquery:
			r.stats.Skipped["osquery_result"]++
			return
		default:
			if r.spool(line, emit) {
				return
			}
			r.stats.Skipped["unknown_format"]++
			return
		}
	}
	switch format {
	case formatNumbat:
		evs, err := adapter.Numbat(line)
		if err != nil {
			r.stats.Skipped["numbat:"+numbatReason(err)]++
		}
		// ErrTooLarge comes with a stand-in event, so the action stays
		// visible; other errors come with none.
		for _, e := range evs {
			r.accept(e, "numbat", emit)
		}
	default:
		if r.spool(line, emit) {
			return
		}
		var e event.Event
		if err := json.Unmarshal(line, &e); err != nil || e.Kind == "" {
			r.stats.Skipped["malformed"]++
			return
		}
		r.accept(&e, "hawkbell", emit)
	}
}

// spool decodes a hook spool line ({"v":1,"event":{...},"content":{...}}).
func (r *eventReader) spool(line []byte, emit func(*event.Event)) bool {
	if !bytes.Contains(line, []byte(`"event"`)) {
		return false
	}
	var rec spoolRecord
	if err := json.Unmarshal(line, &rec); err != nil || rec.Event == nil || rec.V != spool.RecordVersion {
		return false
	}
	e := rec.Event
	if e.Kind == event.KindHealth && e.Health != nil && strings.HasPrefix(e.Health.Reason, "hook_") {
		// The hook supervisor's own failure reports: counted, not evaluated.
		r.stats.Skipped["hook_error:"+clip(e.Health.Reason, 40)]++
		return true
	}
	if c := rec.Content; c != nil {
		e.Content = &event.Content{PromptText: c.PromptText, ToolInput: c.ToolInput, ToolOutput: c.ToolOutput, FileContent: c.FileContent}
	}
	r.accept(e, "spool", emit)
	return true
}

// accept passes activity and inventory on to the engine. Records that are
// themselves results (detections, posture, health, summaries, detection
// context) are not re-evaluated: feeding a finding back in would only
// re-emit it.
func (r *eventReader) accept(e *event.Event, format string, emit func(*event.Event)) {
	switch e.Kind {
	case event.KindActivity, event.KindInventory:
		r.stats.Formats[format]++
		r.stats.Evaluated++
		emit(e)
	default:
		r.stats.Skipped["kind:"+clip(string(e.Kind), 20)]++
	}
}

func numbatReason(err error) string {
	switch {
	case errors.Is(err, adapter.ErrTooLarge):
		return "too_large"
	case errors.Is(err, adapter.ErrVersion):
		return "version"
	case errors.Is(err, adapter.ErrUnknownRecord):
		return "unknown_record"
	case errors.Is(err, adapter.ErrNotNumbat):
		return "not_numbat"
	case errors.Is(err, adapter.ErrMalformed):
		return "malformed"
	}
	return "error"
}
