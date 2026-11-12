// Package spool is the hand-off between the hook entrypoint and the daemon.
//
// A hook process runs as the monitored user, once per agent event, and must
// finish in milliseconds. It appends one record per event to a per-user
// spool directory and exits. The root daemon polls those directories,
// re-derives identity from the file owner and re-runs detection itself.
//
// The spool is user-writable by construction, so the reader treats every
// line as a claim, never as evidence (red-team findings E1, PP-4, F4):
//
//   - only activity records are accepted; a line claiming to be a
//     detection, health, inventory or posture record is counted and dropped,
//     so a user cannot bury or forge findings;
//   - user, host, integrity and writer are overwritten from the file owner
//     and the local host; a user cannot attribute activity to someone else;
//   - files are opened without following symlinks, non-blocking, and checked
//     on the open descriptor to be regular files owned by the expected uid,
//     so a planted link or FIFO can neither exfiltrate a root-only file nor
//     stall the reader;
//   - a per-uid token bucket bounds what one user can push per poll.
//
// Each line is one write(2) on a file opened with O_APPEND, made under an
// exclusive lock that also guards the per-stream sequence counter, so
// concurrent hook processes never interleave and sequence numbers are
// gapless in file order.
package spool

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/platform"
)

// EnvSpool overrides the spool directory (containers, CI, tests).
const EnvSpool = "HAWKBELL_SPOOL"

// Limits.
const (
	// MinFree is the free space below which Append refuses to write: a hook
	// must never be the thing that fills a developer's disk.
	MinFree = 64 << 20
	// MaxRecord caps one spool line. Content fields are cut first.
	MaxRecord = 1 << 20
	// MaxState caps one guard-mode session state file.
	MaxState = 64 << 10
	// RecordVersion is the spool line format version.
	RecordVersion = 1
)

// Errors.
var (
	ErrNoSpace = errors.New("spool: less than 64 MiB free; record dropped")
	ErrUnsafe  = errors.New("spool: directory is not private to the caller")
)

// record is one spool line. The event is the normalized record; content is
// the local-only material detection needs, which the event's own JSON never
// carries.
type record struct {
	V       int           `json:"v"`
	Event   *event.Event  `json:"event"`
	Content *contentLines `json:"content,omitempty"`
}

type contentLines struct {
	PromptText  string         `json:"prompt_text,omitempty"`
	ToolInput   map[string]any `json:"tool_input,omitempty"`
	ToolOutput  string         `json:"tool_output,omitempty"`
	FileContent string         `json:"file_content,omitempty"`
}

// Dir resolves where a hook process running as uid may append, in order:
// $HAWKBELL_SPOOL; <dataDir>/spool/<uid>/ when it exists, is owned by the
// caller and is private (0700); else the caller's own state directory. It
// never returns a shared, world-writable directory.
func Dir(dataDir, uid, home string) (string, error) {
	if d := os.Getenv(EnvSpool); d != "" {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return "", err
		}
		return d, checkPrivate(d, uid)
	}
	if dataDir != "" && uid != "" {
		sys := filepath.Join(dataDir, "spool", uid)
		if checkPrivate(sys, uid) == nil {
			return sys, nil
		}
	}
	d := platform.UserDirs(home).Spool
	if d == "" {
		return "", errors.New("spool: no user directory")
	}
	if err := os.MkdirAll(d, 0o700); err != nil {
		return "", err
	}
	return d, checkPrivate(d, uid)
}

// Writer appends records for one user.
type Writer struct {
	dir string
	uid string
	now func() time.Time
}

// OpenWriter prepares dir for appending. The directory must already be
// private to the caller (see Dir).
func OpenWriter(dir string) (*Writer, error) {
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, fmt.Errorf("spool: %s is not a directory", dir)
	}
	return &Writer{dir: dir, uid: currentUID(), now: time.Now}, nil
}

// WriterID is the Event.Writer value hook records carry.
func (w *Writer) WriterID() string { return "hook-" + w.uid }

// Append writes e (and its local content) as one line of the stream's file.
// It stamps Writer and Seq.
func (w *Writer) Append(e *event.Event) error {
	if e == nil {
		return nil
	}
	if free, ok := freeBytes(w.dir); ok && free < MinFree {
		return ErrNoSpace
	}
	stream := e.Kind.Stream()
	rec := record{V: RecordVersion, Event: e}
	if c := e.Content; c != nil {
		rec.Content = &contentLines{PromptText: c.PromptText, ToolInput: c.ToolInput, ToolOutput: c.ToolOutput, FileContent: c.FileContent}
	}
	unlock, err := lockDir(w.dir)
	if err != nil {
		return err
	}
	defer unlock()
	seq, err := w.nextSeq(stream)
	if err != nil {
		return err
	}
	e.Writer = w.WriterID()
	e.Seq = seq
	line, err := encodeCapped(&rec)
	if err != nil {
		return err
	}
	name := filepath.Join(w.dir, stream+"-"+w.now().UTC().Format("20060102")+".ndjson")
	f, err := openAppend(name)
	if err != nil {
		return err
	}
	_, werr := f.Write(line)
	cerr := f.Close()
	if werr != nil {
		return werr
	}
	return cerr
}

// encodeCapped marshals rec, cutting content until the line fits MaxRecord.
func encodeCapped(rec *record) ([]byte, error) {
	b, err := json.Marshal(rec)
	if err != nil {
		return nil, err
	}
	if len(b) < MaxRecord {
		return append(b, '\n'), nil
	}
	c := rec.Content
	steps := []func(){
		func() { c.ToolOutput = headTail(c.ToolOutput, 32<<10) },
		func() { c.FileContent = headTail(c.FileContent, 64<<10) },
		func() { c.PromptText = headTail(c.PromptText, 32<<10) },
		func() { c.ToolInput = map[string]any{"_truncated": true} },
		func() { rec.Content = nil },
	}
	for _, step := range steps {
		if c == nil {
			break
		}
		step()
		rec.Event.Truncated = appendUniq(rec.Event.Truncated, "content")
		if b, err = json.Marshal(rec); err != nil {
			return nil, err
		}
		if len(b) < MaxRecord {
			return append(b, '\n'), nil
		}
	}
	if len(b) >= MaxRecord {
		return nil, fmt.Errorf("spool: record of %d bytes exceeds %d even without content", len(b), MaxRecord)
	}
	return append(b, '\n'), nil
}

func headTail(s string, n int) string {
	if len(s) <= 2*n {
		return s
	}
	return s[:n] + "\n…[cut]…\n" + s[len(s)-n:]
}

func appendUniq(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// nextSeq increments the stream's counter. Called with the directory lock
// held, so the counter and the line it numbers are written in one critical
// section.
func (w *Writer) nextSeq(stream string) (uint64, error) {
	p := filepath.Join(w.dir, ".seq-"+stream)
	var n uint64
	if f, err := platform.OpenNoFollow(p); err == nil {
		b, _ := io.ReadAll(io.LimitReader(f, 32))
		f.Close()
		n, _ = strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	} else if !errors.Is(err, os.ErrNotExist) {
		return 0, err
	}
	n++
	if err := writeFileAtomic(p, []byte(strconv.FormatUint(n, 10)), 0o600); err != nil {
		return 0, err
	}
	return n, nil
}

// stateName is the file a session's guard state lives in. Session ids come
// from hook stdin and are attacker-controlled, so they are hashed, never
// used as a path component.
func stateName(agentID, sessionID string) string {
	sum := sha256.Sum256([]byte(agentID + "\x00" + sessionID))
	return hex.EncodeToString(sum[:])[:32] + ".json"
}

// LoadState returns the guard-mode state saved for a session.
func (w *Writer) LoadState(agentID, sessionID string) ([]byte, bool) {
	p := filepath.Join(w.dir, "state", stateName(agentID, sessionID))
	f, err := platform.OpenNoFollow(p)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, MaxState+1))
	if err != nil || len(b) > MaxState {
		return nil, false
	}
	return b, true
}

// SaveState stores the guard-mode state for a session.
func (w *Writer) SaveState(agentID, sessionID string, b []byte) error {
	if len(b) > MaxState {
		return fmt.Errorf("spool: state of %d bytes exceeds %d", len(b), MaxState)
	}
	d := filepath.Join(w.dir, "state")
	if err := os.MkdirAll(d, 0o700); err != nil {
		return err
	}
	return writeFileAtomic(filepath.Join(d, stateName(agentID, sessionID)), b, 0o600)
}

// writeFileAtomic writes via a temporary file and rename, refusing to
// replace anything that is not a regular file.
func writeFileAtomic(path string, b []byte, mode os.FileMode) error {
	if fi, err := os.Lstat(path); err == nil && !fi.Mode().IsRegular() {
		return fmt.Errorf("spool: %s is not a regular file", path)
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	_ = os.Chmod(name, mode)
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	return nil
}
