package transcript

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// Checkpoint is how far a file has been read.
type Checkpoint struct {
	Offset int64  `json:"offset"`
	Size   int64  `json:"size"`
	FileID string `json:"file_id"` // inode/dev on POSIX, file index on Windows
	MTime  int64  `json:"mtime"`   // Unix nanoseconds
}

// storeVersion is the checkpoint file schema version.
const storeVersion = 1

// maxStoreBytes bounds the checkpoint file that load will read.
const maxStoreBytes = 256 << 20

type storeFile struct {
	Version int                    `json:"version"`
	Files   map[string]*savedEntry `json:"files"`
}

// savedEntry is one file's persisted record: its checkpoint plus the parser
// state needed to keep going after a restart without re-reading the file.
// Prompts, tool inputs and tool outputs are never written here: a pending
// call is reduced to its name and classification.
type savedEntry struct {
	Checkpoint
	Format   string `json:"format"`
	Tail     string `json:"tail,omitempty"`
	Skipping bool   `json:"skipping,omitempty"`
	More     bool   `json:"more,omitempty"`
	Drift    bool   `json:"drift,omitempty"`
	LastSeen int64  `json:"last_seen,omitempty"` // Unix seconds
	// LastRead is when new bytes were last consumed, Unix seconds.
	LastRead int64       `json:"last_read,omitempty"`
	State    *savedState `json:"state,omitempty"`
}

type savedState struct {
	SessionID       string                  `json:"session_id,omitempty"`
	ParentSessionID string                  `json:"parent_session_id,omitempty"`
	CWD             string                  `json:"cwd,omitempty"`
	Model           string                  `json:"model,omitempty"`
	Version         string                  `json:"version,omitempty"`
	PermissionMode  string                  `json:"permission_mode,omitempty"`
	Unknown         uint64                  `json:"unknown,omitempty"`
	Malformed       uint64                  `json:"malformed,omitempty"`
	Lines           uint64                  `json:"lines,omitempty"`
	Oversize        uint64                  `json:"oversize,omitempty"`
	LastTS          int64                   `json:"last_ts,omitempty"` // Unix milliseconds
	Extra           map[string]string       `json:"extra,omitempty"`
	Pending         map[string]savedPending `json:"pending,omitempty"`
	Seen            []string                `json:"seen,omitempty"`
}

type savedPending struct {
	Name       string         `json:"name,omitempty"`
	Kind       event.ToolKind `json:"kind,omitempty"`
	MCPServer  string         `json:"mcp_server,omitempty"`
	MCPTool    string         `json:"mcp_tool,omitempty"`
	InputHash  string         `json:"input_sha256,omitempty"`
	SubagentID string         `json:"subagent_id,omitempty"`
	TurnID     string         `json:"turn_id,omitempty"`
	TS         int64          `json:"ts,omitempty"` // Unix milliseconds
}

func saveState(st *FileState) *savedState {
	if st == nil {
		return nil
	}
	s := &savedState{
		SessionID: st.SessionID, ParentSessionID: st.ParentSessionID, CWD: st.CWD,
		Model: st.Model, Version: st.Version, PermissionMode: st.PermissionMode,
		Unknown: st.Unknown, Malformed: st.Malformed, Lines: st.Lines, Oversize: st.Oversize,
	}
	if !st.lastTS.IsZero() {
		s.LastTS = st.lastTS.UnixMilli()
	}
	if len(st.Extra) > 0 {
		s.Extra = make(map[string]string, len(st.Extra))
		for k, v := range st.Extra {
			s.Extra[k] = v
		}
	}
	if len(st.Pending) > 0 {
		s.Pending = make(map[string]savedPending, len(st.Pending))
		for id, e := range st.Pending {
			if e == nil {
				continue
			}
			p := savedPending{}
			if e.Tool != nil {
				p.Name, p.Kind, p.MCPServer, p.MCPTool, p.InputHash = e.Tool.Name, e.Tool.Kind, e.Tool.MCPServer, e.Tool.MCPTool, e.Tool.InputSHA256
			}
			if e.Session != nil {
				p.SubagentID, p.TurnID = e.Session.SubagentID, e.Session.TurnID
			}
			if !e.TS.IsZero() {
				p.TS = e.TS.UnixMilli()
			}
			s.Pending[id] = p
		}
	}
	if len(st.seenRing) > 0 {
		s.Seen = append([]string(nil), st.seenRing...)
	}
	return s
}

func loadState(s *savedState, path string) *FileState {
	st := &FileState{Path: path}
	if s == nil {
		return st
	}
	st.SessionID, st.ParentSessionID, st.CWD = s.SessionID, s.ParentSessionID, s.CWD
	st.Model, st.Version, st.PermissionMode = s.Model, s.Version, s.PermissionMode
	st.Unknown, st.Malformed, st.Lines, st.Oversize = s.Unknown, s.Malformed, s.Lines, s.Oversize
	if s.LastTS > 0 {
		st.lastTS = time.UnixMilli(s.LastTS).UTC()
	}
	for k, v := range s.Extra {
		st.setExtra(k, v)
	}
	n := 0
	for id, p := range s.Pending {
		if n >= maxPending {
			break
		}
		n++
		e := &event.Event{
			V: event.SchemaVersion, Kind: event.KindActivity, Type: event.TypeToolPre,
			Source: event.SourceTranscript, Fidelity: event.FidelityObserved,
			Tool:    &event.Tool{Name: p.Name, Kind: p.Kind, UseID: id, MCPServer: p.MCPServer, MCPTool: p.MCPTool, InputSHA256: p.InputHash},
			Session: &event.Session{ID: s.SessionID, SubagentID: p.SubagentID, TurnID: p.TurnID, Transcript: path},
		}
		if p.TS > 0 {
			e.TS = event.At(time.UnixMilli(p.TS))
		}
		st.addPending(id, e)
	}
	for i, k := range s.Seen {
		if i >= maxSeen {
			break
		}
		st.remember(k)
	}
	return st
}

// readStore loads the checkpoint file. A missing file is an empty store.
func readStore(path string) (*storeFile, error) {
	sf := &storeFile{Version: storeVersion, Files: map[string]*savedEntry{}}
	if path == "" {
		return sf, nil
	}
	f, err := os.Open(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return sf, nil
		}
		return sf, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxStoreBytes+1))
	if err != nil {
		return sf, err
	}
	if len(b) > maxStoreBytes {
		return sf, fmt.Errorf("checkpoint store exceeds %d bytes", maxStoreBytes)
	}
	var in storeFile
	if err := json.Unmarshal(b, &in); err != nil {
		return sf, fmt.Errorf("checkpoint store is not valid JSON: %w", err)
	}
	if in.Version != storeVersion {
		return sf, fmt.Errorf("checkpoint store has version %d, want %d", in.Version, storeVersion)
	}
	for p, e := range in.Files {
		if e != nil && p != "" {
			sf.Files[p] = e
		}
	}
	return sf, nil
}

// writeStore replaces the checkpoint file atomically: a temporary file in
// the same directory, synced, then renamed over the old one, so a crash
// leaves either the previous checkpoints or the new ones, never a torn mix.
func writeStore(path string, sf *storeFile) error {
	if path == "" {
		return nil
	}
	b, err := json.Marshal(sf)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	fail := func(err error) error {
		tmp.Close()
		os.Remove(name)
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		os.Remove(name)
		return err
	}
	if runtime.GOOS != "windows" {
		// Make the rename itself durable. Windows has no directory sync.
		if d, err := os.Open(dir); err == nil {
			_ = d.Sync()
			d.Close()
		}
	}
	return nil
}
