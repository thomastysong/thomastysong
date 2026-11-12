package hookinstall

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/event"
)

// A duplicate event key inside "hooks" is resolved last-wins by the agent
// (JSON.parse). A user who appends `"PreToolUse": []` after spoor's entry
// switches the gate off, and Status must not keep reporting "user".
func TestReviewDuplicateEventKeyHidesTamper(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeUser, "claude-code")
	plans := mustPlan(t, c, o)
	mustApply(t, plans)
	path := only(t, plans, "claude-code").Path
	data := readBytes(t, path)
	// Find the closing of the "hooks" object: insert a duplicate empty
	// PreToolUse array as its last member.
	d, err := parseJSON(data)
	if err != nil {
		t.Fatal(err)
	}
	_, hooks := d.root.member("hooks")
	tampered := append([]byte{}, data[:hooks.end-1]...)
	tampered = append(tampered, []byte(`, "PreToolUse": [], "UserPromptSubmit": []`)...)
	tampered = append(tampered, data[hooks.end-1:]...)
	if _, err := parseJSON(tampered); err != nil {
		t.Fatal(err)
	}
	writeFile(t, path, tampered, 0o644)
	s := stateOf(t, c, o, "claude-code")
	if s.Status != StatusModified {
		t.Errorf("PreToolUse is overridden by a later duplicate key (the agent runs no spoor PreToolUse hook), but Status = %q (%s)", s.Status, s.Detail)
	}
}

// Claude Code's disableAllHooks in the user's own settings file switches off
// every user hook. Status reads that very file and still reports "user".
func TestReviewDisableAllHooksNotDetected(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeUser, "claude-code")
	plans := mustPlan(t, c, o)
	mustApply(t, plans)
	path := only(t, plans, "claude-code").Path
	data := readBytes(t, path)
	d, _ := parseJSON(data)
	writeFile(t, path, d.addMember(d.root, "disableAllHooks", true), 0o644)
	s := stateOf(t, c, o, "claude-code")
	if s.Status == StatusUser {
		t.Errorf("disableAllHooks:true in the same file turns spoor's hooks off, but Status = %q (%s)", s.Status, s.Detail)
	}
}

// Uninstalling native OTel removes members the user had before install.
func TestReviewOTelUninstallRemovesUsersOwnTelemetrySwitch(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeUser, "claude-code")
	o.OTel = "http://127.0.0.1:4319"
	path := targetPath(t, c, o, "claude-code")
	orig := []byte(`{
  "env": {
    "CLAUDE_CODE_ENABLE_TELEMETRY": "1",
    "OTEL_METRICS_EXPORTER": "otlp",
    "OTEL_EXPORTER_OTLP_METRICS_ENDPOINT": "https://metrics.example.com/v1/metrics"
  }
}
`)
	writeFile(t, path, orig, 0o600)
	plans := mustPlan(t, c, o)
	for _, p := range plans {
		if p.Action == ActionUnsupported {
			t.Fatalf("install refused: %s", p.Note)
		}
	}
	mustApply(t, plans)
	mustApply(t, mustUnplan(t, c, o))
	got := readBytes(t, path)
	if !bytes.Equal(got, orig) {
		t.Errorf("install + uninstall did not restore the user's file; the user's own metrics pipeline loses CLAUDE_CODE_ENABLE_TELEMETRY:\nbefore:\n%s\nafter:\n%s", orig, got)
	}
}

// With Force, comments must survive ("with Force the same splice keeps the
// comments"). An empty container that holds only a comment loses it.
func TestReviewForceDropsCommentInEmptyObject(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeUser, "claude-code")
	o.Force = true
	path := targetPath(t, c, o, "claude-code")
	orig := []byte("{\n  // \"model\": \"opus\"\n}\n")
	writeFile(t, path, orig, 0o644)
	plans := mustPlan(t, c, o)
	p := only(t, plans, "claude-code")
	if p.Action != ActionMerge {
		t.Fatalf("action %s: %s", p.Action, p.Note)
	}
	if !bytes.Contains(p.After, []byte(`// "model": "opus"`)) {
		t.Errorf("Force install destroyed the user's comment:\n%s", p.After)
	}
}

// Same for a comment inside an existing, empty "hooks" object.
func TestReviewForceDropsCommentInEmptyHooks(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeUser, "claude-code")
	o.Force = true
	path := targetPath(t, c, o, "claude-code")
	orig := []byte("{\n  \"hooks\": {\n    /* team hooks go here */\n  },\n  \"model\": \"opus\"\n}\n")
	writeFile(t, path, orig, 0o644)
	p := only(t, mustPlan(t, c, o), "claude-code")
	if p.Action != ActionMerge {
		t.Fatalf("action %s: %s", p.Action, p.Note)
	}
	if !bytes.Contains(p.After, []byte(`team hooks go here`)) {
		t.Errorf("Force install destroyed the user's comment:\n%s", p.After)
	}
}

// Options.Root confines writes and reads of the target; the related files
// (managed settings consulted for coexistence, allowManagedHooksOnly and
// OTel pins) are read through symbolic links that leave the root.
func TestReviewRelatedFilesEscapeRoot(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeUser, "claude-code")
	outside := t.TempDir()
	writeFile(t, filepath.Join(outside, "managed-settings.json"),
		[]byte(`{"allowManagedHooksOnly": true, "hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "/usr/bin/numbat hook pre --agent claude"}]}]}}`), 0o644)
	if err := os.MkdirAll(filepath.Join(o.Root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	// An absolute link inside the host root: inside a container image it
	// points at the container's /..., read from the host it is the host's.
	if err := os.Symlink(outside, filepath.Join(o.Root, "etc", "claude-code")); err != nil {
		t.Fatal(err)
	}
	p := only(t, mustPlan(t, c, o), "claude-code")
	if strings.Contains(p.Note, "numbat") || strings.Contains(p.Note, "allowManagedHooksOnly") {
		t.Errorf("a file outside Options.Root was read through a link below it; plan: %s %s", p.Action, p.Note)
	}
}

// A Binary that is not valid UTF-8 is accepted, but the JSON encoder
// writes U+FFFD in its place: the registered command names a file that
// does not exist.
func TestReviewInvalidUTF8BinaryAccepted(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeUser, "claude-code")
	o.Binary = "/opt/sp\xffor/spoor"
	plans, err := PlanInstall(c, o)
	if err != nil {
		return // refused: fine
	}
	p := only(t, plans, "claude-code")
	if p.Action == ActionCreate && !bytes.Contains(p.After, []byte(o.Binary)) {
		t.Errorf("Binary %q accepted but written as a different path:\n%s", o.Binary, p.After[:200])
	}
}

// A user-controlled settings file with many spoor-marked entries and a
// large foreign value makes planning re-parse the whole file once per entry
// (removeSpoor), so a root installer can be stalled by a 4 MiB file.
func TestReviewPlanTimeOnHostileFile(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeUser, "claude-code")
	path := targetPath(t, c, o, "claude-code")
	var b bytes.Buffer
	b.WriteString(`{"pad": "`)
	b.Write(bytes.Repeat([]byte("a"), 3<<20))
	b.WriteString(`", "hooks": {"Stop": [{"hooks": [`)
	for i := 0; i < 4000; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"command":"x hook --agent y"}`)
	}
	b.WriteString("]}]}}\n")
	writeFile(t, path, b.Bytes(), 0o644)
	start := time.Now()
	plans := mustPlan(t, c, o)
	el := time.Since(start)
	t.Logf("size %d, plan took %v, action %s", b.Len(), el, only(t, plans, "claude-code").Action)
	if el > 10*time.Second {
		t.Errorf("planning one %d-byte file took %v", b.Len(), el)
	}
}
