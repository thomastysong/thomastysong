package hookinstall

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
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
	if p := only(t, mustPlan(t, c, o), "claude-code"); p.Action == ActionUnchanged {
		t.Errorf("reinstall does not repair it either: Action = %q", p.Action)
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

// allocDuring reports how many bytes f allocated.
func allocDuring(f func()) uint64 {
	var a, b runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&a)
	f()
	runtime.ReadMemStats(&b)
	return b.TotalAlloc - a.TotalAlloc
}

// A user-controlled settings file with many spoor-marked entries and a
// large foreign value makes planning re-parse the whole file once per entry
// (removeSpoor), so a root installer can be stalled by one 4 MiB file
// (a 3.2 MB file took 88 s, a 0.65 MB one 28 s and 16 GiB of
// allocations). Here a 76 KB file with 2000 marked entries is enough to
// allocate gigabytes.
func TestReviewPlanTimeOnHostileFile(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeUser, "claude-code")
	path := targetPath(t, c, o, "claude-code")
	var b bytes.Buffer
	b.WriteString(`{"pad": "`)
	b.Write(bytes.Repeat([]byte("a"), 16<<10))
	b.WriteString(`", "hooks": {"Stop": [{"hooks": [`)
	for i := 0; i < 2000; i++ {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"command":"x hook --agent y"}`)
	}
	b.WriteString("]}]}}\n")
	writeFile(t, path, b.Bytes(), 0o644)
	start := time.Now()
	var action string
	alloc := allocDuring(func() { action = only(t, mustPlan(t, c, o), "claude-code").Action })
	t.Logf("size %d, plan took %v, allocated %d MiB, action %s", b.Len(), time.Since(start), alloc>>20, action)
	if alloc > 256<<20 {
		t.Errorf("planning one %d-byte file allocated %d MiB (one full re-parse per spoor entry)", b.Len(), alloc>>20)
	}
}

// The TOML decoder is quadratic in time and memory on nested inline
// tables, and nothing bounds the nesting before parseTOML hands a file to
// it. ~/.codex/config.toml belongs to the user and is parsed by
// PlanInstall, PlanUninstall, Status (related files) and Apply
// (checkContent). A 48 KB file reached 5.9 GB RSS and 19 s; a 400 KB file
// gets the process OOM-killed, which recover() cannot catch.
func TestReviewHostileCodexConfigTOMLExhaustsMemory(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeUser, "codex")
	path := targetPath(t, c, o, "codex")
	const n = 6000 // a 24 KB file
	cfg := []byte("a = " + strings.Repeat("{b=", n) + "1" + strings.Repeat("}", n) + "\n")
	writeFile(t, filepath.Join(filepath.Dir(path), "config.toml"), cfg, 0o644)
	start := time.Now()
	alloc := allocDuring(func() { _, _ = PlanInstall(c, o) })
	t.Logf("config.toml %d bytes: PlanInstall took %v and allocated %d MiB", len(cfg), time.Since(start), alloc>>20)
	if alloc > 256<<20 {
		t.Errorf("a %d-byte user-owned config.toml made PlanInstall allocate %d MiB (unbounded TOML nesting)", len(cfg), alloc>>20)
	}
}

// Codex requirements may pin [otel] (research: requirements keys include
// otel). Addendum 2: OTel is refused when the managed config already pins
// a telemetry endpoint. For the user scope planCodexOTel only looks at
// requirements.toml beside the USER config.toml, never at the system one.
func TestReviewCodexUserOTelIgnoresManagedRequirementsPin(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeUser, "codex")
	o.OTel = "http://127.0.0.1:4319"
	req := filepath.Join(o.Root, "etc", "codex", "requirements.toml")
	writeFile(t, req, []byte("[otel]\nexporter = { otlp-http = { endpoint = \"https://siem.example.com/v1/logs\", protocol = \"json\" } }\n"), 0o644)
	for _, p := range mustPlan(t, c, o) {
		if strings.HasSuffix(p.Path, "config.toml") && p.Action != ActionUnsupported {
			t.Errorf("managed requirements.toml pins [otel], but the user-scope OTel plan is %q for %s:\n%s", p.Action, p.Path, p.After)
		}
	}
}

// Windows writes a NULL DACL (everyone full control) as
// "D:NO_ACCESS_CONTROL". splitSDDL treats any DACL text without "(" as an
// empty (deny-all) DACL, so the most open descriptor passes as safe.
func TestReviewSDDLNullDACLPassesAsSafe(t *testing.T) {
	for _, s := range []string{"O:BAD:NO_ACCESS_CONTROL", "O:SYG:SYD:NO_ACCESS_CONTROL"} {
		if got := sddlProblem(s); got == "" {
			t.Errorf("sddlProblem(%q) = \"\": a NULL DACL grants everyone full control", s)
		}
	}
}

// Claude Code: "Only disableAllHooks set at the managed settings level can
// disable managed hooks." relatedFiles already reads every managed file
// (for allowManagedHooksOnly) but Status ignores disableAllHooks there and
// reports the drop-in as managed although Claude Code runs none of it.
func TestReviewManagedDisableAllHooksNotShadowed(t *testing.T) {
	c := testCatalog(t)
	o := opts(t, "linux", event.ScopeManaged, "claude-code")
	path := targetPath(t, c, o, "claude-code")
	mustApply(t, mustPlan(t, c, o))
	writeFile(t, filepath.Join(filepath.Dir(filepath.Dir(path)), "managed-settings.json"), []byte(`{"disableAllHooks": true}`+"\n"), 0o644)
	s := stateOf(t, c, o, "claude-code")
	if s.Status == StatusManaged {
		t.Errorf("managed-settings.json sets disableAllHooks:true (unloads managed hooks too), but Status = %q (%s)", s.Status, s.Detail)
	}
}
