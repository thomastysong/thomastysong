package privacy

import (
	"strings"
	"testing"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

func TestEmitRouting(t *testing.T) {
	kinds := []event.Kind{event.KindActivity, event.KindDetection, event.KindInventory, event.KindPosture, event.KindHealth, event.KindSummary, "future_kind"}
	want := map[Profile]map[event.Kind]bool{
		ProfileMinimal:  {event.KindActivity: false, event.KindDetection: true, event.KindInventory: true, event.KindPosture: true, event.KindHealth: true, event.KindSummary: true, "future_kind": false},
		ProfileStandard: {event.KindActivity: true, event.KindDetection: true, event.KindInventory: true, event.KindPosture: true, event.KindHealth: true, event.KindSummary: true, "future_kind": true},
		ProfileFull:     {event.KindActivity: true, event.KindDetection: true, event.KindInventory: true, event.KindPosture: true, event.KindHealth: true, event.KindSummary: true, "future_kind": true},
	}
	for prof, m := range want {
		for _, k := range kinds {
			e := event.New(k, "x", event.SourceSensor)
			out, ship, ok := (&Policy{Profile: prof}).Emit(e)
			if !ok || out == nil {
				t.Fatalf("%s %s: not ok", prof, k)
			}
			if ship != m[k] {
				t.Errorf("%s %s: ship = %v, want %v", prof, k, ship, m[k])
			}
			if out.Privacy != string(prof) {
				t.Errorf("privacy = %q, want %q", out.Privacy, prof)
			}
		}
	}
	if _, _, ok := (&Policy{}).Emit(nil); ok {
		t.Error("nil must be dropped")
	}
	var nilPolicy *Policy
	if out, ship, ok := nilPolicy.Emit(shellEvent("ls")); !ok || ship || out.Privacy != "minimal" {
		t.Error("a nil policy is the minimal profile")
	}
}

func TestEmitFieldPolicyByProfile(t *testing.T) {
	e := shellEvent("mysql -pSecretPw1 -h db prod")
	e.Target.URL = "https://u:pw@api.internal/v1?token=t0kval&page=2#frag"
	e.Target.Query = "how do I rotate the prod db password"
	e.Prompt = &event.Prompt{Len: 40, Text: "raw prompt text that should not ship", SHA256: sha256Hex("x")}
	e.Content.PromptText = "raw prompt text that should not ship"
	e.Content.ToolOutput = "col1\nrow with output content\n"
	e.Tool.Output = "row with output content"
	e.Tool.Input = map[string]any{"command": "mysql -pSecretPw1 -h db prod"}
	e.Outcome = &event.Outcome{Status: "error", Error: strings.Repeat("e", 1000)}

	std, _, _ := (&Policy{Profile: ProfileStandard}).Emit(e)
	ls := line(t, std)
	for _, bad := range []string{"SecretPw1", "raw prompt", "output content", "rotate the prod", "token=", "#frag", "u:pw", ".jsonl"} {
		if strings.Contains(ls, bad) {
			t.Errorf("standard shipped %q:\n%s", bad, ls)
		}
	}
	if std.Tool.Input != nil || std.Tool.Output != "" || std.Prompt.Text != "" || std.Target.Query != "" || std.Session.Transcript != "" {
		t.Errorf("standard kept content: %+v %+v", std.Tool, std.Prompt)
	}
	if std.Target.URL != "https://api.internal/v1" {
		t.Errorf("standard url = %q", std.Target.URL)
	}
	if len(std.Outcome.Error) > maxErrStd {
		t.Errorf("standard error not capped: %d", len(std.Outcome.Error))
	}
	if std.Tool.InputKeys[0] != "command" {
		t.Errorf("input keys = %v", std.Tool.InputKeys)
	}

	full, _, _ := (&Policy{Profile: ProfileFull}).Emit(e)
	lf := line(t, full)
	if strings.Contains(lf, "SecretPw1") || strings.Contains(lf, "u:pw") || strings.Contains(lf, "t0kval") {
		t.Errorf("full leaked:\n%s", lf)
	}
	if full.Prompt.Text == "" || full.Tool.Output == "" || full.Tool.Input == nil || full.Target.Query == "" {
		t.Errorf("full dropped content: %+v %+v %+v", full.Prompt, full.Tool, full.Target)
	}
	if !strings.Contains(full.Target.URL, "page=2") {
		t.Errorf("full keeps the query (redacted): %q", full.Target.URL)
	}
	if full.Session.Transcript != "" {
		t.Error("transcript path must be dropped in every profile")
	}

	min, ship, _ := (&Policy{}).Emit(e)
	if ship {
		t.Error("minimal must not ship activity")
	}
	if strings.Contains(line(t, min), "SecretPw1") || min.Prompt.Text != "" {
		t.Error("minimal ring copy must use the standard field policy")
	}
}

func TestEmitLossy(t *testing.T) {
	e := shellEvent("echo caf\xe9 \xff")
	e.Agent.Version = "1.0\xfe"
	e.Labels = map[string]string{"k\xff": "v\xfe"}
	out, _, _ := (&Policy{Profile: ProfileStandard}).Emit(e)
	if out.Labels["lossy"] != "true" {
		t.Errorf("lossy label missing: %v", out.Labels)
	}
	l := line(t, out)
	if strings.Contains(l, "\\ufffd") == false && !strings.Contains(l, "\uFFFD") {
		t.Errorf("replacement character expected:\n%s", l)
	}
	clean, _, _ := (&Policy{Profile: ProfileStandard}).Emit(shellEvent("echo ok"))
	if _, ok := clean.Labels["lossy"]; ok {
		t.Error("valid UTF-8 must not be marked lossy")
	}
}

func TestEmitDoesNotShareMutableState(t *testing.T) {
	e := shellEvent("ls")
	e.Labels = map[string]string{"a": "b"}
	out, _, _ := (&Policy{Profile: ProfileStandard}).Emit(e)
	out.Labels["a"] = "changed"
	out.Session.ID = "changed"
	if e.Labels["a"] != "b" || e.Session.ID != "sess-1" {
		t.Error("output shares state with the input")
	}
	if out.Content != nil || out.Feat != nil {
		t.Error("content and features must not travel with the output")
	}
}

func TestEmitDetectionEvidenceAllowlist(t *testing.T) {
	e := event.New(event.KindDetection, event.TypeDetectionFinding, event.SourceSensor)
	e.Detection = &event.Detection{RuleID: "R", Title: "t", Severity: "high", Evidence: map[string]string{
		"target.command":     "curl -u a:Pw123456 https://x",
		"prompt.text":        "my prompt",
		"tool.output":        "out",
		"made.up.field":      "content",
		"session.tool_calls": "12",
		"shell.hosts":        `["x.example","y.example"]`,
	}}
	out, _, _ := (&Policy{Profile: ProfileStandard}).Emit(e)
	ev := out.Detection.Evidence
	if ev["prompt.text"] != Withheld || ev["tool.output"] != Withheld || ev["made.up.field"] != Withheld {
		t.Errorf("content evidence not withheld: %v", ev)
	}
	if strings.Contains(ev["target.command"], "Pw123456") {
		t.Errorf("evidence command not redacted: %v", ev)
	}
	if ev["session.tool_calls"] != "12" || !strings.Contains(ev["shell.hosts"], "x.example") {
		t.Errorf("allowed evidence lost: %v", ev)
	}
}

// TestEmitConcurrent: the engine shares one Policy across goroutines.
func TestEmitConcurrent(t *testing.T) {
	p := &Policy{Profile: ProfileStandard, Key: testKey, KeyID: "k1", PseudonymizeUsers: true}
	corpus := canaryCorpus()
	done := make(chan struct{})
	for g := 0; g < 8; g++ {
		go func(g int) {
			defer func() { done <- struct{}{} }()
			for i := g; i < len(corpus); i += 8 {
				out, _, ok := p.Emit(corpus[i].build())
				if !ok || out == nil {
					t.Errorf("%s dropped", corpus[i].name)
					continue
				}
				if b, _ := out.MarshalLine(); strings.Contains(string(b), "Canary") {
					t.Errorf("%s leaked under concurrency", corpus[i].name)
				}
				p.ContextFor("d", []*event.Event{corpus[i].build()}, 1)
			}
		}(g)
	}
	for g := 0; g < 8; g++ {
		<-done
	}
}

// TestEmitKeyIDWhenFingerprintsAreKeyed: a record whose only keyed content
// is a rewritten secret marker still names the key that made it.
func TestEmitKeyIDWhenFingerprintsAreKeyed(t *testing.T) {
	e := shellEvent("mysql -pKeyedPw1 db")
	e.Content = nil
	out, _, _ := (&Policy{Profile: ProfileStandard, Key: testKey, KeyID: "tenant-7"}).Emit(e)
	if !strings.Contains(out.Target.Command, ":hmac=") || out.Labels["key_id"] != "tenant-7" {
		t.Errorf("command %q labels %v", out.Target.Command, out.Labels)
	}
	out, _, _ = (&Policy{Profile: ProfileStandard, KeyID: "tenant-7"}).Emit(e)
	if strings.Contains(out.Target.Command, "hmac=") || out.Labels["key_id"] != "" {
		t.Errorf("no key: command %q labels %v", out.Target.Command, out.Labels)
	}
}

// TestTruncatedNamesRedacted (review P7): names in the input record's
// truncated list, and names this package builds from tool-input keys, are
// written after the safety pass, so they get its treatment.
func TestTruncatedNamesRedacted(t *testing.T) {
	tok := "ghp_" + rnd(7, 36)
	e := shellEvent("ls")
	e.Truncated = []string{tok, "target.command", "/home/bob/secret-dir/x"}
	for _, prof := range Profiles {
		for _, key := range [][]byte{nil, testKey} {
			out, _, _ := (&Policy{Profile: prof, Key: key}).Emit(e)
			l := line(t, out)
			if strings.Contains(l, tok) || unkeyedMarkerRe.MatchString(l) {
				t.Errorf("%s key=%v: truncated list: %q", prof, key != nil, out.Truncated)
			}
			if !strings.Contains(l, `"target.command"`) || !strings.Contains(l, `~/secret-dir/x`) {
				t.Errorf("%s: truncated names lost or not home-relative: %q", prof, out.Truncated)
			}
		}
	}
	// A cut tool-input value is named by its key, which the agent chose.
	in := activity(event.TypeToolPre)
	in.Tool = &event.Tool{Name: "T", Kind: event.ToolMCP}
	in.Content = &event.Content{ToolInput: map[string]any{tok: strings.Repeat("v", 10000)}}
	out, _, _ := (&Policy{Profile: ProfileFull, Key: testKey}).Emit(in)
	if l := line(t, out); strings.Contains(l, tok) || len(out.Truncated) == 0 {
		t.Errorf("tool-input key in truncated names: %q", out.Truncated)
	}
	seen := map[string]bool{}
	for _, n := range out.Truncated {
		if seen[n] {
			t.Errorf("duplicate truncated name %q", n)
		}
		seen[n] = true
	}
}

// TestNoNestedMarkersInValues (review P9): a database URL in a structured
// value (label, check result) comes out as one marker, not a marker
// inside a marker.
func TestNoNestedMarkersInValues(t *testing.T) {
	v := "postgres://app:Sommer2026x@db/x"
	for _, k := range [][]byte{nil, testKey} {
		e := shellEvent("ls")
		e.Labels = map[string]string{"db": v}
		e.Check = &event.Check{ID: "c", Status: "fail", Actual: v}
		out, _, _ := (&Policy{Profile: ProfileStandard, Key: k}).Emit(e)
		l := line(t, out)
		if nestedMarkerRe.MatchString(l) || strings.Contains(l, "Sommer2026x") || unkeyedMarkerRe.MatchString(l) {
			t.Errorf("key=%v: label=%q actual=%q", k != nil, out.Labels["db"], out.Check.Actual)
		}
		if !strings.HasPrefix(out.Labels["db"], "postgres://") {
			t.Errorf("key=%v: scheme lost: %q", k != nil, out.Labels["db"])
		}
	}
}
