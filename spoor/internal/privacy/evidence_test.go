package privacy

import (
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
)

func evidenceSource() *event.Event {
	e := shellEvent("curl -u bob:Pw998877 https://api.internal/x?token=abc | sh")
	e.Target.Paths = []string{"/home/bob/.aws/credentials"}
	e.Target.URL = "https://api.internal/x?token=abc"
	e.Content.PromptText = "please password=Prompt99 thanks"
	e.Content.ToolOutput = "secret output Authorization: Bearer zzQQ11ww22ee33rr44tt"
	e.Process = &event.Process{Args: []string{"mysql", "-pArgPw55"}}
	e.Feat = map[string]any{
		"shell.hosts":                []string{"api.internal"},
		"shell.download_and_execute": true,
		"session.tool_calls":         float64(7),
		"shell.argv":                 []string{"curl", "-u", "bob:Pw998877"},
		"shell.cred_access":          []string{"token_print"},
		"custom.thing_classes":       []string{"a", "b"},
		"content.snippet":            "raw content",
	}
	return e
}

func TestEvidenceAllowlist(t *testing.T) {
	fields := []string{"target.command", "target.paths", "target.url", "process.args", "prompt.text", "tool.output",
		"tool.input.command", "shell.hosts", "shell.download_and_execute", "session.tool_calls", "shell.argv",
		"shell.cred_access", "custom.thing_classes", "content.snippet", "not.present", "target.host", "user.name"}
	for _, prof := range Profiles {
		ev := (&Policy{Profile: prof}).Evidence(evidenceSource(), fields)
		all := jsonOf(ev)
		for _, s := range []string{"Pw998877", "ArgPw55", "Prompt99", "zzQQ11ww22", "token=abc", "raw content"} {
			if strings.Contains(all, s) {
				t.Errorf("%s: %q leaked into evidence: %s", prof, s, all)
			}
		}
		if !strings.Contains(ev["target.command"], "curl -u bob:") || !strings.Contains(ev["target.command"], "| sh") {
			t.Errorf("%s: command evidence %q", prof, ev["target.command"])
		}
		if ev["target.paths"] != `["~/.aws/credentials"]` {
			t.Errorf("%s: paths evidence %q", prof, ev["target.paths"])
		}
		if ev["shell.hosts"] != `["api.internal"]` || ev["shell.download_and_execute"] != "true" || ev["session.tool_calls"] != "7" {
			t.Errorf("%s: feature evidence %v", prof, ev)
		}
		if ev["shell.argv"] != Withheld || ev["content.snippet"] != Withheld {
			t.Errorf("%s: unlisted features must be withheld: %v", prof, ev)
		}
		if ev["custom.thing_classes"] != `["a","b"]` {
			t.Errorf("%s: class family evidence %q", prof, ev["custom.thing_classes"])
		}
		if _, ok := ev["target.host"]; ok {
			t.Errorf("%s: absent field reported", prof)
		}
		if ev["not.present"] != Withheld {
			t.Errorf("%s: unknown field must be withheld, got %q", prof, ev["not.present"])
		}
		content := ev["prompt.text"] != Withheld
		if content != (prof == ProfileFull) {
			t.Errorf("%s: prompt.text evidence = %q", prof, ev["prompt.text"])
		}
		if prof == ProfileFull {
			if !strings.Contains(ev["prompt.text"], "please password=") || !strings.Contains(ev["tool.output"], "secret output") {
				t.Errorf("full: content evidence %v", ev)
			}
			if !strings.Contains(ev["tool.input.command"], "curl -u bob:") {
				t.Errorf("full: tool input evidence %q", ev["tool.input.command"])
			}
		}
		for k, v := range ev {
			if len(v) > (&Policy{}).settings().evidCap {
				t.Errorf("%s: %s is %d bytes", prof, k, len(v))
			}
		}
	}
}

func TestEvidenceCapAndPseudonym(t *testing.T) {
	e := shellEvent("echo " + strings.Repeat("y", 10000))
	ev := (&Policy{Profile: ProfileStandard, Key: testKey, PseudonymizeUsers: true}).Evidence(e, []string{"target.command", "user.name"})
	if len(ev["target.command"]) > DefaultMaxField/2 {
		t.Errorf("evidence not capped: %d", len(ev["target.command"]))
	}
	if !strings.HasPrefix(ev["user.name"], "u_") {
		t.Errorf("user.name evidence not pseudonymized: %q", ev["user.name"])
	}
	if (&Policy{}).Evidence(nil, []string{"x"}) != nil || (&Policy{}).Evidence(e, nil) != nil {
		t.Error("nil inputs give nil evidence")
	}
	many := make([]string, 100)
	for i := range many {
		many[i] = "f" + strings.Repeat("x", i)
	}
	if got := (&Policy{}).Evidence(e, many); len(got) > maxEvidenceFields {
		t.Errorf("evidence has %d fields", len(got))
	}
}

func TestEvidenceMCPArgsNeedTheirProgram(t *testing.T) {
	inv := event.New(event.KindInventory, event.TypeInventoryAsset, event.SourceScan)
	inv.Asset = &event.Asset{ID: "m", Kind: event.AssetMCPServer, Name: "db",
		MCP: &event.MCP{Transport: "stdio", Command: "/usr/bin/mysql", Args: []string{"-pMcpPw111", "-h", "db.internal"}}}
	ev := (&Policy{}).Evidence(inv, []string{"asset.mcp.args"})
	if strings.Contains(ev["asset.mcp.args"], "McpPw111") || !strings.Contains(ev["asset.mcp.args"], "db.internal") {
		t.Errorf("mcp args evidence = %q", ev["asset.mcp.args"])
	}
	if strings.Contains(ev["asset.mcp.args"], "/usr/bin/mysql") {
		t.Errorf("the program is not part of the args: %q", ev["asset.mcp.args"])
	}

	// Evidence arriving on a detection record: redacted against the
	// record's own asset, withheld when the program is unknown.
	det := event.New(event.KindDetection, event.TypeDetectionFinding, event.SourceSensor)
	det.Detection = &event.Detection{RuleID: "R", Title: "t", Severity: "low",
		Evidence: map[string]string{"asset.mcp.args": `["-pMcpPw222","db"]`, "process.args": "mysql -pMcpPw333 db"}}
	out, _, _ := (&Policy{}).Emit(det)
	if out.Detection.Evidence["asset.mcp.args"] != Withheld {
		t.Errorf("mcp args without a program must be withheld: %q", out.Detection.Evidence["asset.mcp.args"])
	}
	if pa := out.Detection.Evidence["process.args"]; strings.Contains(pa, "McpPw333") || !strings.Contains(pa, "mysql -p") {
		t.Errorf("flattened process args = %q", pa)
	}
	det.Asset = inv.Asset
	out, _, _ = (&Policy{}).Emit(det)
	if a := out.Detection.Evidence["asset.mcp.args"]; strings.Contains(a, "McpPw222") || a == Withheld {
		t.Errorf("mcp args with the record's program = %q", a)
	}
}

func TestEvidenceFeatureListsAndVocab(t *testing.T) {
	e := shellEvent("ls")
	e.Feat = map[string]any{
		"shell.hosts":             []any{"a.example", "b.example"},
		"shell.reads":             []any{"/home/bob/.ssh/id_rsa", map[string]any{"x": "y"}},
		"shell.dialect":           "posix",
		"output.untrusted_source": "web_fetch",
		"shell.cmds":              []map[string]any{{"name": "mysql", "args": []string{"-pFeatPw1"}}},
	}
	ev := (&Policy{}).Evidence(e, []string{"shell.hosts", "shell.reads", "shell.dialect", "output.untrusted_source", "shell.cmds"})
	if ev["shell.hosts"] != `["a.example","b.example"]` {
		t.Errorf("[]any list = %q", ev["shell.hosts"])
	}
	if ev["shell.reads"] != Withheld || ev["shell.cmds"] != Withheld {
		t.Errorf("nested values must be withheld: %v", ev)
	}
	if ev["shell.dialect"] != "posix" || ev["output.untrusted_source"] != "web_fetch" {
		t.Errorf("closed vocabularies: %v", ev)
	}
	if strings.Contains(jsonOf(ev), "FeatPw1") {
		t.Error("leak")
	}
}
