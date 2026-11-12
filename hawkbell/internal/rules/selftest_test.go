package rules

import (
	"strings"
	"testing"
)

func results(t *testing.T, rules string) map[string]TestResult {
	t.Helper()
	out := map[string]TestResult{}
	for _, r := range mustPack(t, rules).RunTests() {
		out[r.RuleID+"/"+r.Name] = r
	}
	return out
}

func TestRunTestsReportsFailures(t *testing.T) {
	res := results(t, `  - id: HB-R-001
    title: sudo
    severity: low
    when: {type: tool.pre}
    match: {shell.sudo: true}
    tests:
      - {name: right, event: {type: tool.pre, tool: {kind: shell}, target: {command: "sudo id"}}, expect: match}
      - {name: wrong, event: {type: tool.pre, tool: {kind: shell}, target: {command: "id"}}, expect: match}
      - {name: typo in event, event: {type: tool.pre, tool: {knd: shell}}, expect: match}
      - {name: bad content key, event: {type: tool.pre, content: {stdout: x}}, expect: no_match}
`)
	if r := res["HB-R-001/right"]; !r.OK || r.Got != "match" || r.Want != "match" {
		t.Errorf("right: %+v", r)
	}
	r := res["HB-R-001/wrong"]
	if r.OK || r.Got != "no_match" || !strings.Contains(r.Detail, "when=true") || !strings.Contains(r.Detail, "match=false") {
		t.Errorf("wrong: %+v", r)
	}
	if r := res["HB-R-001/typo in event"]; r.OK || r.Got != "error" || !strings.Contains(r.Detail, "knd") {
		t.Errorf("typo: %+v", r)
	}
	if r := res["HB-R-001/bad content key"]; r.OK || r.Got != "error" || !strings.Contains(r.Detail, "stdout") {
		t.Errorf("content key: %+v", r)
	}
}

func TestRunTestsInputs(t *testing.T) {
	res := results(t, `  - id: HB-R-010
    title: feat override
    severity: low
    match: {shell.opaque: eval}
    tests:
      - {name: override, event: {type: tool.pre, tool: {kind: shell}, target: {command: "ls"}, feat: {shell.opaque: [eval]}}, expect: match}
      - {name: sibling feat, event: {type: tool.pre, tool: {kind: shell}, target: {command: "ls"}}, feat: {shell.opaque: [eval]}, expect: match}
      - {name: computed, event: {type: tool.pre, tool: {kind: shell}, target: {command: "ls"}}, expect: no_match}
  - id: HB-R-011
    title: content and derived tool kind
    severity: low
    when: {type: tool.post}
    match: {tool.kind: file_read, path.sensitive_read: true, output.untrusted: false}
    tests:
      - name: Read tool by name with input only
        event: {type: tool.post, agent: {id: claude-code}, tool: {name: Read}, content: {tool_input: {file_path: /home/tester/.ssh/id_rsa}, tool_output: "-----BEGIN"}}
        expect: match
  - id: HB-R-012
    title: threshold sequence
    severity: low
    match: {tool.kind: shell}
    threshold: {count: 3, window: 2s}
    tests:
      - name: three in two seconds
        events:
          - {type: tool.pre, tool: {kind: shell}, target: {command: "a"}}
          - {type: tool.pre, tool: {kind: shell}, target: {command: "b"}}
          - {type: tool.pre, tool: {kind: shell}, target: {command: "c"}}
        expect: match
      - name: two only
        events:
          - {type: tool.pre, tool: {kind: shell}, target: {command: "a"}}
          - {type: tool.pre, tool: {kind: shell}, target: {command: "b"}}
        expect: no_match
  - id: HB-R-013
    title: inventory
    kind: inventory
    severity: low
    match: {asset.kind: mcp_server, asset.mcp.pinned: false}
    tests:
      - {name: unpinned, event: {type: inventory.asset, asset: {id: a, kind: mcp_server, name: x, mcp: {pinned: false}}}, expect: match}
      - {name: pinned, event: {type: inventory.asset, asset: {id: a, kind: mcp_server, name: x, mcp: {pinned: true}}}, expect: no_match}
  - id: HB-R-014
    title: windows host
    severity: low
    match: {path.normalization_evasion: true}
    tests:
      - {name: trailing dot, event: {type: tool.pre, host: {os: windows}, tool: {kind: file_write}, target: {path: 'C:\Users\t\p\.claude\settings.json.'}}, expect: match}
      - {name: linux, event: {type: tool.pre, tool: {kind: file_write}, target: {path: '/home/t/p/.claude/settings.json.'}}, expect: no_match}
`)
	for k, r := range res {
		if !r.OK {
			t.Errorf("%s: got %s want %s: %s", k, r.Got, r.Want, r.Detail)
		}
	}
	if len(res) != 10 {
		t.Errorf("ran %d tests", len(res))
	}
}

// A disabled rule is still tested: RunTests validates content, and an
// operator disabling a rule must not hide that it is broken.
func TestRunTestsIncludesDisabled(t *testing.T) {
	s := mustPack(t, goodRule)
	s.Disable("HB-T-001")
	if rs := s.RunTests(); len(rs) != 1 || !rs[0].OK {
		t.Fatalf("%+v", rs)
	}
}
