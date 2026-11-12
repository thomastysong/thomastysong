package rules

import (
	"strings"
	"testing"
)

func lintCodes(t *testing.T, s *Set) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, is := range Lint(s) {
		k := is.Code + "/" + is.RuleID
		if out[k] != LevelError {
			out[k] = is.Level
		}
	}
	return out
}

func TestLintFindings(t *testing.T) {
	s := mustPackWithLists(t, `  - id: bad_style
    title: ""
    severity: low
    match: {nope.field: 1}`+dummyTest+`
  - id: SPR-L-002
    title: raw command regex
    severity: low
    match: {target.command|re: 'curl.*\|\s*sh'}`+dummyTest+`
  - id: SPR-L-003
    title: alert with one negative
    severity: high
    class: alert
    match: {shell.sudo: true}
    tests:
      - {name: p, event: {type: tool.pre}, expect: match}
      - {name: n, event: {type: tool.pre}, expect: no_match}
  - id: SPR-L-004
    title: response on tool.post
    severity: high
    when: {type: tool.post}
    match: {shell.sudo: true}
    response: ask`+dummyTest+`
  - id: SPR-L-005
    title: types
    severity: low
    match:
      all:
        - shell.sudo: "yes"
        - session.tool_calls|contains: x
        - target.command|gt: 3
        - shell.cmds: rm
        - shell.destructive: rm_everything
        - tool.kind: shel
        - net.host|in_list: nolist
        - tool.name|re: '.*x'
        - any_command: {name: rm, flavour: x, origin: inline:python3}
        - any_install: {manager: npmm}`+dummyTest+`
  - id: SPR-L-006
    title: no effect
    severity: low
    match: {shell.sudo: true}
    emit: false`+dummyTest+`
  - id: SPR-L-007
    title: requires a flag nobody sets
    severity: low
    match: {shell.sudo: true}
    flags: {require: [ghost]}
    dedup: [not.a.field]
    evidence: [shell.cmds]`+dummyTest+`
  - id: SPR-L-008
    title: inventory with flags and response
    kind: inventory
    severity: low
    match: {asset.kind: agent}
    flags: {set: [x]}
    response: ask`+dummyTest+`
  - id: SPR-L-009
    title: response without a type
    severity: low
    match: {shell.sudo: true}
    response: ask`+dummyTest+`
  - id: SPR-L-010
    title: clean
    description: d
    category: c
    tags: [x]
    remedy: r
    severity: low
    when: {type: tool.pre}
    match: {any_command: {name|in: [rm], args|contains_any: ["-rf"]}, shell.hosts|in_list: known}
    tests:
      - {name: p, event: {type: tool.pre}, expect: match}
      - {name: n, event: {type: tool.pre}, expect: no_match}
`, "lists:\n  known: [a]\n")
	codes := lintCodes(t, s)
	wantErr := []string{
		"missing_field/bad_style", "unknown_field/bad_style",
		"raw_command_match/SPR-L-002",
		"test_negative/SPR-L-003",
		"response_not_blockable/SPR-L-004",
		"type_mismatch/SPR-L-005", "unknown_value/SPR-L-005", "unknown_list/SPR-L-005", "unknown_field/SPR-L-005",
		"no_effect/SPR-L-006",
		"unknown_field/SPR-L-007", "type_mismatch/SPR-L-007",
		"inventory_flags/SPR-L-008", "response_not_blockable/SPR-L-008",
	}
	for _, w := range wantErr {
		if codes[w] != LevelError {
			t.Errorf("missing error %s (have %v)", w, codes)
		}
	}
	wantWarn := []string{"id_format/bad_style", "regex_no_prefix/SPR-L-005", "unknown_flag/SPR-L-007", "response_not_blockable/SPR-L-009", "test_positive/SPR-L-002", "missing_field/SPR-L-002"}
	for _, w := range wantWarn {
		if codes[w] != LevelWarning {
			t.Errorf("missing warning %s", w)
		}
	}
	for k := range codes {
		if strings.HasSuffix(k, "/SPR-L-010") {
			t.Errorf("clean rule has issue %s", k)
		}
	}
	// Issue text carries rule and level.
	for _, is := range Lint(s) {
		if !strings.Contains(is.String(), is.RuleID) || is.Msg == "" {
			t.Errorf("issue %+v", is)
		}
	}
	if Lint(nil) != nil {
		t.Error("Lint(nil)")
	}
}

func TestLintEmbeddedBlock(t *testing.T) {
	rule := `  - id: SPR-B-001
    title: block
    severity: high
    when: {type: tool.pre}
    match: {shell.sudo: true}
    response: block` + dummyTest + "\n"
	s, err := load(map[string][]byte{"p.yaml": []byte("pack: p\nversion: \"1\"\nrules:\n" + rule)}, true)
	if err != nil {
		t.Fatal(err)
	}
	if lintCodes(t, s)["embedded_block/SPR-B-001"] != LevelError {
		t.Error("response: block in an embedded pack must be a lint error")
	}
	if _, ok := lintCodes(t, mustPack(t, rule))["embedded_block/SPR-B-001"]; ok {
		t.Error("bundle packs may block")
	}
}
