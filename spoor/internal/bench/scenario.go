package bench

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Caps on scenario files. A corpus can arrive with a rules bundle or a
// pull request, so it is parsed like any other untrusted document.
const (
	maxScenarioFile   = 1 << 20 // bytes per file
	maxScenarioFiles  = 512
	maxScenarios      = 500 // per file
	maxScenarioEvents = 64  // per scenario or variant
	maxVariants       = 16
	maxYAMLDepth      = 48
	maxYAMLNodes      = 200000
)

// Scenario outcomes and kinds.
const (
	KindAttack = "attack"
	KindBenign = "benign"

	OutcomeAttempted = "attempted"
	OutcomeSucceeded = "succeeded"
)

// Scenario is one named sequence of events with its expectation.
type Scenario struct {
	Name        string
	File        string
	Kind        string // attack | benign (benign = expect_none)
	Incident    int    // row of research/threats.md section 2; 0 when none
	Technique   string // framework id in tag style: attack.t1105, atlas.aml.t0081
	Outcome     string // attempted | succeeded (attacks only)
	Description string
	Expect      []string // rule ids expected to fire (attacks)
	ExpectNone  bool     // no finding or alert may fire (benign look-alikes)
	// Mutations names the operators applied to the attack's shell commands
	// ("all" by default, "none" to opt out); see Operators.
	Mutations []string
	Variants  []Variant
	Events    []EventSpec
}

// Variant is a hand-written mutation: the same attack expressed through a
// different event sequence (another tool, another path spelling).
type Variant struct {
	Name   string
	Events []EventSpec
}

// EventSpec is one partial event as written in a scenario: the JSON shape
// of internal/event plus optional content and feat blocks (exactly what
// inline rule tests accept) and the surfaces that could observe it.
type EventSpec struct {
	node     *yaml.Node
	Surfaces []string
}

type rawScenarioFile struct {
	Suite     string        `yaml:"suite"`
	Scenarios []rawScenario `yaml:"scenarios"`
}

type rawScenario struct {
	Name        string       `yaml:"name"`
	Incident    int          `yaml:"incident"`
	Technique   string       `yaml:"technique"`
	Outcome     string       `yaml:"outcome"`
	Description string       `yaml:"description"`
	Expect      []string     `yaml:"expect"`
	ExpectNone  bool         `yaml:"expect_none"`
	Mutations   []string     `yaml:"mutations"`
	Variants    []rawVariant `yaml:"variants"`
	Events      []yaml.Node  `yaml:"events"`
}

type rawVariant struct {
	Name   string      `yaml:"name"`
	Events []yaml.Node `yaml:"events"`
}

var (
	nameRe      = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,95}$`)
	techniqueRe = regexp.MustCompile(`^(attack\.t[0-9]{4}(\.[0-9]{3})?|atlas\.aml\.t[0-9]{4}(\.[0-9]{3})?|owasp\.(asi|mcp)[0-9]{2})$`)
	ruleRefRe   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
)

// Surfaces an event can be observed on.
const (
	SurfaceHook       = "hook"
	SurfaceTranscript = "transcript"
	SurfaceProcess    = "process"
	SurfaceScan       = "scan"
)

var knownSurfaces = map[string]bool{SurfaceHook: true, SurfaceTranscript: true, SurfaceProcess: true, SurfaceScan: true}

// LoadScenarios reads every *.yaml file directly in dir (no recursion, no
// symbolic links, regular files only) in name order.
func LoadScenarios(dir string) ([]Scenario, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("bench: scenarios: %w", err)
	}
	var names []string
	for _, e := range entries {
		n := e.Name()
		if strings.HasPrefix(n, ".") || !strings.HasSuffix(n, ".yaml") {
			continue
		}
		if e.Type()&fs.ModeType != 0 {
			return nil, fmt.Errorf("bench: scenarios: %s is not a regular file", n)
		}
		names = append(names, n)
	}
	if len(names) > maxScenarioFiles {
		return nil, fmt.Errorf("bench: scenarios: more than %d files", maxScenarioFiles)
	}
	sort.Strings(names)
	var out []Scenario
	seen := map[string]string{}
	for _, n := range names {
		data, err := readCapped(filepath.Join(dir, n), maxScenarioFile)
		if err != nil {
			return nil, err
		}
		sc, err := ParseScenarios(n, data)
		if err != nil {
			return nil, err
		}
		for _, s := range sc {
			if prev, dup := seen[s.Name]; dup {
				return nil, fmt.Errorf("bench: scenario %q in %s already defined in %s", s.Name, n, prev)
			}
			seen[s.Name] = n
		}
		out = append(out, sc...)
	}
	return out, nil
}

// readCapped reads a regular file without following a symbolic link at
// its final component and refuses anything over max bytes.
func readCapped(path string, max int64) ([]byte, error) {
	fi, err := os.Lstat(path)
	if err != nil {
		return nil, fmt.Errorf("bench: %w", err)
	}
	if !fi.Mode().IsRegular() {
		return nil, fmt.Errorf("bench: %s is not a regular file", path)
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("bench: %w", err)
	}
	defer f.Close()
	if st, err := f.Stat(); err != nil || !os.SameFile(fi, st) {
		return nil, fmt.Errorf("bench: %s changed while it was opened", path)
	}
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, fmt.Errorf("bench: %s: %w", path, err)
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("bench: %s is larger than %d bytes", path, max)
	}
	return b, nil
}

// ParseScenarios parses one scenario file. name labels errors and
// Scenario.File.
func ParseScenarios(name string, data []byte) (out []Scenario, err error) {
	defer func() {
		if r := recover(); r != nil {
			out, err = nil, fmt.Errorf("bench: %s: internal error parsing scenarios: %v", name, r)
		}
	}()
	if len(data) > maxScenarioFile {
		return nil, fmt.Errorf("bench: %s is larger than %d bytes", name, maxScenarioFile)
	}
	root, err := parseOne(data)
	if err != nil {
		return nil, fmt.Errorf("bench: %s: %w", name, err)
	}
	var raw rawScenarioFile
	if err := decodeKnown(root, &raw); err != nil {
		return nil, fmt.Errorf("bench: %s: %w", name, err)
	}
	if len(raw.Scenarios) == 0 {
		return nil, fmt.Errorf("bench: %s: no scenarios", name)
	}
	if len(raw.Scenarios) > maxScenarios {
		return nil, fmt.Errorf("bench: %s: more than %d scenarios", name, maxScenarios)
	}
	for i := range raw.Scenarios {
		s, err := compileScenario(name, &raw.Scenarios[i])
		if err != nil {
			return nil, fmt.Errorf("bench: %s: scenario %d (%s): %w", name, i+1, raw.Scenarios[i].Name, err)
		}
		out = append(out, s)
	}
	return out, nil
}

func compileScenario(file string, r *rawScenario) (Scenario, error) {
	s := Scenario{
		Name: r.Name, File: file, Incident: r.Incident, Technique: r.Technique, Outcome: r.Outcome,
		Description: strings.TrimSpace(r.Description), Expect: r.Expect, ExpectNone: r.ExpectNone,
		Mutations: r.Mutations,
	}
	if !nameRe.MatchString(s.Name) {
		return s, fmt.Errorf("name %q: use lower-case letters, digits, '.', '_' and '-'", s.Name)
	}
	if s.Incident < 0 || s.Incident > 999 {
		return s, fmt.Errorf("incident %d out of range", s.Incident)
	}
	if s.Technique != "" && !techniqueRe.MatchString(s.Technique) {
		return s, fmt.Errorf("technique %q: want attack.tNNNN[.NNN], atlas.aml.tNNNN[.NNN] or owasp.asiNN", s.Technique)
	}
	switch {
	case s.ExpectNone && len(s.Expect) > 0:
		return s, errors.New("give expect or expect_none, not both")
	case s.ExpectNone:
		s.Kind = KindBenign
		if s.Outcome != "" {
			return s, errors.New("outcome applies to attacks only")
		}
		if len(r.Mutations) > 0 || len(r.Variants) > 0 {
			return s, errors.New("mutations and variants apply to attacks only")
		}
	case len(s.Expect) > 0:
		s.Kind = KindAttack
		if s.Outcome != OutcomeAttempted && s.Outcome != OutcomeSucceeded {
			return s, fmt.Errorf("outcome %q: want attempted or succeeded", s.Outcome)
		}
	default:
		return s, errors.New("one of expect or expect_none is required")
	}
	for _, id := range s.Expect {
		if !ruleRefRe.MatchString(id) {
			return s, fmt.Errorf("expect: %q is not a rule id", id)
		}
	}
	for _, m := range s.Mutations {
		if m != "all" && m != "none" && operatorByName(m) == nil {
			return s, fmt.Errorf("mutation %q: want all, none or one of %s", m, strings.Join(OperatorNames(), ", "))
		}
	}
	var err error
	if s.Events, err = compileEvents(r.Events); err != nil {
		return s, err
	}
	if len(r.Variants) > maxVariants {
		return s, fmt.Errorf("more than %d variants", maxVariants)
	}
	vseen := map[string]bool{}
	for _, rv := range r.Variants {
		if !nameRe.MatchString(rv.Name) || vseen[rv.Name] || operatorByName(rv.Name) != nil {
			return s, fmt.Errorf("variant name %q is invalid, repeated or an operator name", rv.Name)
		}
		vseen[rv.Name] = true
		v := Variant{Name: rv.Name}
		if v.Events, err = compileEvents(rv.Events); err != nil {
			return s, fmt.Errorf("variant %s: %w", rv.Name, err)
		}
		s.Variants = append(s.Variants, v)
	}
	// Decode every event once now, so a malformed corpus fails at load
	// time and not halfway through a run.
	for _, list := range append([][]EventSpec{s.Events}, variantEvents(s.Variants)...) {
		for i := range list {
			if _, err := list[i].build(i, ""); err != nil {
				return s, fmt.Errorf("event %d: %w", i+1, err)
			}
		}
	}
	return s, nil
}

func variantEvents(vs []Variant) [][]EventSpec {
	out := make([][]EventSpec, 0, len(vs))
	for _, v := range vs {
		out = append(out, v.Events)
	}
	return out
}

func compileEvents(nodes []yaml.Node) ([]EventSpec, error) {
	if len(nodes) == 0 {
		return nil, errors.New("events is required")
	}
	if len(nodes) > maxScenarioEvents {
		return nil, fmt.Errorf("more than %d events", maxScenarioEvents)
	}
	out := make([]EventSpec, 0, len(nodes))
	for i := range nodes {
		n := &nodes[i]
		if n.Kind != yaml.MappingNode {
			return nil, fmt.Errorf("event %d must be a mapping", i+1)
		}
		spec := EventSpec{node: n}
		if sv := mapValue(n, "surfaces"); sv != nil {
			if err := sv.Decode(&spec.Surfaces); err != nil {
				return nil, fmt.Errorf("event %d: surfaces: %v", i+1, err)
			}
			if len(spec.Surfaces) == 0 {
				return nil, fmt.Errorf("event %d: surfaces is empty", i+1)
			}
			for _, s := range spec.Surfaces {
				if !knownSurfaces[s] {
					return nil, fmt.Errorf("event %d: unknown surface %q", i+1, s)
				}
			}
		}
		out = append(out, spec)
	}
	return out, nil
}

// parseOne parses exactly one YAML document and rejects anchors, aliases,
// merge keys, custom tags, duplicate keys and oversized trees.
func parseOne(data []byte) (*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("empty document")
		}
		return nil, err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("more than one YAML document")
	}
	count := 0
	if err := checkTree(&doc, 0, &count); err != nil {
		return nil, err
	}
	root := &doc
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		root = root.Content[0]
	}
	return root, nil
}

func checkTree(n *yaml.Node, depth int, count *int) error {
	*count++
	if *count > maxYAMLNodes {
		return fmt.Errorf("more than %d YAML nodes", maxYAMLNodes)
	}
	if depth > maxYAMLDepth {
		return fmt.Errorf("line %d: nesting deeper than %d", n.Line, maxYAMLDepth)
	}
	if n.Kind == yaml.AliasNode || n.Alias != nil || n.Anchor != "" {
		return fmt.Errorf("line %d: anchors and aliases are not allowed", n.Line)
	}
	switch n.Tag {
	case "", "!!str", "!!int", "!!float", "!!bool", "!!null", "!!seq", "!!map":
	default:
		return fmt.Errorf("line %d: tag %q is not allowed", n.Line, n.Tag)
	}
	if n.Kind == yaml.MappingNode {
		seen := map[string]bool{}
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode {
				return fmt.Errorf("line %d: mapping keys must be scalars", k.Line)
			}
			if k.Value == "<<" {
				return fmt.Errorf("line %d: merge keys are not allowed", k.Line)
			}
			if seen[k.Value] {
				return fmt.Errorf("line %d: duplicate key %q", k.Line, k.Value)
			}
			seen[k.Value] = true
		}
	}
	for _, c := range n.Content {
		if err := checkTree(c, depth+1, count); err != nil {
			return err
		}
	}
	return nil
}

// decodeKnown decodes root into out, refusing mapping keys out does not
// declare (yaml.v3's KnownFields does not apply when decoding a Node).
func decodeKnown(root *yaml.Node, out any) error {
	if err := knownKeys(root); err != nil {
		return err
	}
	return root.Decode(out)
}

var allowedKeys = map[string]map[string]bool{
	"file":     {"suite": true, "scenarios": true},
	"scenario": {"name": true, "incident": true, "technique": true, "outcome": true, "description": true, "expect": true, "expect_none": true, "mutations": true, "variants": true, "events": true},
	"variant":  {"name": true, "events": true},
}

func knownKeys(root *yaml.Node) error {
	if root.Kind != yaml.MappingNode {
		return errors.New("the document must be a mapping")
	}
	if err := keysIn(root, "file"); err != nil {
		return err
	}
	sc := mapValue(root, "scenarios")
	if sc == nil {
		return nil
	}
	if sc.Kind != yaml.SequenceNode {
		return fmt.Errorf("line %d: scenarios must be a list", sc.Line)
	}
	for _, s := range sc.Content {
		if s.Kind != yaml.MappingNode {
			return fmt.Errorf("line %d: a scenario must be a mapping", s.Line)
		}
		if err := keysIn(s, "scenario"); err != nil {
			return err
		}
		if vs := mapValue(s, "variants"); vs != nil && vs.Kind == yaml.SequenceNode {
			for _, v := range vs.Content {
				if v.Kind != yaml.MappingNode {
					return fmt.Errorf("line %d: a variant must be a mapping", v.Line)
				}
				if err := keysIn(v, "variant"); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func keysIn(n *yaml.Node, kind string) error {
	allowed := allowedKeys[kind]
	for i := 0; i+1 < len(n.Content); i += 2 {
		if k := n.Content[i]; !allowed[k.Value] {
			return fmt.Errorf("line %d: unknown key %q in %s", k.Line, k.Value, kind)
		}
	}
	return nil
}

func mapValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}
