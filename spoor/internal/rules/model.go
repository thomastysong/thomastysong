package rules

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

// Loader caps. Rule packs arrive through signed bundles, but a signature
// says who wrote a file, not that its content is sane, and LoadDir also
// reads operator-managed directories.
const (
	MaxPackBytes  = 1 << 20 // one pack file
	MaxPackRules  = 500     // rules in one pack file
	MaxRegexLen   = 1000    // characters in one regular expression
	maxTests      = 64      // inline tests per rule
	maxYAMLDepth  = 64      // nesting of any YAML document
	maxYAMLNodes  = 400000  // nodes in one YAML document
	maxListBytes  = 4 << 20 // lists.yaml
	maxListItems  = 20000   // entries across all lists
	maxSuppBytes  = 1 << 20 // suppressions.yaml
	maxSuppItems  = 5000    // suppressions in one file
	maxFlagNames  = 32      // per flags.require / require_any / set
	maxFieldNames = 32      // per dedup / evidence / novelty list
)

// rawPack is one pack file as written.
type rawPack struct {
	Pack        string    `yaml:"pack"`
	Version     string    `yaml:"version"`
	Description string    `yaml:"description"`
	Rules       []rawRule `yaml:"rules"`
}

type rawRule struct {
	ID             string        `yaml:"id"`
	Title          string        `yaml:"title"`
	Description    string        `yaml:"description"`
	Kind           string        `yaml:"kind"`
	Class          string        `yaml:"class"`
	Severity       string        `yaml:"severity"`
	Confidence     string        `yaml:"confidence"`
	Maturity       string        `yaml:"maturity"`
	Category       string        `yaml:"category"`
	Tags           []string      `yaml:"tags"`
	References     []string      `yaml:"references"`
	FalsePositives []string      `yaml:"falsepositives"`
	When           yaml.Node     `yaml:"when"`
	Match          yaml.Node     `yaml:"match"`
	Allow          yaml.Node     `yaml:"allow"`
	Flags          *rawFlags     `yaml:"flags"`
	Threshold      *rawThreshold `yaml:"threshold"`
	Emit           *bool         `yaml:"emit"`
	Escalate       bool          `yaml:"escalate"`
	Response       string        `yaml:"response"`
	Dedup          []string      `yaml:"dedup"`
	Evidence       []string      `yaml:"evidence"`
	Remedy         string        `yaml:"remedy"`
	Novelty        *rawNovelty   `yaml:"novelty"`
	Tests          []rawTest     `yaml:"tests"`
}

type rawFlags struct {
	Require    []string `yaml:"require"`
	RequireAny []string `yaml:"require_any"`
	Set        []string `yaml:"set"`
	TTL        string   `yaml:"ttl"`
	Scope      string   `yaml:"scope"`
}

type rawThreshold struct {
	Count  int    `yaml:"count"`
	Window string `yaml:"window"`
	By     string `yaml:"by"`
}

type rawNovelty struct {
	Fields []string `yaml:"fields"`
	Raise  bool     `yaml:"raise"`
}

type rawTest struct {
	Name    string      `yaml:"name"`
	Event   yaml.Node   `yaml:"event"`
	Events  []yaml.Node `yaml:"events"`
	Content yaml.Node   `yaml:"content"`
	Feat    yaml.Node   `yaml:"feat"`
	Flags   []string    `yaml:"flags"`
	Expect  string      `yaml:"expect"`
}

type rawLists struct {
	Lists map[string][]string `yaml:"lists"`
}

type rawSuppressions struct {
	Suppressions []rawSuppression `yaml:"suppressions"`
}

type rawSuppression struct {
	Rule    string            `yaml:"rule"`
	Match   map[string]string `yaml:"match"`
	Expires string            `yaml:"expires"`
	Reason  string            `yaml:"reason"`
	Tags    []string          `yaml:"tags"`
}

// errYAML wraps every structural YAML rejection.
var errYAML = errors.New("rules: invalid YAML")

// parseStrict parses exactly one YAML document, checks it and returns its
// root node. It refuses anchors, aliases and merge keys (an alias bomb
// costs nothing to write and a rule that silently inherits fields from
// another is unreviewable), custom tags, duplicate keys and documents
// deeper or larger than the caps; decodeNode then refuses any mapping key
// the target struct does not declare.
func parseStrict(data []byte) (*yaml.Node, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, fmt.Errorf("%w: empty document", errYAML)
		}
		return nil, fmt.Errorf("%w: %v", errYAML, err)
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: more than one YAML document", errYAML)
	}
	count := 0
	if err := checkNode(&doc, 0, &count); err != nil {
		return nil, err
	}
	root := &doc
	if root.Kind == yaml.DocumentNode && len(root.Content) == 1 {
		root = root.Content[0]
	}
	return root, nil
}

// decodeNode decodes a checked node into out after rejecting unknown keys.
func decodeNode(root *yaml.Node, out any) error {
	if err := checkKnown(root, reflect.TypeOf(out).Elem(), ""); err != nil {
		return err
	}
	if err := root.Decode(out); err != nil {
		return fmt.Errorf("%w: %v", errYAML, err)
	}
	return nil
}

// mapValue returns the value node of key in a mapping node.
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

// checkNode walks the whole tree once.
func checkNode(n *yaml.Node, depth int, count *int) error {
	*count++
	if *count > maxYAMLNodes {
		return fmt.Errorf("%w: document has more than %d nodes", errYAML, maxYAMLNodes)
	}
	if depth > maxYAMLDepth {
		return fmt.Errorf("%w: line %d: nesting deeper than %d", errYAML, n.Line, maxYAMLDepth)
	}
	if n.Kind == yaml.AliasNode || n.Alias != nil {
		return fmt.Errorf("%w: line %d: aliases are not allowed", errYAML, n.Line)
	}
	if n.Anchor != "" {
		return fmt.Errorf("%w: line %d: anchors are not allowed", errYAML, n.Line)
	}
	if n.Tag != "" && !strings.HasPrefix(n.Tag, "!!") {
		return fmt.Errorf("%w: line %d: custom tag %q is not allowed", errYAML, n.Line, n.Tag)
	}
	switch n.Tag {
	case "", "!!str", "!!int", "!!float", "!!bool", "!!null", "!!seq", "!!map", "!!timestamp":
	default:
		return fmt.Errorf("%w: line %d: tag %q is not allowed", errYAML, n.Line, n.Tag)
	}
	if n.Kind == yaml.MappingNode {
		seen := make(map[string]int, len(n.Content)/2)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i]
			if k.Kind != yaml.ScalarNode {
				return fmt.Errorf("%w: line %d: mapping keys must be scalars", errYAML, k.Line)
			}
			if k.Value == "<<" && k.Tag == "!!merge" {
				return fmt.Errorf("%w: line %d: merge keys are not allowed", errYAML, k.Line)
			}
			if prev, dup := seen[k.Value]; dup {
				return fmt.Errorf("%w: line %d: key %q already defined at line %d", errYAML, k.Line, k.Value, prev)
			}
			seen[k.Value] = k.Line
		}
	}
	for _, c := range n.Content {
		if err := checkNode(c, depth+1, count); err != nil {
			return err
		}
	}
	return nil
}

var nodeType = reflect.TypeOf(yaml.Node{})

// checkKnown rejects mapping keys that the target type does not declare
// (yaml.v3's KnownFields option does not apply when decoding from a Node).
// Fields typed yaml.Node are parsed later by their own strict parsers.
func checkKnown(n *yaml.Node, t reflect.Type, path string) error {
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t == nodeType {
		return nil
	}
	switch t.Kind() {
	case reflect.Struct:
		if n.Kind != yaml.MappingNode {
			if n.Kind == yaml.ScalarNode && n.Tag == "!!null" {
				return nil
			}
			return fmt.Errorf("%w: line %d: %s must be a mapping", errYAML, n.Line, orRoot(path))
		}
		fields := yamlFields(t)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k := n.Content[i].Value
			f, ok := fields[k]
			if !ok {
				return fmt.Errorf("%w: line %d: unknown key %q in %s", errYAML, n.Content[i].Line, k, orRoot(path))
			}
			if err := checkKnown(n.Content[i+1], f.Type, join(path, k)); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if n.Kind != yaml.SequenceNode {
			return nil // a type error that Decode reports with its own message
		}
		for i, c := range n.Content {
			if err := checkKnown(c, t.Elem(), fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
		}
	case reflect.Map:
		if n.Kind != yaml.MappingNode {
			return nil
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			if err := checkKnown(n.Content[i+1], t.Elem(), join(path, n.Content[i].Value)); err != nil {
				return err
			}
		}
	}
	return nil
}

// fieldCache memoizes yamlFields per struct type: checkKnown runs once per
// mapping node, and recomputing the field map there was an eighth of the
// cost of loading a pack.
var fieldCache sync.Map // reflect.Type -> map[string]reflect.StructField

func yamlFields(t reflect.Type) map[string]reflect.StructField {
	if m, ok := fieldCache.Load(t); ok {
		return m.(map[string]reflect.StructField)
	}
	m := buildYAMLFields(t)
	fieldCache.Store(t, m)
	return m
}

func buildYAMLFields(t reflect.Type) map[string]reflect.StructField {
	out := make(map[string]reflect.StructField, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
		if name == "" || name == "-" {
			continue
		}
		out[name] = f
	}
	return out
}

func join(path, k string) string {
	if path == "" {
		return k
	}
	return path + "." + k
}

func orRoot(path string) string {
	if path == "" {
		return "the document"
	}
	return path
}
