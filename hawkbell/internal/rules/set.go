package rules

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Set is a compiled collection of rules, the named lists they reference and
// the operator suppressions shipped with them. A Set is not safe for
// concurrent mutation (Merge, Disable); engines take a snapshot in
// NewEngine, so a Set may be changed and handed to a new engine while older
// engines keep running on what they were given.
type Set struct {
	rules        []*rule
	byID         map[string]*rule
	lists        map[string]*namedList
	suppressions []Suppression
	packs        map[string]string // pack name -> version
	disabled     map[string]bool
	issues       []Issue // problems found while loading (duplicate ids)
	// flagOnly marks rules a guard subset keeps only because a guard rule
	// requires a flag they set: they maintain state, never emit.
	flagOnly map[string]bool
}

func newSet() *Set {
	return &Set{
		byID:     map[string]*rule{},
		lists:    map[string]*namedList{},
		packs:    map[string]string{},
		disabled: map[string]bool{},
		flagOnly: map[string]bool{},
	}
}

// Info describes one rule for listings (hawkbell rules list, health).
type Info struct {
	ID          string
	Title       string
	Description string
	Severity    string
	Confidence  string
	Class       string
	Kind        string
	Category    string
	Tags        []string
	Maturity    string
	Response    string
	Emit        bool
	Pack        string
	PackVersion string
	Enabled     bool
	Tests       int
}

// packFromNode compiles one parsed pack file into s. A pack from the
// embedded cache (lazy) has its rules compiled in steps (lazy.go).
func (s *Set) packFromNode(name string, root *yaml.Node, embedded, lazy bool, tree *cacheTree) error {
	if lazy {
		if handled, err := s.lazyPack(name, root, embedded, tree); handled {
			return err
		}
	}
	if tree != nil {
		// Compiled whole: every rule's deferred subtrees first.
		if rules := mapValue(root, "rules"); rules != nil {
			for _, rn := range rules.Content {
				if err := tree.materialize(rn, true); err != nil {
					return fmt.Errorf("rules: %s: %w", name, err)
				}
			}
		}
	}
	var p rawPack
	if err := decodeNode(root, &p); err != nil {
		return fmt.Errorf("rules: %s: %w", name, err)
	}
	if err := s.checkPackHead(name, p.Pack, p.Version, len(p.Rules)); err != nil {
		return err
	}
	s.packs[p.Pack] = p.Version
	ruleNodes := mapValue(root, "rules")
	for i := range p.Rules {
		var rn *yaml.Node
		if ruleNodes != nil && i < len(ruleNodes.Content) {
			rn = ruleNodes.Content[i]
		}
		r, err := compileRule(&p.Rules[i], rn, p.Pack, p.Version)
		if err != nil {
			return fmt.Errorf("rules: %s: %w", name, err)
		}
		s.addRule(r, embedded)
	}
	return nil
}

// rawPackHead is a pack file with its rules left as a node. It declares
// the same keys as rawPack (TestRawPackHeadKeys).
type rawPackHead struct {
	Pack        string    `yaml:"pack"`
	Version     string    `yaml:"version"`
	Description string    `yaml:"description"`
	Rules       yaml.Node `yaml:"rules"`
}

// checkPackHead applies the pack-level checks of packFromNode.
func (s *Set) checkPackHead(name, pack, version string, rules int) error {
	if pack == "" || !validListName(pack) {
		return fmt.Errorf("rules: %s: pack name %q: use lower-case letters, digits, '_', '-' and '.'", name, pack)
	}
	if version == "" || len(version) > 64 || strings.ContainsAny(version, ", \t\n") {
		return fmt.Errorf("rules: %s: version is required (no spaces or commas)", name)
	}
	if rules > MaxPackRules {
		return fmt.Errorf("rules: %s: more than %d rules", name, MaxPackRules)
	}
	if prev, ok := s.packs[pack]; ok {
		return fmt.Errorf("rules: %s: pack %q (version %s) is already loaded", name, pack, prev)
	}
	return nil
}

// lazyPack loads a pack from the embedded cache as rule stubs. handled is
// false when the pack is not in the plain shape it reads; the caller then
// compiles it whole (and reports any error from there).
func (s *Set) lazyPack(name string, root *yaml.Node, embedded bool, tree *cacheTree) (handled bool, err error) {
	var p rawPackHead
	if err := decodeNode(root, &p); err != nil {
		return false, nil
	}
	if p.Rules.Kind != 0 && p.Rules.Kind != yaml.SequenceNode {
		return false, nil
	}
	if err := s.checkPackHead(name, p.Pack, p.Version, len(p.Rules.Content)); err != nil {
		return true, err
	}
	s.packs[p.Pack] = p.Version
	for _, rn := range p.Rules.Content {
		r := stubRule(rn, p.Pack, p.Version, tree)
		if r == nil {
			if err := tree.materialize(rn, true); err != nil {
				return true, fmt.Errorf("rules: %s: %w", name, err)
			}
			var rr rawRule
			if err := decodeNode(rn, &rr); err != nil {
				return true, fmt.Errorf("rules: %s: %w", name, err)
			}
			if r, err = compileRule(&rr, rn, p.Pack, p.Version); err != nil {
				return true, fmt.Errorf("rules: %s: %w", name, err)
			}
		}
		s.addRule(r, embedded)
	}
	return true, nil
}

// addRule adds a compiled rule of a pack being loaded, noting a duplicate
// id.
func (s *Set) addRule(r *rule, embedded bool) {
	r.embedded = embedded
	if old, dup := s.byID[r.ID]; dup {
		s.issues = append(s.issues, Issue{RuleID: r.ID, Level: LevelError, Code: "duplicate_id",
			Msg: fmt.Sprintf("rule id defined twice (pack %s and pack %s); the later definition is used", old.pack, r.pack)})
	}
	s.put(r)
}

// put adds r, replacing a rule with the same id in place.
func (s *Set) put(r *rule) {
	if old, ok := s.byID[r.ID]; ok {
		for i, x := range s.rules {
			if x == old {
				s.rules[i] = r
				break
			}
		}
	} else {
		s.rules = append(s.rules, r)
	}
	s.byID[r.ID] = r
}

// Load compiles rule content from memory. Keys are file names as they
// appear in a bundle or a rules directory: "lists.yaml" and
// "suppressions.yaml" (at any directory level) are the list and
// suppression files, every other "*.yaml" is a pack. Files are processed
// in name order, so the result does not depend on map iteration.
func Load(files map[string][]byte) (*Set, error) {
	return load(files, false)
}

func load(files map[string][]byte, embedded bool) (*Set, error) {
	s := newSet()
	for _, n := range sortedFileNames(files) {
		src, ok, err := parseSource(n, files[n])
		if err != nil {
			return nil, err
		}
		if !ok {
			continue
		}
		if err := s.addSource(src, embedded); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// loadSources compiles already parsed files, in the order given (the
// order load would have used). The embedded node cache feeds it.
func loadSources(srcs []sourceFile, embedded bool) (*Set, error) {
	s := newSet()
	for _, src := range srcs {
		if err := s.addSource(src, embedded); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// sourceFile is one content file after YAML parsing and the structural
// checks of parseStrict.
type sourceFile struct {
	name string
	size int // bytes of the YAML source, for the per-file caps
	root *yaml.Node
	// cached is set on files decoded from the embedded cache: content that
	// compiled whole when the cache was made, so its rules may be
	// compiled lazily. tree holds their subtrees not decoded yet.
	cached bool
	tree   *cacheTree
}

// fileRole says what a content file is from its base name: "lists",
// "suppressions", "pack", or "" for a file that is not content.
func fileRole(name string) string {
	base := path.Base(strings.ReplaceAll(name, `\`, "/"))
	switch {
	case base == "lists.yaml":
		return "lists"
	case base == "suppressions.yaml":
		return "suppressions"
	case strings.HasSuffix(base, ".yaml"):
		return "pack"
	}
	return ""
}

func sortedFileNames(files map[string][]byte) []string {
	names := make([]string, 0, len(files))
	for n := range files {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// checkSize applies the per-file byte cap of a content file.
func checkSize(name string, size int) error {
	switch fileRole(name) {
	case "lists":
		if size > maxListBytes {
			return fmt.Errorf("rules: lists.yaml is larger than %d bytes", maxListBytes)
		}
	case "suppressions":
		if size > maxSuppBytes {
			return fmt.Errorf("rules: suppressions.yaml is larger than %d bytes", maxSuppBytes)
		}
	case "pack":
		if size > MaxPackBytes {
			return fmt.Errorf("rules: %s: pack is larger than %d bytes", name, MaxPackBytes)
		}
	}
	return nil
}

// parseSource parses one content file; ok is false for a file that is not
// content (it is ignored).
func parseSource(name string, data []byte) (src sourceFile, ok bool, err error) {
	role := fileRole(name)
	if role == "" {
		return sourceFile{}, false, nil
	}
	if err := checkSize(name, len(data)); err != nil {
		return sourceFile{}, false, err
	}
	root, err := parseStrict(data)
	if err != nil {
		switch role {
		case "lists":
			return sourceFile{}, false, fmt.Errorf("lists.yaml: %w", err)
		case "suppressions":
			return sourceFile{}, false, fmt.Errorf("rules: suppressions.yaml: %w", err)
		}
		return sourceFile{}, false, fmt.Errorf("rules: %s: %w", name, err)
	}
	return sourceFile{name: name, size: len(data), root: root}, true, nil
}

// addSource compiles one parsed file into s.
func (s *Set) addSource(src sourceFile, embedded bool) error {
	if err := checkSize(src.name, src.size); err != nil {
		return err
	}
	switch fileRole(src.name) {
	case "lists":
		ls, err := listsFromNode(src.root)
		if err != nil {
			return err
		}
		for k, v := range ls {
			s.lists[k] = v
		}
	case "suppressions":
		sups, err := suppressionsFromNode(src.root)
		if err != nil {
			return err
		}
		s.suppressions = append(s.suppressions, sups...)
	case "pack":
		return s.packFromNode(src.name, src.root, embedded, src.cached, src.tree)
	}
	return nil
}

func suppressionsFromNode(root *yaml.Node) ([]Suppression, error) {
	var raw rawSuppressions
	if err := decodeNode(root, &raw); err != nil {
		return nil, fmt.Errorf("rules: suppressions.yaml: %w", err)
	}
	if len(raw.Suppressions) > maxSuppItems {
		return nil, fmt.Errorf("rules: suppressions.yaml: more than %d entries", maxSuppItems)
	}
	out := make([]Suppression, 0, len(raw.Suppressions))
	for i, r := range raw.Suppressions {
		if r.Rule == "" {
			return nil, fmt.Errorf("rules: suppressions.yaml: entry %d: rule is required (use \"*\" for every rule)", i+1)
		}
		if r.Reason == "" {
			return nil, fmt.Errorf("rules: suppressions.yaml: entry %d: reason is required", i+1)
		}
		sp := Suppression{RuleID: r.Rule, Match: r.Match, Reason: r.Reason, Tags: r.Tags}
		if r.Expires != "" {
			t, err := ParseExpiry(r.Expires)
			if err != nil {
				return nil, fmt.Errorf("rules: suppressions.yaml: entry %d: expires %w", i+1, err)
			}
			sp.Expires = t
		}
		out = append(out, sp)
	}
	return out, nil
}

// clone returns a copy that can be mutated independently. Compiled rules
// and lists are immutable and shared.
func (s *Set) clone() *Set {
	c := newSet()
	c.rules = append([]*rule(nil), s.rules...)
	for k, v := range s.byID {
		c.byID[k] = v
	}
	for k, v := range s.lists {
		c.lists[k] = v
	}
	c.suppressions = append([]Suppression(nil), s.suppressions...)
	for k, v := range s.packs {
		c.packs[k] = v
	}
	for k, v := range s.disabled {
		c.disabled[k] = v
	}
	for k, v := range s.flagOnly {
		c.flagOnly[k] = v
	}
	c.issues = append([]Issue(nil), s.issues...)
	return c
}

// Merge folds o into s: rules of o replace rules of s with the same id and
// are added otherwise, lists of o replace lists of s with the same name,
// suppressions are appended, disabled ids and pack versions are combined.
// This is how a bundle overrides the embedded content.
func (s *Set) Merge(o *Set) {
	if o == nil {
		return
	}
	for _, r := range o.rules {
		s.put(r)
		delete(s.flagOnly, r.ID)
		if o.flagOnly[r.ID] {
			s.flagOnly[r.ID] = true
		}
	}
	for k, v := range o.lists {
		s.lists[k] = v
	}
	s.suppressions = append(s.suppressions, o.suppressions...)
	for k, v := range o.packs {
		s.packs[k] = v
	}
	for k := range o.disabled {
		s.disabled[k] = true
	}
	s.issues = append(s.issues, o.issues...)
}

// Disable turns rules off by id. Unknown ids are remembered, so disabling
// before merging the pack that defines a rule works too.
func (s *Set) Disable(ids ...string) {
	for _, id := range ids {
		if id != "" {
			s.disabled[id] = true
		}
	}
}

// Suppressions returns the operator suppressions shipped with the set
// (suppressions.yaml). NewEngine applies them together with
// Options.Suppressions.
func (s *Set) Suppressions() []Suppression {
	return append([]Suppression(nil), s.suppressions...)
}

func (s *Set) enabled(r *rule) bool { return !s.disabled[r.ID] }

// Count returns the number of enabled rules.
func (s *Set) Count() int {
	n := 0
	for _, r := range s.rules {
		if s.enabled(r) {
			n++
		}
	}
	return n
}

// Version returns "pack@version" for every loaded pack, sorted and joined
// with commas: what health and detections report as the content version.
func (s *Set) Version() string {
	parts := make([]string, 0, len(s.packs))
	for p, v := range s.packs {
		parts = append(parts, p+"@"+v)
	}
	sort.Strings(parts)
	return strings.Join(parts, ",")
}

// Hash returns a SHA-256 over the normalized content the engine runs:
// every rule's canonical definition and enabled state in id order, every
// list's sorted entries and every suppression. Formatting, comments and key
// order do not change it.
func (s *Set) Hash() string {
	h := sha256.New()
	ids := make([]string, 0, len(s.byID))
	for id := range s.byID {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		r := s.byID[id]
		state := "on"
		if !s.enabled(r) {
			state = "off"
		}
		if s.flagOnly[id] {
			state = "flags"
		}
		fmt.Fprintf(h, "rule\x00%s\x00%s\x00", id, state)
		h.Write(r.canonical())
		h.Write([]byte{0})
	}
	names := make([]string, 0, len(s.lists))
	for n := range s.lists {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(h, "list\x00%s\x00%s\x00", n, strings.Join(s.lists[n].entries, "\x01"))
	}
	for _, sp := range s.suppressions {
		b, _ := json.Marshal(sp)
		fmt.Fprintf(h, "supp\x00%s\x00", b)
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Rules describes every rule, enabled or not, in load order.
func (s *Set) Rules() []Info {
	out := make([]Info, 0, len(s.rules))
	for _, r := range s.rules {
		_ = r.ensure() // an invalid rule is listed with its id; Lint says why
		out = append(out, Info{
			ID: r.ID, Title: r.Title, Description: r.Description, Severity: r.Severity,
			Confidence: r.Confidence, Class: r.Class, Kind: r.Kind, Category: r.Category,
			Tags: append([]string(nil), r.Tags...), Maturity: r.Maturity, Response: r.response,
			Emit: r.emit && !s.flagOnly[r.ID], Pack: r.pack, PackVersion: r.packVersion,
			Enabled: s.enabled(r), Tests: r.testCount,
		})
	}
	return out
}

// GuardSubset returns the rules `hawkbell hook` loads in guard mode: every
// enabled rule whose response is ask or block, plus, transitively, the
// rules that set a flag one of them requires. Without the latter a guard
// rule that depends on session state could never fire in a hook process;
// they are kept as flag maintainers only and never emit a detection there.
func (s *Set) GuardSubset() *Set {
	g := newSet()
	for k, v := range s.lists {
		g.lists[k] = v
	}
	for k, v := range s.packs {
		g.packs[k] = v
	}
	g.suppressions = append(g.suppressions, s.suppressions...)
	keep := map[string]bool{}
	need := map[string]bool{}
	for _, r := range s.rules {
		if s.enabled(r) && r.Kind == KindActivity && (r.response == ResponseAsk || r.response == ResponseBlock) {
			keep[r.ID] = true
			for _, f := range r.require {
				need[f] = true
			}
			for _, f := range r.requireAny {
				need[f] = true
			}
		}
	}
	flagOnly := map[string]bool{}
	for changed := true; changed; {
		changed = false
		for _, r := range s.rules {
			if keep[r.ID] || flagOnly[r.ID] || !s.enabled(r) || r.Kind != KindActivity {
				continue
			}
			sets := false
			for _, f := range r.setFlags {
				if need[f] {
					sets = true
					break
				}
			}
			if !sets {
				continue
			}
			flagOnly[r.ID] = true
			changed = true
			for _, f := range r.require {
				need[f] = true
			}
			for _, f := range r.requireAny {
				need[f] = true
			}
		}
	}
	for _, r := range s.rules {
		if keep[r.ID] || flagOnly[r.ID] {
			g.put(r)
			if flagOnly[r.ID] {
				g.flagOnly[r.ID] = true
			}
		}
	}
	return g
}
