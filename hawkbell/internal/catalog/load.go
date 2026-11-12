package catalog

import (
	"bytes"
	"embed"
	"errors"
	"fmt"
	"io/fs"
	"reflect"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"gopkg.in/yaml.v3"
)

//go:embed data/*.yaml
var dataFS embed.FS

// Bounds applied to every data file, embedded or overlay. The embedded
// files are trusted but go through the same parser, so the limits are also
// a regression guard on the data.
const (
	maxFileBytes   = 1 << 20
	maxProducts    = 4096
	maxOverlayFile = 256
)

// Catalog is an immutable, indexed set of products. All methods are safe
// for concurrent use; LoadOverlay swaps in a new snapshot atomically.
type Catalog struct {
	snap atomic.Pointer[snapshot]
	// overlayMu serializes LoadOverlay so two concurrent calls layer one
	// after the other instead of the second discarding the first.
	overlayMu sync.Mutex
}

// emptySnap backs a zero Catalog, so a caller that ignored a Load error (or
// declared a Catalog by value) gets "nothing matches" instead of a nil
// dereference in the middle of a scan.
var emptySnap = &snapshot{source: &state{interpreters: map[string]string{}}}

func (c *Catalog) current() *snapshot {
	if c == nil {
		return emptySnap
	}
	if s := c.snap.Load(); s != nil {
		return s
	}
	return emptySnap
}

// dataFile is the on-disk shape of one catalog YAML file.
type dataFile struct {
	// Version is a date-style string ("2026.11.11"). The catalog reports the
	// highest version among its files.
	Version string
	// AmbiguousNames are process names that need a second class of evidence.
	AmbiguousNames []string
	// Interpreters adds host process names whose script argument identifies
	// the program, mapped to the ecosystem (npm or pypi) of that script.
	Interpreters map[string]string
	Products     []entry
}

// entry is one product as written in a file, plus what an overlay needs to
// know: which keys were present and whether to replace instead of merge.
type entry struct {
	Product Product
	keys    map[string]bool
	replace bool
	line    int
}

// Load parses and validates the embedded catalog. It fails if an id is
// duplicated, if a product has no fingerprint, or if two products claim the
// same fingerprint without listing each other in Aliases.
//
// The embedded data is parsed once per process (about 12 ms, nearly all of
// it YAML decoding) and the immutable result is shared by every Catalog that
// Load returns. A short-lived process that does not need the catalog, such
// as the hook entry point, should not call Load at all.
func Load() (*Catalog, error) {
	baseOnce.Do(func() { baseSnap, baseErr = loadEmbedded() })
	if baseErr != nil {
		return nil, baseErr
	}
	c := &Catalog{}
	c.snap.Store(baseSnap)
	return c, nil
}

var (
	baseOnce sync.Once
	baseSnap *snapshot
	baseErr  error
)

func loadEmbedded() (snap *snapshot, err error) {
	defer func() {
		if r := recover(); r != nil {
			snap, err = nil, fmt.Errorf("catalog: internal error loading embedded data: %v", r)
		}
	}()
	names, err := fs.Glob(dataFS, "data/*.yaml")
	if err != nil {
		return nil, fmt.Errorf("catalog: %w", err)
	}
	sort.Strings(names)
	var files []namedFile
	for _, name := range names {
		b, err := dataFS.ReadFile(name)
		if err != nil {
			return nil, fmt.Errorf("catalog: %w", err)
		}
		df, err := parseFile(name, b)
		if err != nil {
			return nil, err
		}
		files = append(files, namedFile{name, df})
	}
	st := &state{interpreters: map[string]string{}}
	for _, f := range files {
		if err := st.add(f.name, f.df, false); err != nil {
			return nil, err
		}
	}
	return st.build()
}

type namedFile struct {
	name string
	df   *dataFile
}

// parseFile decodes one YAML document strictly: unknown keys anywhere are an
// error, so a misspelt field cannot silently remove a fingerprint.
func parseFile(name string, b []byte) (*dataFile, error) {
	if len(b) > maxFileBytes {
		return nil, fmt.Errorf("catalog: %s: file is larger than %d bytes", name, maxFileBytes)
	}
	// A UTF-8 byte order mark is common in files edited on Windows.
	b = bytes.TrimPrefix(b, []byte("\xef\xbb\xbf"))
	var root yaml.Node
	if err := yaml.Unmarshal(b, &root); err != nil {
		return nil, fmt.Errorf("catalog: %s: %w", name, err)
	}
	df := &dataFile{}
	if root.Kind == 0 {
		return df, nil // empty file
	}
	doc := &root
	if doc.Kind == yaml.DocumentNode && len(doc.Content) == 1 {
		doc = doc.Content[0]
	}
	if doc.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("catalog: %s: top level must be a mapping", name)
	}
	for i := 0; i+1 < len(doc.Content); i += 2 {
		k, v := doc.Content[i], doc.Content[i+1]
		switch k.Value {
		case "version":
			if err := v.Decode(&df.Version); err != nil {
				return nil, fmt.Errorf("catalog: %s: version: %w", name, err)
			}
		case "ambiguous_names":
			if err := v.Decode(&df.AmbiguousNames); err != nil {
				return nil, fmt.Errorf("catalog: %s: ambiguous_names: %w", name, err)
			}
		case "interpreters":
			if err := v.Decode(&df.Interpreters); err != nil {
				return nil, fmt.Errorf("catalog: %s: interpreters: %w", name, err)
			}
		case "products":
			if v.Kind != yaml.SequenceNode {
				return nil, fmt.Errorf("catalog: %s: line %d: products must be a list", name, v.Line)
			}
			if len(v.Content) > maxProducts {
				return nil, fmt.Errorf("catalog: %s: more than %d products", name, maxProducts)
			}
			for _, pn := range v.Content {
				e, err := parseEntry(pn)
				if err != nil {
					return nil, fmt.Errorf("catalog: %s: %w", name, err)
				}
				df.Products = append(df.Products, e)
			}
		default:
			return nil, fmt.Errorf("catalog: %s: line %d: unknown top-level key %q", name, k.Line, k.Value)
		}
	}
	return df, nil
}

var productType = reflect.TypeOf(Product{})

func parseEntry(n *yaml.Node) (entry, error) {
	e := entry{keys: map[string]bool{}, line: n.Line}
	if n.Kind != yaml.MappingNode {
		return e, fmt.Errorf("line %d: a product must be a mapping", n.Line)
	}
	// "replace" belongs to the overlay mechanism, not to Product, so it is
	// lifted out before the strict check.
	body := &yaml.Node{Kind: yaml.MappingNode, Tag: n.Tag, Line: n.Line, Column: n.Column}
	for i := 0; i+1 < len(n.Content); i += 2 {
		k, v := n.Content[i], n.Content[i+1]
		if k.Value == "replace" {
			if err := v.Decode(&e.replace); err != nil {
				return e, fmt.Errorf("line %d: replace: %w", k.Line, err)
			}
			continue
		}
		if e.keys[k.Value] {
			return e, fmt.Errorf("line %d: key %q is repeated", k.Line, k.Value)
		}
		e.keys[k.Value] = true
		body.Content = append(body.Content, k, v)
	}
	if err := strictCheck(body, productType, 0); err != nil {
		return e, err
	}
	if err := body.Decode(&e.Product); err != nil {
		if strings.HasPrefix(err.Error(), "line ") {
			return e, err // already located by a custom unmarshaler
		}
		return e, fmt.Errorf("line %d: %w", n.Line, err)
	}
	return e, nil
}

var unmarshalerType = reflect.TypeOf((*yaml.Unmarshaler)(nil)).Elem()

// strictCheck verifies that every mapping key in n names a field of t.
// yaml.v3 only offers this (KnownFields) on a whole-document decoder, and we
// decode node by node to keep line numbers and key presence.
func strictCheck(n *yaml.Node, t reflect.Type, depth int) error {
	if depth > 16 {
		return fmt.Errorf("line %d: nested too deeply", n.Line)
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	// Anchors keep the data files short (one settings file list reused by
	// several probes); check what the alias points at.
	if n.Kind == yaml.AliasNode && n.Alias != nil {
		n = n.Alias
	}
	if reflect.PointerTo(t).Implements(unmarshalerType) {
		return nil // the type validates its own keys (OSPaths)
	}
	switch t.Kind() {
	case reflect.Struct:
		if n.Kind != yaml.MappingNode {
			if n.Kind == yaml.ScalarNode && n.Tag == "!!null" {
				return nil
			}
			return fmt.Errorf("line %d: expected a mapping", n.Line)
		}
		fields := yamlFields(t)
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			if k.Tag == "!!merge" {
				// "<<: *anchor" contributes the anchor's keys to this struct.
				if err := strictCheck(v, t, depth+1); err != nil {
					return err
				}
				continue
			}
			f, ok := fields[k.Value]
			if !ok {
				return fmt.Errorf("line %d: unknown key %q", k.Line, k.Value)
			}
			if err := strictCheck(v, t.Field(f).Type, depth+1); err != nil {
				return err
			}
		}
	case reflect.Slice:
		if n.Kind != yaml.SequenceNode {
			return nil // scalar/null: let Decode report a type mismatch
		}
		for _, c := range n.Content {
			if err := strictCheck(c, t.Elem(), depth+1); err != nil {
				return err
			}
		}
	}
	return nil
}

// yamlFields maps YAML keys to struct field indexes.
func yamlFields(t reflect.Type) map[string]int {
	out := make(map[string]int, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		tag := t.Field(i).Tag.Get("yaml")
		name, _, _ := strings.Cut(tag, ",")
		if name == "" || name == "-" {
			continue
		}
		out[name] = i
	}
	return out
}

// state accumulates files before a snapshot is built.
type state struct {
	version      string
	products     []Product
	byID         map[string]int
	ambiguous    []string
	interpreters map[string]string
	overlay      string // hex digest of overlay content, "" when none
}

// add merges one file into the state. For the embedded data a repeated id is
// an error; for an overlay it overrides the existing product.
func (st *state) add(name string, df *dataFile, overlay bool) error {
	if st.byID == nil {
		st.byID = map[string]int{}
	}
	if !overlay && df.Version > st.version {
		st.version = df.Version
	}
	st.ambiguous = append(st.ambiguous, df.AmbiguousNames...)
	for k, v := range df.Interpreters {
		st.interpreters[strings.ToLower(k)] = v
	}
	var errs []error
	for _, e := range df.Products {
		id := e.Product.ID
		i, exists := st.byID[id]
		switch {
		case !exists:
			if len(st.products) >= maxProducts {
				return fmt.Errorf("catalog: %s: more than %d products", name, maxProducts)
			}
			st.byID[id] = len(st.products)
			st.products = append(st.products, e.Product)
		case !overlay:
			errs = append(errs, fmt.Errorf("catalog: %s: line %d: duplicate product id %q", name, e.line, id))
		case e.replace:
			st.products[i] = e.Product
		default:
			st.products[i] = mergeProduct(st.products[i], e)
		}
	}
	return errors.Join(errs...)
}

// mergeProduct copies the fields that were present in the overlay entry over
// the base product. Lists replace rather than append: an administrator who
// writes binaries: [x] means exactly that list. Leaving a key out keeps the
// shipped value, so an overlay that only adds a state directory does not
// silently drop the product's hooks or transcript locations.
func mergeProduct(base Product, e entry) Product {
	out := base.clone()
	fields := yamlFields(productType)
	dst := reflect.ValueOf(&out).Elem()
	src := reflect.ValueOf(e.Product)
	for key := range e.keys {
		if i, ok := fields[key]; ok {
			dst.Field(i).Set(src.Field(i))
		}
	}
	return out
}
