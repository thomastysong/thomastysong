package event

// The JSON Schema of the wire record, generated from this package and
// checked against what the binary really writes.
//
//	go test ./internal/event -run TestSchema            check
//	go test ./internal/event -run TestSchema -update    regenerate
//
// The generator reads the Go types by reflection (field names, JSON tags,
// omitempty/omitzero) and this package's source with go/ast (doc comments
// and the constants that make up each closed vocabulary), so a new field or
// constant changes the schema without anyone editing it by hand, and the
// test fails until the regenerated files are committed:
//
//   - docs/schema/event.schema.json (JSON Schema 2020-12);
//   - the field reference between the GENERATED markers in docs/EVENTS.md.
//
// The validator below implements the subset of JSON Schema the generator
// emits, with the standard library only, and refuses any keyword it does
// not implement, so the schema cannot quietly grow a constraint nobody
// checks. Every line under docs/schema/examples (records the real binary
// wrote; docs/schema/examples/regen.sh) must validate, and every example
// record quoted in docs/EVENTS.md must be one of those lines.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

var updateSchema = flag.Bool("update", false, "rewrite docs/schema/event.schema.json and the generated field reference in docs/EVENTS.md")

var (
	schemaFile  = filepath.Join("..", "..", "docs", "schema", "event.schema.json")
	eventsDoc   = filepath.Join("..", "..", "docs", "EVENTS.md")
	examplesDir = filepath.Join("..", "..", "docs", "schema", "examples")
	// The detection-context type is declared where context records are
	// made; it is part of the wire vocabulary all the same.
	privacyContextSrc = filepath.Join("..", "privacy", "context.go")
)

const (
	genBegin     = "<!-- BEGIN GENERATED: field reference (go test ./internal/event -run TestSchema -update) -->"
	genEnd       = "<!-- END GENERATED: field reference -->"
	profileBegin = "<!-- BEGIN PROFILE FIELDS -->"
	profileEnd   = "<!-- END PROFILE FIELDS -->"
	// Time.MarshalJSON writes TimeLayout in UTC: six fraction digits and Z.
	timePattern = `^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}Z$`
)

// Untyped string fields that carry a closed vocabulary declared as untyped
// constants (typed fields are matched by their Go type).
var fieldEnums = map[string]string{
	"Event.Type":          "EventType",
	"Detection.Class":     "DetectionClass",
	"Detection.Severity":  "Severity",
	"Check.Severity":      "Severity",
	"Summary.MaxSeverity": "Severity",
}

// Untyped constant groups by name prefix.
var prefixEnums = []struct{ prefix, enum string }{
	{"Type", "EventType"},
	{"Class", "DetectionClass"},
	{"Sev", "Severity"},
}

// ---- facts from the source -------------------------------------------------

type enumValue struct{ Value, Const, Doc string }

type srcFacts struct {
	typeDoc  map[string]string
	fieldDoc map[string]map[string]string
	enums    map[string][]enumValue
	enumDoc  map[string]string
}

func docText(groups ...*ast.CommentGroup) string {
	var parts []string
	for _, g := range groups {
		if g == nil {
			continue
		}
		if s := strings.Join(strings.Fields(g.Text()), " "); s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " ")
}

// specDoc is a constant's comment: its own, or the declaration's when the
// declaration holds only this one spec ("// X is ...\nconst X = ...").
func specDoc(gd *ast.GenDecl, vs *ast.ValueSpec) string {
	doc := docText(vs.Doc, vs.Comment)
	if doc == "" && len(gd.Specs) == 1 {
		doc = docText(gd.Doc)
	}
	return doc
}

func readSourceFacts(t *testing.T) *srcFacts {
	t.Helper()
	f := &srcFacts{
		typeDoc:  map[string]string{},
		fieldDoc: map[string]map[string]string{},
		enums:    map[string][]enumValue{},
		enumDoc: map[string]string{
			"EventType":      "Event.Type: the activity types (Kind activity) and the types of the other kinds. detection.context is declared in internal/privacy.",
			"DetectionClass": "Detection classes, lowest to highest (ClassRank).",
			"Severity":       "Severity levels, lowest to highest (SeverityRank).",
		},
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	fset := token.NewFileSet()
	var parsed []*ast.File
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if err != nil {
			t.Fatal(err)
		}
		parsed = append(parsed, af)
	}
	// Types first, so typed constants know which types are enums.
	named := map[string]bool{}
	for _, af := range parsed {
		for _, d := range af.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, sp := range gd.Specs {
				ts := sp.(*ast.TypeSpec)
				doc := docText(ts.Doc)
				if doc == "" && len(gd.Specs) == 1 {
					doc = docText(gd.Doc)
				}
				f.typeDoc[ts.Name.Name] = doc
				switch st := ts.Type.(type) {
				case *ast.StructType:
					fd := map[string]string{}
					for _, fl := range st.Fields.List {
						for _, n := range fl.Names {
							fd[n.Name] = docText(fl.Doc, fl.Comment)
						}
					}
					f.fieldDoc[ts.Name.Name] = fd
				case *ast.Ident:
					if st.Name == "string" {
						named[ts.Name.Name] = true
					}
				}
			}
		}
	}
	for _, af := range parsed {
		for _, d := range af.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			for _, sp := range gd.Specs {
				vs := sp.(*ast.ValueSpec)
				for i, n := range vs.Names {
					if i >= len(vs.Values) {
						continue
					}
					lit, ok := vs.Values[i].(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					val, err := strconv.Unquote(lit.Value)
					if err != nil {
						t.Fatal(err)
					}
					v := enumValue{Value: val, Const: n.Name, Doc: specDoc(gd, vs)}
					if id, ok := vs.Type.(*ast.Ident); ok {
						if named[id.Name] {
							f.enums[id.Name] = append(f.enums[id.Name], v)
							if f.enumDoc[id.Name] == "" {
								f.enumDoc[id.Name] = f.typeDoc[id.Name]
							}
						}
						continue
					}
					if vs.Type != nil {
						continue
					}
					for _, p := range prefixEnums {
						if strings.HasPrefix(n.Name, p.prefix) {
							f.enums[p.enum] = append(f.enums[p.enum], v)
							break
						}
					}
				}
			}
		}
	}
	// detection.context, from internal/privacy.
	af, err := parser.ParseFile(fset, privacyContextSrc, nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, d := range af.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, sp := range gd.Specs {
			vs := sp.(*ast.ValueSpec)
			for i, id := range vs.Names {
				if id.Name != "TypeContext" || i >= len(vs.Values) {
					continue
				}
				if lit, ok := vs.Values[i].(*ast.BasicLit); ok && lit.Kind == token.STRING {
					val, _ := strconv.Unquote(lit.Value)
					f.enums["EventType"] = append(f.enums["EventType"], enumValue{Value: val, Const: "privacy.TypeContext", Doc: specDoc(gd, vs)})
					found = true
				}
			}
		}
	}
	if !found {
		t.Fatalf("%s: const TypeContext not found", privacyContextSrc)
	}
	return f
}

// ---- schema generation ------------------------------------------------------

// jobj is a JSON object that keeps its key order, so the generated file is
// stable and reads in Go field order.
type jobj struct {
	keys []string
	vals map[string]any
}

func newObj() *jobj { return &jobj{vals: map[string]any{}} }

func (o *jobj) set(k string, v any) *jobj {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
	return o
}

func (o *jobj) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, err := marshalNoHTML(k)
		if err != nil {
			return nil, err
		}
		b.Write(kb)
		b.WriteByte(':')
		vb, err := marshalNoHTML(o.vals[k])
		if err != nil {
			return nil, err
		}
		b.Write(vb)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

func marshalNoHTML(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}

type fieldInfo struct {
	Go, JSON string
	Type     reflect.Type
	Required bool // no omitempty/omitzero: always written
	Doc      string
	Enum     string // closed vocabulary of an untyped string field
}

type schemaGen struct {
	t     *testing.T
	src   *srcFacts
	defs  map[string]*jobj
	order []string // struct defs in first-reference order (for the doc)
	enums []string // enums in first-reference order
	seen  map[string]bool
}

var (
	timeType  = reflect.TypeOf(Time{})
	eventPath = reflect.TypeOf(Event{}).PkgPath()
)

// fields lists the JSON fields of a struct type.
func (g *schemaGen) fields(t reflect.Type) []fieldInfo {
	var out []fieldInfo
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		if !sf.IsExported() {
			continue
		}
		tag := sf.Tag.Get("json")
		if tag == "-" {
			continue
		}
		if sf.Anonymous {
			g.t.Fatalf("%s.%s: embedded fields are not supported by the schema generator", t.Name(), sf.Name)
		}
		name, opts, _ := strings.Cut(tag, ",")
		if name == "" {
			name = sf.Name
		}
		req := true
		for _, o := range strings.Split(opts, ",") {
			if o == "omitempty" || o == "omitzero" {
				req = false
			}
		}
		out = append(out, fieldInfo{
			Go: sf.Name, JSON: name, Type: sf.Type, Required: req,
			Doc:  g.src.fieldDoc[t.Name()][sf.Name],
			Enum: fieldEnums[t.Name()+"."+sf.Name],
		})
	}
	return out
}

func ref(name string) *jobj { return newObj().set("$ref", "#/$defs/"+name) }

func (g *schemaGen) enumRef(name string) *jobj {
	vals := g.src.enums[name]
	if len(vals) == 0 {
		g.t.Fatalf("closed vocabulary %s has no constants in internal/event", name)
	}
	if !g.seen["enum:"+name] {
		g.seen["enum:"+name] = true
		g.enums = append(g.enums, name)
		e := make([]string, len(vals))
		for i, v := range vals {
			e[i] = v.Value
		}
		d := newObj().set("type", "string")
		if doc := g.src.enumDoc[name]; doc != "" {
			d.set("description", doc)
		}
		d.set("enum", e)
		g.defs[name] = d
	}
	return ref(name)
}

func (g *schemaGen) schemaFor(t reflect.Type, enum string) *jobj {
	if enum != "" {
		return g.enumRef(enum)
	}
	if t == timeType {
		if !g.seen["Time"] {
			g.seen["Time"] = true
			g.defs["Time"] = newObj().
				set("type", "string").
				set("description", "RFC 3339 in UTC with exactly six fraction digits (TimeLayout), the form Fluent Bit's strict parser needs. Optional time fields are left out when unset.").
				set("format", "date-time").
				set("pattern", timePattern)
		}
		return ref("Time")
	}
	switch t.Kind() {
	case reflect.String:
		if t.PkgPath() == eventPath && t.Name() != "" && len(g.src.enums[t.Name()]) > 0 {
			return g.enumRef(t.Name())
		}
		return newObj().set("type", "string")
	case reflect.Bool:
		return newObj().set("type", "boolean")
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return newObj().set("type", "integer")
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return newObj().set("type", "integer").set("minimum", 0)
	case reflect.Float32, reflect.Float64:
		return newObj().set("type", "number")
	case reflect.Pointer:
		return g.schemaFor(t.Elem(), "")
	case reflect.Slice:
		return newObj().set("type", "array").set("items", g.schemaFor(t.Elem(), ""))
	case reflect.Map:
		if t.Key().Kind() != reflect.String {
			g.t.Fatalf("map %s: only string keys encode as JSON objects", t)
		}
		o := newObj().set("type", "object")
		if t.Elem().Kind() != reflect.Interface {
			o.set("additionalProperties", g.schemaFor(t.Elem(), ""))
		}
		return o
	case reflect.Interface:
		return newObj() // any JSON value
	case reflect.Struct:
		g.structDef(t)
		return ref(t.Name())
	}
	g.t.Fatalf("type %s (%s) is not supported by the schema generator", t, t.Kind())
	return nil
}

func (g *schemaGen) structDef(t reflect.Type) {
	name := t.Name()
	if g.seen[name] {
		return
	}
	g.seen[name] = true
	g.order = append(g.order, name)
	d := newObj().set("type", "object")
	g.defs[name] = d // before the fields: a recursive type must find it
	if doc := g.src.typeDoc[name]; doc != "" {
		d.set("description", doc)
	}
	props := newObj()
	var req []string
	for _, f := range g.fields(t) {
		p := g.schemaFor(f.Type, f.Enum)
		k := f.Type.Kind()
		if f.Required && (k == reflect.Pointer || k == reflect.Slice || k == reflect.Map) {
			// A nil value of a field without omitempty encodes as null.
			p = newObj().set("anyOf", []any{p, newObj().set("type", "null")})
		}
		if name == "Event" && f.Go == "V" {
			p = newObj().set("type", "integer").set("const", SchemaVersion)
		}
		if f.Doc != "" {
			p.set("description", f.Doc)
		}
		props.set(f.JSON, p)
		if f.Required {
			req = append(req, f.JSON)
		}
	}
	d.set("properties", props)
	if len(req) > 0 {
		d.set("required", req)
	}
	d.set("additionalProperties", false)
}

// generateSchema returns the schema document and the generator state.
func generateSchema(t *testing.T) ([]byte, *schemaGen) {
	t.Helper()
	g := &schemaGen{t: t, src: readSourceFacts(t), defs: map[string]*jobj{}, seen: map[string]bool{}}
	g.structDef(reflect.TypeOf(Event{}))

	// The content-free stand-in the privacy stage and the sinks write when a
	// record cannot be redacted or cut to the line cap.
	g.defs["Skeleton"] = newObj().
		set("type", "object").
		set("description", "Content-free stand-in written when redaction failed or a record could not be brought under the line cap (internal/privacy, internal/sink). It keeps the Event layout and its routing fields, its truncated list contains \"*\" and, when the privacy stage wrote it, a label names the reason (privacy_error or line_cap). Its string values may be clipped, so only the marker and the routing fields are checked here.").
		set("properties", newObj().
			set("v", newObj().set("type", "integer").set("const", SchemaVersion)).
			set("id", newObj().set("type", "string")).
			set("ts", ref("Time")).
			set("kind", newObj().set("type", "string")).
			set("type", newObj().set("type", "string")).
			set("source", newObj().set("type", "string")).
			set("truncated", newObj().set("type", "array").set("items", newObj().set("type", "string")).set("contains", newObj().set("const", "*")))).
		set("required", []string{"v", "id", "ts", "kind", "type", "source", "truncated"})

	names := make([]string, 0, len(g.defs))
	for n := range g.defs {
		names = append(names, n)
	}
	sort.Strings(names)
	defs := newObj()
	for _, n := range names {
		defs.set(n, g.defs[n])
	}
	root := newObj().
		set("$schema", "https://json-schema.org/draft/2020-12/schema").
		set("title", "spoor event record").
		set("description", fmt.Sprintf("One NDJSON line written by spoor (outbox segments, local ring, stdout, spoor detect --ndjson). Schema version %d (field v). Generated from internal/event by `go test ./internal/event -run TestSchema -update`; do not edit by hand. Reference: docs/EVENTS.md.", SchemaVersion)).
		set("anyOf", []any{ref("Event"), ref("Skeleton")}).
		set("$defs", defs)
	b, err := marshalNoHTML(root)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := json.Indent(&out, b, "", "  "); err != nil {
		t.Fatal(err)
	}
	out.WriteByte('\n')
	return out.Bytes(), g
}

// ---- validation -------------------------------------------------------------

// validator checks a decoded JSON value (json.Decoder.UseNumber) against
// the subset of JSON Schema 2020-12 the generator emits. Only local $refs
// ("#/$defs/<name>") are resolved.
type validator struct {
	root map[string]any
	re   map[string]*regexp.Regexp
}

var knownKeywords = map[string]bool{
	"$schema": true, "$defs": true, "title": true, "description": true, "$comment": true,
	"format": true, // annotation only; date-time is enforced by pattern
	"$ref":   true, "anyOf": true, "type": true, "const": true, "enum": true,
	"pattern": true, "minimum": true, "properties": true, "required": true,
	"additionalProperties": true, "items": true, "contains": true,
}

func newValidator(schema []byte) (*validator, error) {
	var root map[string]any
	dec := json.NewDecoder(bytes.NewReader(schema))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return nil, err
	}
	return &validator{root: root, re: map[string]*regexp.Regexp{}}, nil
}

func (v *validator) Validate(x any) []string {
	return v.check(v.root, x, "", 0)
}

func (v *validator) check(s any, x any, path string, depth int) []string {
	at := path
	if at == "" {
		at = "(record)"
	}
	if depth > 64 {
		return []string{at + ": schema nesting too deep"}
	}
	switch sb := s.(type) {
	case bool:
		if sb {
			return nil
		}
		return []string{at + ": not allowed"}
	case map[string]any:
	default:
		return []string{at + ": invalid schema node"}
	}
	sm := s.(map[string]any)
	keys := make([]string, 0, len(sm))
	for k := range sm {
		if !knownKeywords[k] {
			return []string{fmt.Sprintf("%s: schema keyword %q is not implemented by the validator", at, k)}
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var errs []string
	for _, k := range keys {
		kw := sm[k]
		switch k {
		case "$ref":
			name, ok := strings.CutPrefix(kw.(string), "#/$defs/")
			defs, _ := v.root["$defs"].(map[string]any)
			def, found := defs[name]
			if !ok || !found {
				errs = append(errs, fmt.Sprintf("%s: unresolvable $ref %v", at, kw))
				continue
			}
			errs = append(errs, v.check(def, x, path, depth+1)...)
		case "anyOf":
			var branchErrs []string
			matched := false
			for i, b := range kw.([]any) {
				e := v.check(b, x, path, depth+1)
				if len(e) == 0 {
					matched = true
					break
				}
				branchErrs = append(branchErrs, fmt.Sprintf("[branch %d: %s]", i, strings.Join(e, "; ")))
			}
			if !matched {
				errs = append(errs, fmt.Sprintf("%s: no anyOf branch matched %s", at, strings.Join(branchErrs, " ")))
			}
		case "type":
			var types []string
			switch tv := kw.(type) {
			case string:
				types = []string{tv}
			case []any:
				for _, e := range tv {
					types = append(types, e.(string))
				}
			}
			ok := false
			for _, ty := range types {
				ok = ok || hasJSONType(x, ty)
			}
			if !ok {
				errs = append(errs, fmt.Sprintf("%s: %s is not of type %s", at, jsonTypeName(x), strings.Join(types, "|")))
			}
		case "const":
			if !jsonEqual(kw, x) {
				errs = append(errs, fmt.Sprintf("%s: %s, want %v", at, short(x), kw))
			}
		case "enum":
			ok := false
			for _, e := range kw.([]any) {
				ok = ok || jsonEqual(e, x)
			}
			if !ok {
				errs = append(errs, fmt.Sprintf("%s: %s is not in the closed vocabulary", at, short(x)))
			}
		case "pattern":
			str, isStr := x.(string)
			if !isStr {
				continue
			}
			p := kw.(string)
			re := v.re[p]
			if re == nil {
				var err error
				if re, err = regexp.Compile(p); err != nil {
					errs = append(errs, fmt.Sprintf("%s: bad pattern: %v", at, err))
					continue
				}
				v.re[p] = re
			}
			if !re.MatchString(str) {
				errs = append(errs, fmt.Sprintf("%s: %s does not match %s", at, short(x), p))
			}
		case "minimum":
			n, isNum := x.(json.Number)
			if !isNum {
				continue
			}
			got, ok1 := new(big.Rat).SetString(n.String())
			lim, ok2 := new(big.Rat).SetString(fmt.Sprint(kw))
			if !ok1 || !ok2 || got.Cmp(lim) < 0 {
				errs = append(errs, fmt.Sprintf("%s: %s is below the minimum %v", at, n, kw))
			}
		case "properties", "required", "additionalProperties":
			obj, isObj := x.(map[string]any)
			if !isObj {
				continue
			}
			props, _ := sm["properties"].(map[string]any)
			switch k {
			case "properties":
				names := make([]string, 0, len(obj))
				for name := range obj {
					names = append(names, name)
				}
				sort.Strings(names)
				for _, name := range names {
					if ps, ok := props[name]; ok {
						errs = append(errs, v.check(ps, obj[name], joinPath(path, name), depth+1)...)
					}
				}
			case "required":
				for _, r := range kw.([]any) {
					if _, ok := obj[r.(string)]; !ok {
						errs = append(errs, fmt.Sprintf("%s: required field %q is missing", at, r))
					}
				}
			case "additionalProperties":
				names := make([]string, 0, len(obj))
				for name := range obj {
					if _, ok := props[name]; !ok {
						names = append(names, name)
					}
				}
				sort.Strings(names)
				for _, name := range names {
					if b, isBool := kw.(bool); isBool && !b {
						errs = append(errs, fmt.Sprintf("%s: field %q is not part of the schema", at, name))
						continue
					}
					errs = append(errs, v.check(kw, obj[name], joinPath(path, name), depth+1)...)
				}
			}
		case "items":
			arr, isArr := x.([]any)
			if !isArr {
				continue
			}
			for i, e := range arr {
				errs = append(errs, v.check(kw, e, fmt.Sprintf("%s[%d]", path, i), depth+1)...)
			}
		case "contains":
			arr, isArr := x.([]any)
			if !isArr {
				continue
			}
			ok := false
			for _, e := range arr {
				ok = ok || len(v.check(kw, e, path, depth+1)) == 0
			}
			if !ok {
				errs = append(errs, fmt.Sprintf("%s: no element matches %s", at, short(kw)))
			}
		}
	}
	return errs
}

func joinPath(p, k string) string {
	if p == "" {
		return k
	}
	return p + "." + k
}

func hasJSONType(x any, ty string) bool {
	switch ty {
	case "object":
		_, ok := x.(map[string]any)
		return ok
	case "array":
		_, ok := x.([]any)
		return ok
	case "string":
		_, ok := x.(string)
		return ok
	case "boolean":
		_, ok := x.(bool)
		return ok
	case "null":
		return x == nil
	case "number":
		_, ok := x.(json.Number)
		return ok
	case "integer":
		n, ok := x.(json.Number)
		if !ok {
			return false
		}
		r, ok := new(big.Rat).SetString(n.String())
		return ok && r.IsInt()
	}
	return false
}

func jsonTypeName(x any) string {
	switch x.(type) {
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string " + short(x)
	case bool:
		return "boolean"
	case json.Number:
		return "number " + short(x)
	case nil:
		return "null"
	}
	return fmt.Sprintf("%T", x)
}

func jsonEqual(a, b any) bool {
	if na, ok := numOf(a); ok {
		nb, ok := numOf(b)
		return ok && na.Cmp(nb) == 0
	}
	switch av := a.(type) {
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !jsonEqual(av[i], bv[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for k, x := range av {
			y, ok := bv[k]
			if !ok || !jsonEqual(x, y) {
				return false
			}
		}
		return true
	}
	return a == b
}

func numOf(x any) (*big.Rat, bool) {
	switch n := x.(type) {
	case json.Number:
		return new(big.Rat).SetString(n.String())
	case float64:
		return new(big.Rat).SetFloat64(n), true
	case int:
		return new(big.Rat).SetInt64(int64(n)), true
	}
	return nil, false
}

func short(x any) string {
	b, _ := json.Marshal(x)
	s := string(b)
	if len(s) > 80 {
		s = s[:80] + "..."
	}
	return s
}

func decodeJSON(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var x any
	if err := dec.Decode(&x); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("trailing data after the JSON value")
	}
	return x, nil
}

// ---- helpers ----------------------------------------------------------------

func readText(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// A Windows checkout may have CRLF line ends; the files are LF.
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

func firstDiff(a, b string) string {
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	for i := 0; i < len(al) || i < len(bl); i++ {
		var x, y string
		if i < len(al) {
			x = al[i]
		}
		if i < len(bl) {
			y = bl[i]
		}
		if x != y {
			return fmt.Sprintf("line %d:\n  committed: %s\n  generated: %s", i+1, x, y)
		}
	}
	return "(none)"
}

type exampleLine struct {
	file string
	line int
	raw  string
	val  any
}

func readExamples(t *testing.T) []exampleLine {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(examplesDir, "*.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatalf("no example records under %s (docs/schema/examples/regen.sh writes them)", examplesDir)
	}
	sort.Strings(files)
	var out []exampleLine
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		n := 0
		for sc.Scan() {
			n++
			raw := strings.TrimRight(sc.Text(), "\r")
			if raw == "" {
				continue
			}
			x, err := decodeJSON([]byte(raw))
			if err != nil {
				t.Errorf("%s:%d: %v", filepath.Base(f), n, err)
				continue
			}
			out = append(out, exampleLine{file: filepath.Base(f), line: n, raw: raw, val: x})
		}
		if err := sc.Err(); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		fh.Close()
	}
	return out
}

func getPath(x any, path ...string) (any, bool) {
	for _, p := range path {
		m, ok := x.(map[string]any)
		if !ok {
			return nil, false
		}
		if x, ok = m[p]; !ok {
			return nil, false
		}
	}
	return x, true
}

// ---- tests ------------------------------------------------------------------

func TestSchemaFileIsGenerated(t *testing.T) {
	got, _ := generateSchema(t)
	if *updateSchema {
		if err := os.MkdirAll(filepath.Dir(schemaFile), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(schemaFile, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want := readText(t, schemaFile)
	if want != string(got) {
		t.Fatalf("docs/schema/event.schema.json is not what internal/event generates; run\n\tgo test ./internal/event -run TestSchema -update\nfirst difference at %s", firstDiff(want, string(got)))
	}
}

func TestSchemaValidatesExampleRecords(t *testing.T) {
	schema, _ := generateSchema(t)
	v, err := newValidator(schema)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	types := map[string]int{}
	for _, ex := range readExamples(t) {
		for _, e := range v.Validate(ex.val) {
			t.Errorf("%s:%d: %s", ex.file, ex.line, e)
		}
		// The Go type reads every field back.
		dec := json.NewDecoder(strings.NewReader(ex.raw))
		dec.DisallowUnknownFields()
		var ev Event
		if err := dec.Decode(&ev); err != nil {
			t.Errorf("%s:%d: decode into event.Event: %v", ex.file, ex.line, err)
			continue
		}
		kinds[string(ev.Kind)]++
		types[ev.Type]++

		// What the profiles promise, checked on the binary's own output.
		prof, _ := getPath(ex.val, "privacy")
		if prof == "minimal" || prof == "standard" {
			for _, p := range [][]string{{"prompt", "text"}, {"tool", "input"}, {"tool", "output"}, {"target", "query"}, {"session", "transcript"}} {
				if _, ok := getPath(ex.val, p...); ok {
					t.Errorf("%s:%d: %s record carries %s", ex.file, ex.line, prof, strings.Join(p, "."))
				}
			}
		}
		if prof == "minimal" && ev.Kind == KindActivity {
			t.Errorf("%s:%d: an activity record in the minimal profile's output", ex.file, ex.line)
		}
	}
	for _, k := range Streams {
		if kinds[k] == 0 {
			t.Errorf("the examples have no %s record: regenerate them (docs/schema/examples/regen.sh)", k)
		}
	}
	t.Logf("validated example records by kind %v, by type %v", kinds, types)
}

// TestSchemaValidatesGivenFiles checks other NDJSON against the schema, for
// example a live outbox: SPOOR_SCHEMA_VALIDATE is a list of files or
// directories (their *.ndjson files) separated by the OS path-list
// separator. Skipped when unset.
func TestSchemaValidatesGivenFiles(t *testing.T) {
	spec := os.Getenv("SPOOR_SCHEMA_VALIDATE")
	if spec == "" {
		t.Skip("set SPOOR_SCHEMA_VALIDATE to files or directories of NDJSON records")
	}
	schema, _ := generateSchema(t)
	v, err := newValidator(schema)
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, p := range filepath.SplitList(spec) {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if !fi.IsDir() {
			files = append(files, p)
			continue
		}
		m, err := filepath.Glob(filepath.Join(p, "*.ndjson"))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	n := 0
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		line := 0
		for sc.Scan() {
			line++
			raw := strings.TrimRight(sc.Text(), "\r")
			if raw == "" {
				continue
			}
			n++
			x, err := decodeJSON([]byte(raw))
			if err != nil {
				t.Errorf("%s:%d: %v", f, line, err)
				continue
			}
			for _, e := range v.Validate(x) {
				t.Errorf("%s:%d: %s", f, line, e)
			}
		}
		if err := sc.Err(); err != nil {
			t.Errorf("%s: %v", f, err)
		}
		fh.Close()
	}
	t.Logf("validated %d records in %d files", n, len(files))
}

func TestSchemaRejectsInvalidRecords(t *testing.T) {
	schema, _ := generateSchema(t)
	v, err := newValidator(schema)
	if err != nil {
		t.Fatal(err)
	}
	ts := At(time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC))
	base := &Event{
		V: SchemaVersion, ID: StableID(ts.Time, "schema-test"), TS: ts, Seq: 3,
		Kind: KindDetection, Type: TypeDetectionFinding, Source: SourceSensor,
		Sources: []Source{SourceHook, SourceTranscript}, Integrity: IntegrityUser,
		Host:      &Host{ID: "h", Name: "devbox", OS: "linux", Arch: "amd64"},
		Tool:      &Tool{Name: "Bash", Kind: ToolShell},
		Prompt:    &Prompt{Len: 16},
		Detection: &Detection{RuleID: "SPR-EXEC-001", Title: "t", Class: ClassFinding, Severity: SevHigh},
		Health:    &Health{SensorVersion: "dev", Mode: "daemon", Counters: map[string]uint64{"events_in": 1}},
		Asset:     &Asset{ID: "a", Kind: AssetAgent, Name: "x"},
		Labels:    map[string]string{"k": "v"},
	}
	line, err := base.MarshalLine()
	if err != nil {
		t.Fatal(err)
	}
	fresh := func() map[string]any {
		x, err := decodeJSON(line)
		if err != nil {
			t.Fatal(err)
		}
		return x.(map[string]any)
	}
	if errs := v.Validate(fresh()); len(errs) > 0 {
		t.Fatalf("the base record does not validate: %v", errs)
	}
	sub := func(m map[string]any, k string) map[string]any { return m[k].(map[string]any) }
	cases := []struct {
		name string
		mut  func(m map[string]any)
	}{
		{"unknown top-level field", func(m map[string]any) { m["extra"] = "x" }},
		{"unknown nested field", func(m map[string]any) { sub(m, "host")["serial"] = "x" }},
		{"kind outside the vocabulary", func(m map[string]any) { m["kind"] = "telemetry" }},
		{"type outside the vocabulary", func(m map[string]any) { m["type"] = "tool.run" }},
		{"source outside the vocabulary", func(m map[string]any) { m["source"] = "cloud" }},
		{"sources element outside the vocabulary", func(m map[string]any) { m["sources"] = []any{"hook", "email"} }},
		{"integrity outside the vocabulary", func(m map[string]any) { m["integrity"] = "kernel" }},
		{"tool kind outside the vocabulary", func(m map[string]any) { sub(m, "tool")["kind"] = "terminal" }},
		{"asset kind outside the vocabulary", func(m map[string]any) { sub(m, "asset")["kind"] = "vm" }},
		{"severity outside the vocabulary", func(m map[string]any) { sub(m, "detection")["severity"] = "urgent" }},
		{"class outside the vocabulary", func(m map[string]any) { sub(m, "detection")["class"] = "page" }},
		{"schema version 2", func(m map[string]any) { m["v"] = json.Number("2") }},
		{"time without fraction", func(m map[string]any) { m["ts"] = "2026-11-12T09:00:00Z" }},
		{"time with an offset", func(m map[string]any) { m["ts"] = "2026-11-12T10:00:00.000000+01:00" }},
		{"time as a number", func(m map[string]any) { m["ts"] = json.Number("1700000000") }},
		{"negative seq", func(m map[string]any) { m["seq"] = json.Number("-1") }},
		{"fractional seq", func(m map[string]any) { m["seq"] = json.Number("1.5") }},
		{"seq as a string", func(m map[string]any) { m["seq"] = "3" }},
		{"missing type", func(m map[string]any) { delete(m, "type") }},
		{"missing id", func(m map[string]any) { delete(m, "id") }},
		{"missing rule id", func(m map[string]any) { delete(sub(m, "detection"), "rule_id") }},
		{"missing prompt length", func(m map[string]any) { delete(sub(m, "prompt"), "len") }},
		{"label value not a string", func(m map[string]any) { sub(m, "labels")["k"] = json.Number("1") }},
		{"negative counter", func(m map[string]any) { sub(sub(m, "health"), "counters")["events_in"] = json.Number("-4") }},
		{"truncated not a list", func(m map[string]any) { m["truncated"] = "target.command" }},
		{"host not an object", func(m map[string]any) { m["host"] = "devbox" }},
		{"null where a value is required", func(m map[string]any) { m["kind"] = nil }},
		{"clipped type without the skeleton marker", func(m map[string]any) { m["type"] = "detectio" }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := fresh()
			c.mut(m)
			if errs := v.Validate(m); len(errs) == 0 {
				t.Fatalf("accepted: %s", short(m))
			}
		})
	}
}

// TestSchemaValidatorHostileInput: the validator is bounded by the schema,
// not by the input, and refuses schemas it cannot fully check.
func TestSchemaValidatorHostileInput(t *testing.T) {
	schema, _ := generateSchema(t)
	v, err := newValidator(schema)
	if err != nil {
		t.Fatal(err)
	}
	nested := func(depth int, leaf string) string {
		return strings.Repeat(`{"a":`, depth) + leaf + strings.Repeat(`}`, depth)
	}
	manyFields := func(n int) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, `,"x%d":1`, i)
		}
		return b.String()
	}
	base := `"v":1,"id":"x","ts":"2026-11-12T09:00:00.000000Z","kind":"activity","type":"tool.pre","source":"hook"`
	cases := []struct {
		name    string
		line    string
		valid   bool
		decodes bool
	}{
		{"deep JSON inside the open tool.input", `{` + base + `,"tool":{"input":` + nested(5000, `"x"`) + `}}`, true, true},
		{"deep JSON where labels want strings", `{` + base + `,"labels":` + nested(5000, `"x"`) + `}`, false, true},
		{"a 1 MiB command", `{` + base + `,"target":{"command":"` + strings.Repeat("A", 1<<20) + `"}}`, true, true},
		{"invalid UTF-8 in a string", `{` + base + `,"target":{"command":"` + "\xff\xfe" + `"}}`, true, true},
		{"an unknown field", `{` + base + `,"x":1}`, false, true},
		{"10,000 unknown fields", `{` + base + manyFields(10000) + `}`, false, true},
		{"trailing data", `{` + base + `} {}`, false, false},
		{"not an object", `[1,2,3]`, false, true},
		{"null", `null`, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			start := time.Now()
			x, err := decodeJSON([]byte(c.line))
			if (err == nil) != c.decodes {
				t.Fatalf("decode error %v, want decodes=%v", err, c.decodes)
			}
			if err != nil {
				return
			}
			errs := v.Validate(x)
			if (len(errs) == 0) != c.valid {
				t.Fatalf("valid=%v, want %v: %v", len(errs) == 0, c.valid, errs)
			}
			if d := time.Since(start); d > 5*time.Second {
				t.Fatalf("took %v", d)
			}
		})
	}

	// A schema the validator cannot fully check is an error, never a pass.
	for name, s := range map[string]string{
		"unknown keyword": `{"type":"object","maxProperties":1}`,
		"ref cycle":       `{"$defs":{"A":{"$ref":"#/$defs/A"}},"$ref":"#/$defs/A"}`,
		"dangling ref":    `{"$ref":"#/$defs/Missing"}`,
		"remote ref":      `{"$ref":"https://example.com/s.json"}`,
	} {
		v, err := newValidator([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		if errs := v.Validate(map[string]any{}); len(errs) == 0 {
			t.Errorf("%s: schema %s accepted a record", name, s)
		}
	}
}

func TestSchemaAcceptsSkeletons(t *testing.T) {
	schema, _ := generateSchema(t)
	v, err := newValidator(schema)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		// internal/sink: identity only, strings clipped to a safe subset.
		`{"v":1,"id":"01a1cefe-efcc-8941-bb24-f6e74ac7821e","ts":"2026-11-12T09:02:56.460197Z","seq":4,"kind":"activity","type":"tool.pre","source":"hook","privacy":"standard","truncated":["*"],"host":{"id":"h","name":"devbox","os":"linux","arch":"amd64"}}`,
		// internal/privacy routing-only fallback: no id or type survived.
		`{"v":1,"id":"","ts":"2026-11-12T09:02:56.460197Z","kind":"detection","type":"","source":"","privacy":"minimal","truncated":["*"],"labels":{"line_cap":"true"}}`,
		// a value clipped by the per-value budget
		`{"v":1,"id":"x","ts":"2026-11-12T09:02:56.460197Z","kind":"detection","type":"detectio","source":"sensor","privacy":"minimal","truncated":["*"],"labels":{"privacy_error":"true"}}`,
	} {
		x, err := decodeJSON([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		if errs := v.Validate(x); len(errs) > 0 {
			t.Errorf("skeleton rejected: %v\n%s", errs, s)
		}
	}
}

// fill sets every field reachable from v to a non-zero value the encoder
// writes, picking the first value of a closed vocabulary.
func fill(t *testing.T, g *schemaGen, v reflect.Value, enum string) {
	switch v.Kind() {
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		fill(t, g, v.Elem(), enum)
	case reflect.Struct:
		if v.Type() == timeType {
			v.Set(reflect.ValueOf(At(time.Date(2026, 11, 12, 9, 0, 0, 123456000, time.UTC))))
			return
		}
		for _, f := range g.fields(v.Type()) {
			fill(t, g, v.FieldByName(f.Go), f.Enum)
		}
	case reflect.String:
		name := enum
		if name == "" && v.Type().PkgPath() == eventPath {
			name = v.Type().Name()
		}
		if vals := g.src.enums[name]; len(vals) > 0 {
			v.SetString(vals[0].Value)
		} else {
			v.SetString("x")
		}
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int64, reflect.Int32:
		v.SetInt(1)
	case reflect.Uint, reflect.Uint64, reflect.Uint32:
		v.SetUint(1)
	case reflect.Float64:
		v.SetFloat(1.5)
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 1, 1)
		fill(t, g, s.Index(0), "")
		v.Set(s)
	case reflect.Map:
		m := reflect.MakeMap(v.Type())
		e := reflect.New(v.Type().Elem()).Elem()
		if e.Kind() == reflect.Interface {
			e.Set(reflect.ValueOf("x"))
		} else {
			fill(t, g, e, "")
		}
		m.SetMapIndex(reflect.ValueOf("k"), e)
		v.Set(m)
	case reflect.Interface:
		v.Set(reflect.ValueOf("x"))
	default:
		t.Fatalf("fill: unsupported kind %s", v.Kind())
	}
}

// TestSchemaMatchesTheEncoder fills every field of an Event, encodes it with
// MarshalLine and requires that the record validates and that the schema
// declares exactly the keys the encoder wrote, object by object.
func TestSchemaMatchesTheEncoder(t *testing.T) {
	schema, g := generateSchema(t)
	v, err := newValidator(schema)
	if err != nil {
		t.Fatal(err)
	}
	var ev Event
	fill(t, g, reflect.ValueOf(&ev).Elem(), "")
	ev.V = SchemaVersion
	ev.Content = &Content{PromptText: "local only"}
	ev.Feat = map[string]any{"local": true}
	line, err := ev.MarshalLine()
	if err != nil {
		t.Fatal(err)
	}
	x, err := decodeJSON(line)
	if err != nil {
		t.Fatal(err)
	}
	if errs := v.Validate(x); len(errs) > 0 {
		t.Fatalf("a fully populated record does not validate: %v", errs)
	}
	defs := v.root["$defs"].(map[string]any)
	var walk func(def string, obj map[string]any, path string)
	walk = func(def string, obj map[string]any, path string) {
		props := defs[def].(map[string]any)["properties"].(map[string]any)
		for k := range obj {
			if _, ok := props[k]; !ok {
				t.Errorf("%s: the encoder wrote %q, the schema does not declare it", def, joinPath(path, k))
			}
		}
		for k, p := range props {
			val, ok := obj[k]
			if !ok {
				t.Errorf("%s: the schema declares %q, the encoder never wrote it", def, joinPath(path, k))
				continue
			}
			pm := p.(map[string]any)
			if r, ok := pm["$ref"].(string); ok {
				if sub, ok := val.(map[string]any); ok {
					walk(strings.TrimPrefix(r, "#/$defs/"), sub, joinPath(path, k))
				}
			}
			if items, ok := pm["items"].(map[string]any); ok {
				if r, ok := items["$ref"].(string); ok {
					if arr, ok := val.([]any); ok && len(arr) > 0 {
						if sub, ok := arr[0].(map[string]any); ok {
							walk(strings.TrimPrefix(r, "#/$defs/"), sub, joinPath(path, k)+"[0]")
						}
					}
				}
			}
		}
	}
	walk("Event", x.(map[string]any), "")
}

// TestSchemaVocabulariesMatchTheCode cross-checks what go/ast read from the
// source with the compiled package.
func TestSchemaVocabulariesMatchTheCode(t *testing.T) {
	src := readSourceFacts(t)
	vals := func(name string) []string {
		var out []string
		for _, v := range src.enums[name] {
			out = append(out, v.Value)
		}
		sort.Strings(out)
		return out
	}
	streams := append([]string(nil), Streams...)
	sort.Strings(streams)
	if got := vals("Kind"); !reflect.DeepEqual(got, streams) {
		t.Errorf("Kind constants %v, Streams %v", got, streams)
	}
	for _, k := range src.enums["Kind"] {
		if Kind(k.Value).Stream() != k.Value {
			t.Errorf("kind %s writes to stream %s", k.Value, Kind(k.Value).Stream())
		}
	}
	if got := vals("Severity"); len(got) != 5 {
		t.Errorf("severities %v", got)
	}
	for _, s := range src.enums["Severity"] {
		if SeverityRank(s.Value) == 0 {
			t.Errorf("severity %s has no rank", s.Value)
		}
	}
	want := map[string]int{ClassSignal: 1, ClassFinding: 2, ClassAlert: 3}
	if got := vals("DetectionClass"); len(got) != len(want) {
		t.Errorf("classes %v", got)
	}
	for _, c := range src.enums["DetectionClass"] {
		if ClassRank(c.Value) != want[c.Value] {
			t.Errorf("class %s ranks %d", c.Value, ClassRank(c.Value))
		}
	}
	for _, typ := range []string{TypeSessionStart, TypeToolPre, TypePayloadAnomaly, TypeInventoryAsset, TypePostureCheck,
		TypeDetectionFinding, TypeHealthHeartbeat, TypeHealthError, TypeSessionSummary, "detection.context"} {
		found := false
		for _, v := range src.enums["EventType"] {
			found = found || v.Value == typ
		}
		if !found {
			t.Errorf("type %s missing from the EventType vocabulary", typ)
		}
	}
	for _, name := range []string{"Source", "Fidelity", "Integrity", "ToolKind", "AssetKind", "Scope", "Change"} {
		if len(src.enums[name]) == 0 {
			t.Errorf("no constants found for %s", name)
		}
	}
}

// ---- docs/EVENTS.md ---------------------------------------------------------

func mdEscape(s string) string {
	r := strings.NewReplacer("|", `\|`, "<", "&lt;", ">", "&gt;", "\n", " ")
	return r.Replace(s)
}

func (g *schemaGen) mdType(t reflect.Type, enum string) string {
	if enum != "" {
		return fmt.Sprintf("[`%s`](#%s-values)", enum, strings.ToLower(enum))
	}
	if t == timeType {
		return "[`Time`](#time-string)"
	}
	switch t.Kind() {
	case reflect.String:
		if t.PkgPath() == eventPath && len(g.src.enums[t.Name()]) > 0 {
			return fmt.Sprintf("[`%s`](#%s-values)", t.Name(), strings.ToLower(t.Name()))
		}
		return "string"
	case reflect.Bool:
		return "boolean"
	case reflect.Int, reflect.Int64, reflect.Int32:
		return "integer"
	case reflect.Uint, reflect.Uint64, reflect.Uint32:
		return "integer ≥ 0"
	case reflect.Float64:
		return "number"
	case reflect.Pointer:
		return g.mdType(t.Elem(), "")
	case reflect.Slice:
		return "array of " + g.mdType(t.Elem(), "")
	case reflect.Map:
		if t.Elem().Kind() == reflect.Interface {
			return "object (any JSON)"
		}
		return "object of " + g.mdType(t.Elem(), "")
	case reflect.Struct:
		return fmt.Sprintf("[`%s`](#%s-object)", t.Name(), strings.ToLower(t.Name()))
	}
	return t.String()
}

func (g *schemaGen) fieldReference() string {
	var b strings.Builder
	b.WriteString(genBegin + "\n\n")
	b.WriteString("Generated from the Go types in `internal/event` and their doc comments. \"always\" fields are written on every record of that object (an empty string or zero when unset); the others are left out when empty.\n\n")
	for _, name := range g.order {
		t := g.structType(name)
		fmt.Fprintf(&b, "### `%s` object\n\n", name)
		if doc := g.src.typeDoc[name]; doc != "" {
			b.WriteString(mdEscape(doc) + "\n\n")
		}
		b.WriteString("| Field | Type | Present | Description |\n|---|---|---|---|\n")
		for _, f := range g.fields(t) {
			ty := g.mdType(f.Type, f.Enum)
			doc := f.Doc
			if name == "Event" && f.Go == "V" {
				ty = "integer"
				doc = fmt.Sprintf("Schema version, %d (SchemaVersion). Bumped only on breaking changes; adding optional fields is not breaking.", SchemaVersion)
			}
			present := "when set"
			if f.Required {
				present = "always"
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", f.JSON, ty, present, mdEscape(doc))
		}
		b.WriteString("\n")
	}
	b.WriteString("### `Time` string\n\n")
	b.WriteString("RFC 3339 in UTC with exactly six fraction digits, for example `2026-11-12T09:02:56.460197Z` (`TimeLayout`; Fluent Bit's strict parser needs the fraction). Optional time fields are left out when unset.\n\n")
	for _, name := range g.enums {
		fmt.Fprintf(&b, "### `%s` values\n\n", name)
		if doc := g.src.enumDoc[name]; doc != "" {
			b.WriteString(mdEscape(doc) + "\n\n")
		}
		b.WriteString("| Value | Constant | Meaning |\n|---|---|---|\n")
		for _, v := range g.src.enums[name] {
			fmt.Fprintf(&b, "| `%s` | `%s` | %s |\n", v.Value, v.Const, mdEscape(v.Doc))
		}
		b.WriteString("\n")
	}
	b.WriteString(genEnd)
	return b.String()
}

// structType finds a struct type reachable from Event by name.
func (g *schemaGen) structType(name string) reflect.Type {
	var found reflect.Type
	seen := map[reflect.Type]bool{}
	var walk func(t reflect.Type)
	walk = func(t reflect.Type) {
		for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Map {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct || seen[t] || found != nil {
			return
		}
		seen[t] = true
		if t.Name() == name {
			found = t
			return
		}
		for i := 0; i < t.NumField(); i++ {
			walk(t.Field(i).Type)
		}
	}
	walk(reflect.TypeOf(Event{}))
	if found == nil {
		g.t.Fatalf("struct %s not reachable from Event", name)
	}
	return found
}

func TestSchemaFieldReferenceInEventsDoc(t *testing.T) {
	_, g := generateSchema(t)
	doc := readText(t, eventsDoc)
	i := strings.Index(doc, genBegin)
	j := strings.Index(doc, genEnd)
	if i < 0 || j < i {
		t.Fatalf("docs/EVENTS.md has no generated field reference between %q and %q", genBegin, genEnd)
	}
	want := g.fieldReference()
	cur := doc[i : j+len(genEnd)]
	if cur == want {
		return
	}
	if *updateSchema {
		if err := os.WriteFile(eventsDoc, []byte(doc[:i]+want+doc[j+len(genEnd):]), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatalf("the field reference in docs/EVENTS.md is stale; run\n\tgo test ./internal/event -run TestSchema -update\nfirst difference at %s", firstDiff(cur, want))
}

// TestSchemaProfileTableNamesRealFields keeps the hand-written profile table
// in docs/EVENTS.md honest about field names.
func TestSchemaProfileTableNamesRealFields(t *testing.T) {
	schema, _ := generateSchema(t)
	v, err := newValidator(schema)
	if err != nil {
		t.Fatal(err)
	}
	defs := v.root["$defs"].(map[string]any)
	resolve := func(path string) bool {
		def := "Event"
		parts := strings.Split(path, ".")
		for i, p := range parts {
			props, _ := defs[def].(map[string]any)["properties"].(map[string]any)
			ps, ok := props[p].(map[string]any)
			if !ok {
				return false
			}
			if i == len(parts)-1 {
				return true
			}
			if it, ok := ps["items"].(map[string]any); ok {
				ps = it
			}
			r, ok := ps["$ref"].(string)
			if !ok {
				return false
			}
			def = strings.TrimPrefix(r, "#/$defs/")
		}
		return false
	}
	doc := readText(t, eventsDoc)
	i, j := strings.Index(doc, profileBegin), strings.Index(doc, profileEnd)
	if i < 0 || j < i {
		t.Fatalf("docs/EVENTS.md has no profile table between %q and %q", profileBegin, profileEnd)
	}
	rows := 0
	cell := regexp.MustCompile("^\\| `([a-z0-9_.]+)`")
	for _, l := range strings.Split(doc[i:j], "\n") {
		m := cell.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		rows++
		if !resolve(m[1]) {
			t.Errorf("profile table names %q, which is not a field of the record", m[1])
		}
	}
	if rows == 0 {
		t.Fatal("the profile table has no field rows")
	}
}

// TestSchemaDocExamplesAreReal requires every example record quoted in
// docs/EVENTS.md (a ```json block after an "<!-- example: <file> -->"
// comment) to be one of the lines the binary wrote under
// docs/schema/examples, value for value.
func TestSchemaDocExamplesAreReal(t *testing.T) {
	doc := readText(t, eventsDoc)
	re := regexp.MustCompile("(?s)<!-- example: ([a-z0-9_.-]+\\.ndjson) -->\\s*```json\\n(.*?)\\n```")
	ms := re.FindAllStringSubmatch(doc, -1)
	if len(ms) < 3 {
		t.Fatalf("docs/EVENTS.md quotes %d example records, want at least 3", len(ms))
	}
	byFile := map[string][]exampleLine{}
	for _, ex := range readExamples(t) {
		byFile[ex.file] = append(byFile[ex.file], ex)
	}
	for _, m := range ms {
		x, err := decodeJSON([]byte(m[2]))
		if err != nil {
			t.Errorf("example from %s is not JSON: %v", m[1], err)
			continue
		}
		found := false
		for _, ex := range byFile[m[1]] {
			if jsonEqual(ex.val, x) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("the example quoted from %s is not a line of that file: %s", m[1], short(x))
		}
	}
}
