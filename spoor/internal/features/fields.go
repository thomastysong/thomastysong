package features

import (
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/thomastysong/spoor/internal/event"
)

// The flattened view is derived from the event struct itself (JSON names,
// omitempty semantics) so that a field added to internal/event becomes
// matchable, and known to the lint registry, without a change here.

type valueKind uint8

const (
	vString valueKind = iota
	vBool
	vNum
	vStrings
	vTime
	vPtrBool
	vPtrNum
	vStringMap // map[string]string: one entry per key, "prefix.key"
	vNumMap    // map[string]<int|uint>: one entry per key, value float64
)

type accessor struct {
	name      string
	index     []int // field path below the top-level field; pointers are followed
	kind      valueKind
	omitempty bool
}

// group holds the accessors below one top-level Event field, so a nil
// sub-struct (most of them on any given event) costs one check.
type group struct {
	top  int // index in event.Event
	ptr  bool
	accs []accessor
}

type plan struct {
	groups []group
	// names maps every flattened name (and "prefix.*" for map fields) to its
	// registry type.
	names map[string]Type
}

var (
	planOnce sync.Once
	thePlan  plan
)

func eventPlan() *plan {
	planOnce.Do(func() {
		thePlan = buildPlan()
	})
	return &thePlan
}

var timeType = reflect.TypeOf(event.Time{})

func buildPlan() plan {
	p := plan{names: map[string]Type{}}
	t := reflect.TypeOf(event.Event{})
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		name, omit, ok := jsonName(f)
		if !ok {
			continue
		}
		g := group{top: i}
		ft := f.Type
		if ft.Kind() == reflect.Pointer && ft.Elem().Kind() == reflect.Struct && ft.Elem() != timeType {
			g.ptr = true
			collect(ft.Elem(), name+".", nil, &g.accs, 0)
		} else if a, ok := leafAccessor(ft, name, []int{i}, omit); ok {
			g.accs = append(g.accs, a)
		}
		if len(g.accs) > 0 {
			p.groups = append(p.groups, g)
		}
	}
	for _, g := range p.groups {
		for _, a := range g.accs {
			switch a.kind {
			case vStringMap:
				p.names[a.name+".*"] = TypeString
			case vNumMap:
				p.names[a.name+".*"] = TypeNumber
			default:
				p.names[a.name] = kindType(a.kind)
			}
		}
	}
	return p
}

func kindType(k valueKind) Type {
	switch k {
	case vBool, vPtrBool:
		return TypeBool
	case vNum, vPtrNum:
		return TypeNumber
	case vStrings:
		return TypeStrings
	default:
		return TypeString
	}
}

// collect walks a struct type and appends one accessor per emitted field.
// depth bounds recursion: the event contract nests at most two levels
// (asset.mcp.pinned).
func collect(t reflect.Type, prefix string, index []int, out *[]accessor, depth int) {
	if depth > 3 {
		return
	}
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		name, omit, ok := jsonName(f)
		if !ok {
			continue
		}
		idx := append(append([]int(nil), index...), i)
		ft := f.Type
		if ft.Kind() == reflect.Pointer && ft.Elem().Kind() == reflect.Struct && ft.Elem() != timeType {
			collect(ft.Elem(), prefix+name+".", idx, out, depth+1)
			continue
		}
		if a, ok := leafAccessor(ft, prefix+name, idx, omit); ok {
			*out = append(*out, a)
		}
	}
}

func leafAccessor(ft reflect.Type, name string, idx []int, omit bool) (accessor, bool) {
	a := accessor{name: name, index: idx, omitempty: omit}
	switch {
	case ft == timeType:
		a.kind = vTime
	case ft.Kind() == reflect.String:
		a.kind = vString
	case ft.Kind() == reflect.Bool:
		a.kind = vBool
	case isNumber(ft.Kind()):
		a.kind = vNum
	case ft.Kind() == reflect.Slice && ft.Elem().Kind() == reflect.String:
		a.kind = vStrings
	case ft.Kind() == reflect.Pointer && ft.Elem().Kind() == reflect.Bool:
		a.kind = vPtrBool
	case ft.Kind() == reflect.Pointer && isNumber(ft.Elem().Kind()):
		a.kind = vPtrNum
	case ft.Kind() == reflect.Map && ft.Key().Kind() == reflect.String && ft.Elem().Kind() == reflect.String:
		a.kind = vStringMap
	case ft.Kind() == reflect.Map && ft.Key().Kind() == reflect.String && isNumber(ft.Elem().Kind()):
		a.kind = vNumMap
	default:
		// Structured values (tool input, surfaces, coverage) are not
		// flattened: rules match on features derived from them instead.
		return a, false
	}
	return a, true
}

func isNumber(k reflect.Kind) bool {
	switch k {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
		reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
		reflect.Float32, reflect.Float64:
		return true
	}
	return false
}

func jsonName(f reflect.StructField) (name string, omit bool, ok bool) {
	tag := f.Tag.Get("json")
	if tag == "-" {
		return "", false, false
	}
	name, opts, _ := strings.Cut(tag, ",")
	if name == "" {
		name = strings.ToLower(f.Name)
	}
	for _, o := range strings.Split(opts, ",") {
		if o == "omitempty" || o == "omitzero" {
			omit = true
		}
	}
	return name, omit, true
}

// maxMapEntries bounds how many keys of one map field (labels, asset
// detail) are flattened; maps are written by sources, not by attackers,
// but the bound keeps the cost of Fields predictable.
const maxMapEntries = 64

// Fields returns the flattened view rules match on: every emitted event
// field by its JSON path ("tool.kind", "asset.mcp.pinned", "labels.<key>"),
// following omitempty (an empty optional field is absent, not ""), plus
// every computed feature in e.Feat. Values are string, bool, float64,
// []string, or []map[string]any for the structured lists shell.cmds and
// shell.install_entries. The map is freshly allocated; callers may add
// keys. Fields never panics; on an internal error it returns what it has.
func Fields(e *event.Event) (out map[string]any) {
	if e == nil {
		return map[string]any{}
	}
	out = make(map[string]any, 64+len(e.Feat))
	defer func() {
		if recover() != nil {
			// A malformed event must not take the caller down; a partial
			// view can only make rules match less.
			return
		}
	}()
	p := eventPlan()
	root := reflect.ValueOf(e).Elem()
	for gi := range p.groups {
		g := &p.groups[gi]
		v := root.Field(g.top)
		if g.ptr {
			if v.IsNil() {
				continue
			}
			v = v.Elem()
			for ai := range g.accs {
				readAccessor(v, &g.accs[ai], out)
			}
			continue
		}
		readAccessor(root, &g.accs[0], out)
	}
	for k, v := range e.Feat {
		if k == computedKey {
			continue
		}
		if nv, ok := normalizeValue(v); ok {
			out[k] = nv
		}
	}
	return out
}

func readAccessor(base reflect.Value, a *accessor, out map[string]any) {
	v := base
	for i, idx := range a.index {
		v = v.Field(idx)
		if i < len(a.index)-1 && v.Kind() == reflect.Pointer {
			if v.IsNil() {
				return
			}
			v = v.Elem()
		}
	}
	switch a.kind {
	case vString:
		s := v.String()
		if s == "" {
			// An empty string is absent whatever the JSON tag says, so
			// "a missing field never matches" also covers "" .
			return
		}
		out[a.name] = s
	case vBool:
		b := v.Bool()
		if !b && a.omitempty {
			return
		}
		out[a.name] = b
	case vNum:
		f := numValue(v)
		if f == 0 && a.omitempty {
			return
		}
		out[a.name] = f
	case vStrings:
		n := v.Len()
		if n == 0 {
			return
		}
		s := make([]string, n)
		for i := 0; i < n; i++ {
			s[i] = v.Index(i).String()
		}
		out[a.name] = s
	case vTime:
		t := v.Interface().(event.Time)
		if t.IsZero() {
			return
		}
		out[a.name] = t.String()
	case vPtrBool:
		if v.IsNil() {
			return
		}
		out[a.name] = v.Elem().Bool()
	case vPtrNum:
		if v.IsNil() {
			return
		}
		out[a.name] = numValue(v.Elem())
	case vStringMap:
		if v.Len() == 0 {
			return
		}
		keys := sortedKeys(v)
		for _, k := range keys {
			out[a.name+"."+k] = v.MapIndex(reflect.ValueOf(k).Convert(v.Type().Key())).String()
		}
	case vNumMap:
		if v.Len() == 0 {
			return
		}
		keys := sortedKeys(v)
		for _, k := range keys {
			out[a.name+"."+k] = numValue(v.MapIndex(reflect.ValueOf(k).Convert(v.Type().Key())))
		}
	}
}

func sortedKeys(v reflect.Value) []string {
	keys := make([]string, 0, v.Len())
	iter := v.MapRange()
	for iter.Next() {
		keys = append(keys, iter.Key().String())
	}
	sort.Strings(keys)
	if len(keys) > maxMapEntries {
		keys = keys[:maxMapEntries]
	}
	return keys
}

func numValue(v reflect.Value) float64 {
	switch v.Kind() {
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return float64(v.Int())
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return float64(v.Uint())
	case reflect.Float32, reflect.Float64:
		return v.Float()
	}
	return 0
}

// normalizeValue converts a feature value to one of the types rules
// understand. Features computed here already have those types; values
// injected by tests or other enrichers (ints, []any) are converted.
func normalizeValue(v any) (any, bool) {
	switch t := v.(type) {
	case string, bool, float64, []string, []map[string]any:
		return v, true
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case uint64:
		return float64(t), true
	case float32:
		return float64(t), true
	case []any:
		out := make([]string, 0, len(t))
		for _, x := range t {
			s, ok := x.(string)
			if !ok {
				return nil, false
			}
			out = append(out, s)
		}
		return out, true
	}
	return nil, false
}
