package privacy

import (
	"reflect"
	"sort"
	"strings"
	"sync"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// The safety pass and the line cap must reach every string the encoder
// will write, including fields added to the event contract after this
// package was written. They therefore walk the record by reflection, using
// the JSON names for field paths, instead of a hand-written field list.

// slot is one string leaf of a record.
type slot struct {
	name string // JSON path, e.g. "target.command", "labels.env", "tool.input.cmd"
	get  func() string
	set  func(string)
}

var timeType = reflect.TypeOf(event.Time{})

const maxWalkDepth = 24

// collectSlots returns every string leaf of e (Content and Feat are
// json:"-" and skipped).
func collectSlots(e *event.Event) []slot {
	var out []slot
	walkValue(reflect.ValueOf(e), "", 0, func(s slot) { out = append(out, s) })
	return out
}

func joinName(parent, child string) string {
	if parent == "" {
		return child
	}
	return parent + "." + child
}

// jsonField is an exported, encoded field of a struct type.
type jsonField struct {
	index int
	name  string
}

// structFieldCache maps a struct type to its jsonFields. The walk runs
// several times per record (safety pass, key rewrite, every line-cap
// pass); reading struct tags each time was a tenth of Emit.
var structFieldCache sync.Map // reflect.Type -> []jsonField

func jsonFields(t reflect.Type) []jsonField {
	if v, ok := structFieldCache.Load(t); ok {
		return v.([]jsonField)
	}
	out := make([]jsonField, 0, t.NumField())
	for i := 0; i < t.NumField(); i++ {
		f := t.Field(i)
		if !f.IsExported() {
			continue
		}
		if jn, ok := jsonName(f); ok {
			out = append(out, jsonField{index: i, name: jn})
		}
	}
	v, _ := structFieldCache.LoadOrStore(t, out)
	return v.([]jsonField)
}

func jsonName(f reflect.StructField) (string, bool) {
	tag := f.Tag.Get("json")
	if tag == "-" {
		return "", false
	}
	name, _, _ := strings.Cut(tag, ",")
	if name == "" {
		name = strings.ToLower(f.Name)
	}
	return name, true
}

func walkValue(v reflect.Value, name string, depth int, add func(slot)) {
	if depth > maxWalkDepth || !v.IsValid() {
		return
	}
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			walkValue(v.Elem(), name, depth+1, add)
		}
	case reflect.Struct:
		if v.Type() == timeType {
			return
		}
		for _, f := range jsonFields(v.Type()) {
			walkValue(v.Field(f.index), joinName(name, f.name), depth+1, add)
		}
	case reflect.String:
		if !v.CanSet() {
			return
		}
		fv := v
		add(slot{name: name, get: fv.String, set: fv.SetString})
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return
		}
		for i := 0; i < v.Len(); i++ {
			walkValue(v.Index(i), name, depth+1, add)
		}
	case reflect.Map:
		if v.IsNil() || v.Type().Key().Kind() != reflect.String {
			return
		}
		et := v.Type().Elem()
		switch {
		case et.Kind() == reflect.String:
			for _, k := range sortedKeys(v) {
				mk, mv := k, v
				add(slot{
					name: joinName(name, k.String()),
					get:  func() string { return mv.MapIndex(mk).String() },
					set:  func(s string) { mv.SetMapIndex(mk, reflect.ValueOf(s).Convert(et)) },
				})
			}
		case et.Kind() == reflect.Interface:
			if m, ok := v.Interface().(map[string]any); ok {
				walkAny(m, name, depth+1, add)
			}
		}
	}
}

func sortedKeys(v reflect.Value) []reflect.Value {
	keys := v.MapKeys()
	sort.Slice(keys, func(i, j int) bool { return keys[i].String() < keys[j].String() })
	return keys
}

// walkAny visits string leaves of decoded JSON (tool input).
func walkAny(m map[string]any, name string, depth int, add func(slot)) {
	if depth > maxWalkDepth {
		return
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p := joinName(name, k)
		switch t := m[k].(type) {
		case string:
			mm, kk := m, k
			add(slot{name: p, get: func() string { s, _ := mm[kk].(string); return s }, set: func(s string) { mm[kk] = s }})
		case map[string]any:
			walkAny(t, p, depth+1, add)
		case []any:
			walkList(t, p, depth+1, add)
		case []string:
			for i := range t {
				arr, ii := t, i
				add(slot{name: p, get: func() string { return arr[ii] }, set: func(s string) { arr[ii] = s }})
			}
		}
	}
}

func walkList(l []any, name string, depth int, add func(slot)) {
	if depth > maxWalkDepth {
		return
	}
	for i, it := range l {
		switch t := it.(type) {
		case string:
			arr, ii := l, i
			add(slot{name: name, get: func() string { s, _ := arr[ii].(string); return s }, set: func(s string) { arr[ii] = s }})
		case map[string]any:
			walkAny(t, name, depth+1, add)
		case []any:
			walkList(t, name, depth+1, add)
		}
	}
}

// rekeyMaps rewrites the keys of every string-keyed map in e with fn
// (keys are data too: a map keyed by a token leaks through its keys).
func rekeyMaps(e *event.Event, fn func(string) string) {
	rekeyValue(reflect.ValueOf(e), 0, fn)
}

func rekeyValue(v reflect.Value, depth int, fn func(string) string) {
	if depth > maxWalkDepth || !v.IsValid() {
		return
	}
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			rekeyValue(v.Elem(), depth+1, fn)
		}
	case reflect.Struct:
		if v.Type() == timeType {
			return
		}
		for _, f := range jsonFields(v.Type()) {
			rekeyValue(v.Field(f.index), depth+1, fn)
		}
	case reflect.Slice:
		if v.Type().Elem().Kind() == reflect.Struct || v.Type().Elem().Kind() == reflect.Pointer {
			for i := 0; i < v.Len(); i++ {
				rekeyValue(v.Index(i), depth+1, fn)
			}
		}
	case reflect.Map:
		if v.IsNil() || v.Type().Key().Kind() != reflect.String || !v.CanSet() {
			return
		}
		if m, ok := v.Interface().(map[string]any); ok {
			v.Set(reflect.ValueOf(rekeyAny(m, depth+1, fn)))
			return
		}
		changed := false
		for _, k := range v.MapKeys() {
			if fn(k.String()) != k.String() {
				changed = true
				break
			}
		}
		if !changed {
			return
		}
		nm := reflect.MakeMapWithSize(v.Type(), v.Len())
		kt := v.Type().Key()
		for _, k := range sortedKeys(v) {
			nk := reflect.ValueOf(fn(k.String())).Convert(kt)
			if nm.MapIndex(nk).IsValid() {
				continue // two keys collapsed into one: keep the first
			}
			nm.SetMapIndex(nk, v.MapIndex(k))
		}
		v.Set(nm)
	}
}

func rekeyAny(m map[string]any, depth int, fn func(string) string) map[string]any {
	if m == nil || depth > maxWalkDepth {
		return m
	}
	out := make(map[string]any, len(m))
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		nk := fn(k)
		if _, dup := out[nk]; dup {
			continue
		}
		out[nk] = rekeyAnyValue(m[k], depth+1, fn)
	}
	return out
}

func rekeyAnyValue(v any, depth int, fn func(string) string) any {
	switch t := v.(type) {
	case map[string]any:
		return rekeyAny(t, depth, fn)
	case []any:
		for i := range t {
			t[i] = rekeyAnyValue(t[i], depth+1, fn)
		}
		return t
	}
	return v
}
