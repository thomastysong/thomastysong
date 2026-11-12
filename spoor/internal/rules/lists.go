package rules

import (
	"fmt"
	"sort"
	"strings"
)

// namedList is one named list from lists.yaml. Matching ignores case: lists hold
// host names, command names and package names, all case-insensitive where
// they are used.
//
// Entry forms:
//
//	example.com     exact
//	*.example.com   any subdomain of example.com (not example.com itself)
//	prefix*         anything that starts with prefix
type namedList struct {
	name     string
	entries  []string // as written, for hashing and display
	exact    map[string]struct{}
	suffixes []string // ".example.com"
	prefixes []string
}

func newList(name string, entries []string) (*namedList, error) {
	if !validListName(name) {
		return nil, fmt.Errorf("list name %q: use lower-case letters, digits, '_', '-' and '.'", name)
	}
	l := &namedList{name: name, exact: make(map[string]struct{}, len(entries))}
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" || len(e) > 1024 {
			return nil, fmt.Errorf("list %s: empty or oversized entry", name)
		}
		l.entries = append(l.entries, e)
		le := strings.ToLower(e)
		switch {
		case strings.HasPrefix(le, "*.") && len(le) > 2 && !strings.Contains(le[2:], "*"):
			l.suffixes = append(l.suffixes, le[1:])
		case strings.HasSuffix(le, "*") && len(le) > 1 && !strings.Contains(le[:len(le)-1], "*"):
			l.prefixes = append(l.prefixes, le[:len(le)-1])
		case strings.Contains(le, "*"):
			return nil, fmt.Errorf("list %s: entry %q: '*' is allowed only as a leading \"*.\" or a trailing \"*\"", name, e)
		default:
			l.exact[le] = struct{}{}
		}
	}
	sort.Strings(l.entries)
	return l, nil
}

func (l *namedList) match(s string) bool {
	if s == "" {
		return false
	}
	ls := strings.ToLower(s)
	if _, ok := l.exact[ls]; ok {
		return true
	}
	for _, suf := range l.suffixes {
		if len(ls) > len(suf) && strings.HasSuffix(ls, suf) {
			return true
		}
	}
	for _, p := range l.prefixes {
		if strings.HasPrefix(ls, p) {
			return true
		}
	}
	return false
}

// parseLists loads lists.yaml.
func parseLists(data []byte) (map[string]*namedList, error) {
	if len(data) > maxListBytes {
		return nil, fmt.Errorf("rules: lists.yaml is larger than %d bytes", maxListBytes)
	}
	var raw rawLists
	if err := decodeStrict(data, &raw); err != nil {
		return nil, fmt.Errorf("lists.yaml: %w", err)
	}
	out := make(map[string]*namedList, len(raw.Lists))
	total := 0
	for name, entries := range raw.Lists {
		total += len(entries)
		if total > maxListItems {
			return nil, fmt.Errorf("rules: lists.yaml has more than %d entries", maxListItems)
		}
		l, err := newList(name, entries)
		if err != nil {
			return nil, fmt.Errorf("rules: lists.yaml: %w", err)
		}
		out[name] = l
	}
	return out, nil
}
