package classify

import "sync"

// Start-up cost. Every hook invocation is a fresh process that links this
// package, and its budget is a few milliseconds. A map literal at package
// level is built by package init in every one of those processes, whether
// the process ever looks at it or not; so is a regexp.MustCompile, a
// netip.MustParseAddr or any other call in a package-level initializer.
// Tables here are therefore declared as static data (string slices, which
// the linker lays out at build time and which cost nothing to start) and
// indexed on first use; regular expressions are compiled on first use behind
// a sync.Once, at most once per process. Package init runs no code at all
// (lazyinit_test.go checks this before any test runs).

// lazySet is a set of strings declared as a list and indexed into a map the
// first time it is queried. The zero sync.Once and nil map make a lazySet
// composite literal static data.
type lazySet struct {
	list []string
	once sync.Once
	m    map[string]struct{}
}

// has reports whether k is in the set.
func (s *lazySet) has(k string) bool {
	s.once.Do(s.build)
	_, ok := s.m[k]
	return ok
}

func (s *lazySet) build() {
	m := make(map[string]struct{}, len(s.list))
	for _, k := range s.list {
		m[k] = struct{}{}
	}
	s.m = m
}

// built reports whether the set has been indexed (for the init-cost test).
func (s *lazySet) built() bool { return s.m != nil }

// setOf builds a set directly; for tables that are themselves built lazily.
func setOf(words ...string) map[string]bool {
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}
