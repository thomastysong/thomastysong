package rules

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"

	"gopkg.in/yaml.v3"
)

// Decoding packs/embedded.cache.
//
// One pass over the stream validates every node as parseStrict's checkNode
// does (kinds, allowed tags, scalar and unique mapping keys, depth, node
// counts) and builds yaml.Node trees. In a pack file the value of a rule
// key outside the rule's stub (lazy.go) that is a sequence or a mapping
// (match, allow, tests, tags, references, ...) is validated but not built:
// its node is created without children, and the subtree is decoded from
// the same bytes on first use (cacheTree.materialize). A hook process that
// evaluates a handful of rules builds a quarter of the nodes, which was
// most of its start-up (an arena of 20,000 nodes, 3 MB, cold).

// cacheTree is what the files decoded from one cache share: the cache bytes
// and string table, and the subtrees not built yet.
type cacheTree struct {
	b    []byte
	strs []string
	tags []uint8 // per string: tagUnknown, tagOK or tagBad

	mu       sync.Mutex
	deferred map[*yaml.Node]deferredRef
}

// deferredRef locates the children of a node left without them.
type deferredRef struct {
	off   int // offset of the first child in b
	kids  int // children
	nodes int // nodes in the children's subtrees
	depth int // depth of the node itself
}

// materialize builds the deferred subtrees under the values of the mapping
// n (a rule), the value of its tests key only with tests set. It is
// idempotent and safe for concurrent use; whoever reads the collection
// values of a rule node from the cache calls it first.
func (t *cacheTree) materialize(n *yaml.Node, tests bool) (err error) {
	if t == nil || n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	defer func() {
		if recover() != nil {
			err = errCache // validated at load; never expected
		}
	}()
	if len(t.deferred) == 0 {
		return nil
	}
	// One reader for the rule, its arena sized to the nodes it builds.
	want := func(i int) (deferredRef, bool) {
		ref, ok := t.deferred[n.Content[i]]
		return ref, ok && (tests || n.Content[i-1].Value != "tests")
	}
	total := 0
	for i := 1; i < len(n.Content); i += 2 {
		if ref, ok := want(i); ok {
			total += ref.nodes
		}
	}
	if total == 0 {
		return nil
	}
	r := &cacheReader{b: t.b, strs: t.strs, tags: t.tags, limit: total}
	type done struct {
		v    *yaml.Node
		kids []*yaml.Node
	}
	var built []done
	for i := 1; i < len(n.Content); i += 2 {
		ref, ok := want(i)
		if !ok {
			continue
		}
		v := n.Content[i]
		r.off = ref.off
		before := r.visited
		kids := r.newPtrs(ref.kids)
		r.children(v.Kind, ref.kids, ref.depth, true, posNone, kids)
		if r.err != nil || r.visited-before != ref.nodes {
			return fmt.Errorf("%w: deferred subtree at line %d", errCache, v.Line)
		}
		built = append(built, done{v, kids})
	}
	for _, d := range built {
		d.v.Content = d.kids
		delete(t.deferred, d.v)
	}
	return nil
}

// childCount returns the number of children of n, built or deferred.
func (t *cacheTree) childCount(n *yaml.Node) int {
	if t != nil {
		t.mu.Lock()
		ref, ok := t.deferred[n]
		t.mu.Unlock()
		if ok {
			return ref.kids
		}
	}
	return len(n.Content)
}

// stubKey reports the rule keys whose values are built at load.
func stubKey(k string) bool {
	switch k {
	case "id", "kind", "response", "flags", "when":
		return true
	}
	return false
}

// nodePos is where a node sits in a pack file, which decides deferral.
type nodePos uint8

const (
	posNone     nodePos = iota
	posPackRoot         // the root mapping of a pack file
	posRules            // its rules sequence
	posRule             // one rule mapping
)

// decodeCache returns the parsed files of a cache made from content whose
// sourceDigest is want. Every structural property is validated: the cache
// is embedded and trusted, but a decoder that trusts its input is one bug
// away from a panic in every hook process.
func decodeCache(b []byte, want [sha256.Size]byte) (srcs []sourceFile, err error) {
	defer func() {
		if recover() != nil {
			srcs, err = nil, errCache
		}
	}()
	if len(b) > maxCacheBytes || len(b) < len(cacheMagic)+sha256.Size || string(b[:len(cacheMagic)]) != cacheMagic {
		return nil, errCache
	}
	r := &cacheReader{b: b, off: len(cacheMagic)}
	if !bytes.Equal(r.take(sha256.Size), want[:]) {
		return nil, fmt.Errorf("%w: made from different content (run go generate ./internal/rules)", errCache)
	}
	ns := r.count(maxCacheStrs)
	lens := make([]int, ns)
	total := 0
	for i := range lens {
		lens[i] = r.count(maxCacheBytes)
		total += lens[i]
	}
	if r.err != nil || total > len(b) {
		return nil, errCache
	}
	// One allocation for every string; nodes share substrings of it.
	all := string(r.take(total))
	r.strs = make([]string, ns)
	off := 0
	for i, l := range lens {
		r.strs[i] = all[off : off+l]
		off += l
	}
	tree := &cacheTree{b: b, strs: r.strs, tags: make([]uint8, ns), deferred: make(map[*yaml.Node]deferredRef, 1024)}
	r.tree, r.tags = tree, tree.tags
	nf := r.count(maxCacheFiles)
	for i := 0; i < nf && r.err == nil; i++ {
		name := r.str()
		size := r.count(maxCacheBytes)
		nodes := r.count(maxYAMLNodes)
		if r.err != nil || nodes == 0 || fileRole(name) == "" {
			return nil, errCache
		}
		r.limit, r.visited = nodes, 0 // the arena carries over: files share chunks
		pos := posNone
		if fileRole(name) == "pack" {
			pos = posPackRoot
		}
		root, _, _ := r.node(0, true, pos)
		if r.err != nil || r.visited != nodes {
			return nil, errCache
		}
		srcs = append(srcs, sourceFile{name: name, size: size, root: root, cached: true, tree: tree})
	}
	if r.err != nil || r.off != len(b) {
		return nil, errCache
	}
	return srcs, nil
}

type cacheReader struct {
	b    []byte
	off  int
	err  error
	strs []string
	tags []uint8    // memo of tag checks, by string index
	tree *cacheTree // set while decoding a whole cache: deferral is on
	keys []int      // stack of the mapping keys being checked (value indexes)

	limit   int // nodes this decode may visit
	visited int
	arena   []yaml.Node
	ptrs    []*yaml.Node
}

func (r *cacheReader) fail() { r.err = errCache }

func (r *cacheReader) uvarint() uint64 {
	// Most values (string indexes, columns, child counts, lines) take one
	// or two bytes.
	if o := r.off; o+1 < len(r.b) {
		if c := r.b[o]; c < 0x80 {
			r.off = o + 1
			return uint64(c)
		} else if d := r.b[o+1]; d < 0x80 {
			r.off = o + 2
			return uint64(c&0x7f) | uint64(d)<<7
		}
	}
	if r.err != nil || r.off >= len(r.b) {
		r.fail()
		return 0
	}
	v, n := binary.Uvarint(r.b[r.off:])
	if n <= 0 {
		r.fail()
		return 0
	}
	r.off += n
	return v
}

// count reads a non-negative integer no larger than max.
func (r *cacheReader) count(max int) int {
	v := r.uvarint()
	if v > uint64(max) {
		r.fail()
		return 0
	}
	return int(v)
}

func (r *cacheReader) take(n int) []byte {
	if r.err != nil || n < 0 || n > len(r.b)-r.off {
		r.fail()
		return nil
	}
	out := r.b[r.off : r.off+n]
	r.off += n
	return out
}

// strIndex reads a string table index.
func (r *cacheReader) strIndex() int {
	i := r.uvarint()
	if i >= uint64(len(r.strs)) {
		r.fail()
		return 0
	}
	return int(i)
}

func (r *cacheReader) str() string {
	i := r.strIndex()
	if r.err != nil {
		return ""
	}
	return r.strs[i]
}

// nodeHeader is one encoded node without its children.
type nodeHeader struct {
	kind       yaml.Kind
	style      yaml.Style
	tag, value int // string table indexes
	line, col  int
	kids       int
}

// header reads and checks one node header into h.
func (r *cacheReader) header(h *nodeHeader) {
	if o := r.off; o+1 < len(r.b) {
		h.kind, h.style = yaml.Kind(r.b[o]), yaml.Style(r.b[o+1])
		r.off = o + 2
	} else {
		r.fail()
		return
	}
	h.tag = r.strIndex()
	h.value = r.strIndex()
	h.line = r.count(1 << 30)
	h.col = r.count(1 << 30)
	h.kids = r.count(r.limit - r.visited) // every child is at least one node
	if r.err != nil {
		return
	}
	switch h.kind {
	case yaml.SequenceNode, yaml.MappingNode, yaml.ScalarNode:
	default:
		// Documents are unwrapped before encoding and aliases are
		// rejected by the parser.
		r.fail()
		return
	}
	if h.kind == yaml.ScalarNode && h.kids > 0 || h.kind == yaml.MappingNode && h.kids%2 != 0 {
		r.fail()
		return
	}
	if !r.tagOK(h.tag) {
		r.fail() // what checkNode refuses: custom tags, !!binary, !!merge
	}
}

const (
	tagUnknown uint8 = iota
	tagOK
	tagBad
)

// tagOK reports whether string i is a tag checkNode accepts.
func (r *cacheReader) tagOK(i int) bool {
	if r.tags == nil {
		return allowedTag(r.strs[i])
	}
	switch r.tags[i] {
	case tagOK:
		return true
	case tagBad:
		return false
	}
	ok := allowedTag(r.strs[i])
	r.tags[i] = tagBad
	if ok {
		r.tags[i] = tagOK
	}
	return ok
}

func allowedTag(t string) bool {
	switch t {
	case "", "!!str", "!!int", "!!float", "!!bool", "!!null", "!!seq", "!!map", "!!timestamp":
		return true
	}
	return false
}

// newNode returns a zeroed node from the arena.
func (r *cacheReader) newNode() *yaml.Node {
	if len(r.arena) == 0 {
		n := r.limit - r.visited + 1 // at most the nodes left to visit
		if n > 256 {
			n = 256
		}
		r.arena = make([]yaml.Node, n)
	}
	n := &r.arena[0]
	r.arena = r.arena[1:]
	return n
}

// newPtrs returns a child slice of length and capacity k, so an append to
// it can never overwrite a neighbour's children.
func (r *cacheReader) newPtrs(k int) []*yaml.Node {
	if len(r.ptrs) < k {
		n := r.limit - r.visited // no node has more children than nodes remain
		if n > 1024 {
			n = 1024
		}
		if n < k {
			n = k
		}
		r.ptrs = make([]*yaml.Node, n)
	}
	out := r.ptrs[:k:k]
	r.ptrs = r.ptrs[k:]
	return out
}

// node decodes one node and its subtree in pre-order. With build false it
// only validates and counts them. pos is where the node sits in a pack
// file; a rule's collection values outside its stub are deferred when the
// reader belongs to a whole-cache decode. It returns the node (nil when
// not building), its kind and its value's string index.
func (r *cacheReader) node(depth int, build bool, pos nodePos) (*yaml.Node, yaml.Kind, int) {
	if r.err != nil {
		return nil, 0, 0
	}
	if depth > maxYAMLDepth || r.visited >= r.limit {
		r.fail()
		return nil, 0, 0
	}
	r.visited++
	var h nodeHeader
	r.header(&h)
	if r.err != nil {
		return nil, 0, 0
	}
	var n *yaml.Node
	if build {
		n = r.newNode()
		n.Kind, n.Style = h.kind, h.style
		n.Tag, n.Value = r.strs[h.tag], r.strs[h.value]
		n.Line, n.Column = h.line, h.col
	}
	if h.kids > 0 {
		var kids []*yaml.Node
		if build {
			kids = r.newPtrs(h.kids)
			n.Content = kids
		}
		r.children(h.kind, h.kids, depth, build, pos, kids)
	}
	return n, h.kind, h.value
}

// children decodes the k children of a node of kind at depth into kids
// (nil when not building). Mapping keys must be unique scalars.
func (r *cacheReader) children(kind yaml.Kind, k, depth int, build bool, pos nodePos, kids []*yaml.Node) {
	if kind == yaml.SequenceNode {
		kpos := posNone
		if pos == posRules {
			kpos = posRule
		}
		for i := 0; i < k && r.err == nil; i++ {
			c, _, _ := r.node(depth+1, build, kpos)
			if build {
				kids[i] = c
			}
		}
		return
	}
	base := len(r.keys)
	for i := 0; i+1 < k && r.err == nil; i += 2 {
		kn, kkind, kval := r.node(depth+1, build, posNone)
		if r.err != nil {
			break
		}
		if kkind != yaml.ScalarNode {
			r.fail()
			break
		}
		key := r.strs[kval]
		for _, p := range r.keys[base:] {
			if p == kval || r.strs[p] == key {
				r.fail() // duplicate key
				break
			}
		}
		r.keys = append(r.keys, kval)
		vpos := posNone
		if pos == posPackRoot && key == "rules" {
			vpos = posRules
		}
		var v *yaml.Node
		if build && pos == posRule && r.tree != nil && !stubKey(key) {
			v = r.deferrable(depth + 1)
		} else {
			v, _, _ = r.node(depth+1, build, vpos)
		}
		if build {
			kids[i], kids[i+1] = kn, v
		}
	}
	r.keys = r.keys[:base]
}

// deferrable decodes the value of a rule key outside the stub: a scalar is
// built; a sequence or mapping is built without its children, which are
// validated now and recorded for materialize.
func (r *cacheReader) deferrable(depth int) *yaml.Node {
	if r.err != nil || depth > maxYAMLDepth || r.visited >= r.limit {
		r.fail()
		return nil
	}
	r.visited++
	var h nodeHeader
	r.header(&h)
	if r.err != nil {
		return nil
	}
	n := r.newNode()
	n.Kind, n.Style = h.kind, h.style
	n.Tag, n.Value = r.strs[h.tag], r.strs[h.value]
	n.Line, n.Column = h.line, h.col
	if h.kids == 0 {
		return n
	}
	ref := deferredRef{off: r.off, kids: h.kids, depth: depth}
	before := r.visited
	r.children(h.kind, h.kids, depth, false, posNone, nil)
	if r.err != nil {
		return nil
	}
	ref.nodes = r.visited - before
	r.tree.deferred[n] = ref
	return n
}
