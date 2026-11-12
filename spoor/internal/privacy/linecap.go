package privacy

import (
	"encoding/json"
	"sort"
	"unicode/utf8"
)

// The line cap. Fluent Bit's tail input stops monitoring a file (or drops
// the line) when one line exceeds its buffer, so every record is forced
// under MaxLine. The cap is enforced on the ENCODED line: JSON escaping
// turns one byte of "<", ">", "&" or a control character into six, so a
// 4 KiB field can encode to 24 KiB. The largest fields are cut first,
// water-filling them down to a common level; if the record is made of many
// small values, whole optional containers are dropped; as a last resort a
// content-free skeleton is written. Every cut is named in Truncated.

const (
	minKeep        = 64 // a cut field keeps at least this many encoded bytes
	markerOverhead = 24 // room for "[TRUNCATED:nnnnnnB]" plus quotes
	fitSlack       = 96 // growth of the truncated list between passes
	maxFitPasses   = 8
)

// protectedSlots are never cut: routing, identity of the record and the
// labels this package writes.
var protectedSlots = map[string]bool{
	"id": true, "kind": true, "type": true, "source": true, "fidelity": true, "integrity": true,
	"writer": true, "dedupe": true, "privacy": true, "truncated": true,
	"detection.rule_id": true, "detection.severity": true, "detection.class": true,
	"labels.lossy": true, "labels.key_id": true, "labels.len_bucketed": true,
	"labels." + LabelContextFor:     true,
	"labels." + LabelContextKind:    true,
	"labels." + LabelContextType:    true,
	"labels." + LabelContextEventID: true,
}

// jsonLen is the encoded size of s as encoding/json writes it (HTML
// escaping on), quotes included. Over-estimates are safe.
func jsonLen(s string) int {
	n := 2
	for i := 0; i < len(s); {
		e, size := encRune(s, i)
		n += e
		i += size
	}
	return n
}

// encRune returns the encoded width and byte size of the rune at s[i].
func encRune(s string, i int) (int, int) {
	c := s[i]
	if c < utf8.RuneSelf {
		switch {
		case c == '"' || c == '\\' || c == '\n' || c == '\r' || c == '\t':
			return 2, 1
		case c < 0x20 || c == '<' || c == '>' || c == '&':
			return 6, 1
		}
		return 1, 1
	}
	r, size := utf8.DecodeRuneInString(s[i:])
	if r == utf8.RuneError && size == 1 || r == ' ' || r == ' ' {
		return 6, size
	}
	return size, size
}

// cutEncoded shortens s so that its encoded form, marker included, is at
// most budget bytes, keeping its head and tail.
func cutEncoded(s string, budget int) string {
	content := budget - 2 - len(truncMarker(len(s)))
	if content < 0 {
		content = 0
	}
	headB := (content + 1) / 2
	tailB := content - headB
	h, acc := 0, 0
	for h < len(s) {
		e, size := encRune(s, h)
		if acc+e > headB {
			break
		}
		acc += e
		h += size
	}
	t, acc2 := len(s), 0
	for t > h {
		_, size := utf8.DecodeLastRuneInString(s[:t])
		e, _ := encRune(s, t-size)
		if acc2+e > tailB {
			break
		}
		acc2 += e
		t -= size
	}
	h = markerSafe(s, h, true)
	t = markerSafe(s, t, false)
	if t < h {
		t = h
	}
	return s[:h] + truncMarker(t-h) + s[t:]
}

// fitLine forces the marshalled record under the line budget.
func (r *run) fitLine() {
	budget := r.s.lineBudget()
	for pass := 0; pass < maxFitPasses; pass++ {
		b, err := json.Marshal(r.out)
		if err != nil {
			r.toSkeleton("privacy_error")
			return
		}
		over := len(b) - budget
		if over <= 0 {
			return
		}
		if !r.cutLargest(over + fitSlack) {
			r.dropContainers(over + fitSlack)
		}
		r.finish()
	}
	if b, err := json.Marshal(r.out); err == nil && len(b) <= budget {
		return
	}
	r.toSkeleton("line_cap")
}

// toSkeleton replaces the record with its content-free skeleton, keeping
// the labels this package stamps (a context record must still say which
// finding it belongs to).
func (r *run) toSkeleton(reason string) {
	sk := r.p.skeleton(r.out, r.s, r.out.Privacy, reason)
	if sk == nil {
		return
	}
	for k, v := range r.stamp {
		sk.Labels[k] = v
	}
	r.out = sk
}

type sized struct {
	slot
	size int
}

// cutLargest water-fills the largest string fields down to a common level
// that frees need bytes. It reports false when cutting strings alone
// cannot free enough (the fields that remain were still cut to minKeep).
func (r *run) cutLargest(need int) bool {
	var all []sized
	for _, sl := range collectSlots(r.out) {
		if protectedSlots[sl.name] {
			continue
		}
		if n := jsonLen(sl.get()); n > minKeep+markerOverhead {
			all = append(all, sized{sl, n})
		}
	}
	if len(all) == 0 {
		return false
	}
	sort.SliceStable(all, func(i, j int) bool { return all[i].size > all[j].size })
	prefix, level, k := 0, -1, 0
	for k = 1; k <= len(all); k++ {
		prefix += all[k-1].size
		next := minKeep
		if k < len(all) && all[k].size > next {
			next = all[k].size
		}
		if prefix-k*(next+markerOverhead) >= need {
			level = (prefix-need)/k - markerOverhead
			break
		}
	}
	enough := level >= 0
	if !enough {
		level, k = minKeep, len(all)
	}
	for _, s := range all[:min(k, len(all))] {
		if s.size <= level+markerOverhead {
			continue
		}
		s.set(cutEncoded(s.get(), level+markerOverhead))
		r.note(s.name)
	}
	return enough
}

// dropContainers removes optional containers, least valuable first, until
// the estimate of freed bytes reaches need.
func (r *run) dropContainers(need int) {
	out := r.out
	freed := 0
	size := func(v any) int {
		b, err := json.Marshal(v)
		if err != nil {
			return 0
		}
		return len(b)
	}
	type dropper struct {
		name string
		fn   func() int
	}
	steps := []dropper{
		{"tool.input", func() int {
			if out.Tool == nil || out.Tool.Input == nil {
				return 0
			}
			n := size(out.Tool.Input)
			out.Tool.Input = nil
			return n
		}},
		{"detection.evidence", func() int {
			if out.Detection == nil || out.Detection.Evidence == nil {
				return 0
			}
			n := size(out.Detection.Evidence)
			out.Detection.Evidence = nil
			return n
		}},
		{"labels", func() int {
			n := 0
			for k, v := range out.Labels {
				if !protectedSlots["labels."+k] {
					n += len(k) + len(v) + 6
					delete(out.Labels, k)
				}
			}
			return n
		}},
		{"process.args", func() int {
			if out.Process == nil {
				return 0
			}
			return trimList(&out.Process.Args, 8)
		}},
		{"target.paths", func() int {
			if out.Target == nil {
				return 0
			}
			return trimList(&out.Target.Paths, 0)
		}},
		{"target.hosts", func() int {
			if out.Target == nil {
				return 0
			}
			return trimList(&out.Target.Hosts, 0)
		}},
		{"asset.mcp.args", func() int {
			if out.Asset == nil || out.Asset.MCP == nil {
				return 0
			}
			return trimList(&out.Asset.MCP.Args, 0)
		}},
		{"asset.detail", func() int {
			if out.Asset == nil || out.Asset.Detail == nil {
				return 0
			}
			n := size(out.Asset.Detail)
			out.Asset.Detail = nil
			return n
		}},
		{"summary", func() int {
			s := out.Summary
			if s == nil {
				return 0
			}
			return trimList(&s.Hosts, 0) + trimList(&s.HostClasses, 0) + trimList(&s.PathClasses, 0) +
				trimList(&s.MCPServers, 0) + trimList(&s.Installs, 0) + trimList(&s.Detections, 0) + trimList(&s.Flags, 0)
		}},
		{"health.coverage", func() int {
			if out.Health == nil {
				return 0
			}
			n := size(out.Health.Coverage) + size(out.Health.Surfaces)
			out.Health.Coverage, out.Health.Surfaces = nil, nil
			return n
		}},
		{"process.ancestors", func() int {
			p := out.Process
			if p == nil {
				return 0
			}
			return trimList(&p.Ancestors, 0) + trimList(&p.EnvMarkers, 0) + trimList(&p.Flags, 0)
		}},
		{"tool.input_keys", func() int {
			if out.Tool == nil {
				return 0
			}
			return trimList(&out.Tool.InputKeys, 0)
		}},
		{"health.counters", func() int {
			if out.Health == nil || out.Health.Counters == nil {
				return 0
			}
			n := size(out.Health.Counters)
			out.Health.Counters = nil
			return n
		}},
	}
	for _, st := range steps {
		if freed >= need {
			return
		}
		if n := st.fn(); n > 0 {
			freed += n
			r.note(st.name)
		}
	}
}

// trimList keeps the first keep entries and returns the bytes freed.
func trimList(l *[]string, keep int) int {
	if len(*l) <= keep {
		return 0
	}
	n := 0
	for _, s := range (*l)[keep:] {
		n += jsonLen(s) + 1
	}
	if keep == 0 {
		*l = nil
	} else {
		*l = (*l)[:keep]
	}
	return n
}
