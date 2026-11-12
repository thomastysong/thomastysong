package rules

import (
	"strconv"
	"strings"
	"time"
)

// Suppression is an operator exception: a matching detection is not
// emitted and, in guard mode, its response is not applied. Suppressions do
// not change session state (flags are still set), because the behaviour
// still happened.
type Suppression struct {
	// RuleID is a rule id or a glob over rule ids ("SPR-NET-*", "*").
	RuleID string `json:"rule"`
	// Match maps field names (as in Fields) to globs; every entry must
	// match. For a list field any element may match. "*" matches any
	// sequence, "?" one character; matching is case-sensitive.
	Match map[string]string `json:"match,omitempty"`
	// Expires ends the exception; zero means it never expires.
	Expires time.Time `json:"expires,omitzero"`
	Reason  string    `json:"reason"`
	// Tags limits the exception to hosts whose configured tags include at
	// least one of these (Options.HostTags); empty applies everywhere.
	Tags []string `json:"tags,omitempty"`
}

func (s *Suppression) applies(ruleID string, fields map[string]any, now time.Time, hostTags []string) bool {
	if !s.Expires.IsZero() && !now.Before(s.Expires) {
		return false
	}
	if !glob(s.RuleID, ruleID) {
		return false
	}
	if len(s.Tags) > 0 && !intersects(s.Tags, hostTags) {
		return false
	}
	for field, pat := range s.Match {
		if !fieldGlob(fields[field], pat) {
			return false
		}
	}
	return true
}

func intersects(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

func fieldGlob(v any, pat string) bool {
	switch t := v.(type) {
	case string:
		return t != "" && glob(pat, t)
	case []string:
		for _, s := range t {
			if glob(pat, s) {
				return true
			}
		}
		return false
	case bool:
		return glob(pat, strconv.FormatBool(t))
	case float64:
		return glob(pat, strconv.FormatFloat(t, 'f', -1, 64))
	}
	return false
}

// glob matches s against a pattern of literal text, "*" (any sequence,
// including empty and including "/") and "?" (one byte). It runs in
// O(len(pat) * len(s)) with the classic single-backtrack algorithm.
func glob(pat, s string) bool {
	if pat == "*" {
		return true
	}
	if !strings.ContainsAny(pat, "*?") {
		return pat == s
	}
	p, i := 0, 0
	star, mark := -1, 0
	for i < len(s) {
		switch {
		case p < len(pat) && (pat[p] == '?' || pat[p] == s[i]):
			p++
			i++
		case p < len(pat) && pat[p] == '*':
			star, mark = p, i
			p++
		case star >= 0:
			p = star + 1
			mark++
			i = mark
		default:
			return false
		}
	}
	for p < len(pat) && pat[p] == '*' {
		p++
	}
	return p == len(pat)
}
