package privacy

import "strings"

// Version labels.
//
// The engine stamps every finding and heartbeat with the rule content that
// produced it: rules_version (rules.Set.Version, "pack@version" for every
// loaded pack, sorted and joined by ",") and rules_hash (a prefix of the
// content hash). Labels are free text and get the short-field cap
// (maxNameLen, 256 bytes), but rules_version grows by about 22 bytes per
// pack and passes 256 bytes at twelve packs; thirteen ship today. A cut
// version string makes a finding unattributable, which is the reason the
// label exists. These two keys therefore have their own bound, and only
// for a value made entirely of the version vocabulary:
//
//	rules_version  pack "@" version, joined by ","; pack names in the
//	               rules package's alphabet (a-z 0-9 _ - .), versions in
//	               A-Z a-z 0-9 . _ + - (semantic and calendar versions),
//	               each 1..64 bytes, the whole at most 1 KiB
//	rules_hash     lower-case hex, 1..128 digits
//
// Anything else under these keys (a version with other characters, a
// longer value, text from a producer that is not the rules engine) is an
// ordinary free-text label with the ordinary cap, so the larger bound
// cannot carry other content. A vocabulary value still goes through the
// whole redaction pipeline; the exemption applies only if that leaves it
// unchanged, and it changes only the cap. The line cap (fitLine) still
// applies: on an oversized record the label can be cut like any other
// field, and is then named in "truncated".

const (
	labelRulesVersion = "rules_version"
	labelRulesHash    = "rules_hash"
	// maxVersionLabel is the rules_version bound: about forty packs.
	maxVersionLabel = 1 << 10
	// maxVersionPart is the rules package's own limit on a pack name and on
	// a pack version.
	maxVersionPart = 64
	// maxHashLabel fits a hex SHA-512 digest.
	maxHashLabel = 128
)

// versionLabelCap returns the cap for label key when value is in that
// key's version vocabulary; ok is false for every other key or value.
func versionLabelCap(key, value string) (limit int, ok bool) {
	switch key {
	case labelRulesVersion:
		return maxVersionLabel, validRulesVersion(value)
	case labelRulesHash:
		return maxHashLabel, validHexLabel(value)
	}
	return 0, false
}

// validRulesVersion reports a rules.Set.Version string: "pack@version"
// entries joined by ",".
func validRulesVersion(s string) bool {
	if s == "" || len(s) > maxVersionLabel {
		return false
	}
	for len(s) > 0 {
		entry, rest, more := strings.Cut(s, ",")
		if more && rest == "" {
			return false // trailing separator
		}
		pack, ver, ok := strings.Cut(entry, "@")
		if !ok || !validPackName(pack) || !validPackVersion(ver) {
			return false
		}
		s = rest
	}
	return true
}

// validPackName is the rules package's pack-name alphabet.
func validPackName(s string) bool {
	if s == "" || len(s) > maxVersionPart {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// validPackVersion accepts semantic and calendar versions ("1.4.2",
// "2026.11.0", "1.0.0-rc.1+build.5"). The rules package itself allows any
// character but space and comma; a version outside this alphabet makes the
// label ordinary free text rather than being accepted at the larger bound.
func validPackVersion(s string) bool {
	if s == "" || len(s) > maxVersionPart {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '+' || c == '-') {
			return false
		}
	}
	return true
}

func validHexLabel(s string) bool {
	if s == "" || len(s) > maxHashLabel {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// labelStr redacts one label value: a short free-text value, or a version
// label at its own bound (see above).
func (r *run) labelStr(key, value string) string {
	name := joinName("labels", key)
	if limit, ok := versionLabelCap(key, value); ok {
		if out := r.valueStr(value, name, limit); out == value {
			return out
		}
		// Redaction changed it, so it is not a plain version string any
		// more: it is capped as free text below.
	}
	return r.valueStr(value, name, maxNameLen)
}

// slotCap is the per-string cap the safety pass applies to a slot whose
// redacted value is value. It is decided on the value as it stands, not
// on what labels() saw, so whatever reaches the larger bound has passed
// the vocabulary check after every rewrite.
func (r *run) slotCap(name, value string) int {
	if key, ok := strings.CutPrefix(name, "labels."); ok {
		if limit, ok := versionLabelCap(key, value); ok {
			return limit
		}
	}
	return r.s.maxField
}
