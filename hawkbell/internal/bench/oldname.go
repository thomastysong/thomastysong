package bench

import "bytes"

// The project was renamed on 2026-11-12 from its working name, spoor, to
// hawkbell: paths, tables, tags, environment variables and key-domain
// strings changed with it, and rule ids SPR-<PACK>-<NNN> became
// HB-<PACK>-<NNN>. Session logs and reports recorded before then use the old
// spelling. Replayed as they are, the renamed rules no longer recognise the
// sensor's own files in them (the sensor-tamper rules match hawkbell's
// paths, not spoor's), and their rule ids do not join with the current
// ones. RewriteOldName rewrites such text the way the repository's own
// files were rewritten by the rename, so that a corpus recorded before it
// replays as if its sessions had run against hawkbell.

// oldNameGlobs are glob spellings of the old name (in tests, rule tests and
// sessions that probed path-spelling evasions) and the same kind of glob
// over the new name. They are tried in this order at each position.
var oldNameGlobs = [...][2]string{
	{"[s][p]oo[r]", "[h][a]wkbel[l]"},
	{"[s][p]oor", "[h][a]wkbell"},
	{"[sx]poor", "[hx]awkbell"},
	{"[s]poor", "[h]awkbell"},
	{"spoo[r]", "hawkbel[l]"},
	{"spo?r", "haw?bell"},
	{"sp?or", "ha?kbell"},
	{"sp*r", "ha*l"},
	{"sp*", "ha*"},
}

// oldNameLiterals are replaced, in this order, after the globs.
var oldNameLiterals = [...][2]string{
	{"https://github.com/thomastysong/spoor/security/advisories/new", "https://github.com/thomastysong/thomastysong/security/advisories/new"},
	{"github.com/thomastysong/spoor", "github.com/thomastysong/thomastysong/hawkbell"},
	{"SPOOR", "HAWKBELL"},
	{"Spoor", "Hawkbell"},
	{"spoor", "hawkbell"},
}

// RewriteOldName returns b with the project's working name rewritten to
// hawkbell. The steps, each over the result of the one before:
//
//  1. a glob spelling of the old name (oldNameGlobs) that is not preceded
//     by an ASCII letter or digit and not followed by an ASCII letter,
//     digit, "[" or "?" becomes the same glob over the new name;
//  2. the advisory URL, the module path and spoor, Spoor and SPOOR are
//     replaced (oldNameLiterals);
//  3. "SPR-" not preceded by an ASCII letter, digit or "_" becomes "HB-";
//  4. "SPRNC1" (the rule cache magic) becomes "HBNC1".
//
// It works on bytes, so text that is not UTF-8 passes through. b is not
// modified; when nothing changes, b itself is returned.
func RewriteOldName(b []byte) []byte {
	if !mayHoldOldName(b) {
		return b
	}
	out := rewriteGlobs(b)
	for _, l := range oldNameLiterals {
		out = bytes.ReplaceAll(out, []byte(l[0]), []byte(l[1]))
	}
	out = rewriteRuleIDPrefix(out)
	out = bytes.ReplaceAll(out, []byte("SPRNC1"), []byte("HBNC1"))
	if bytes.Equal(out, b) {
		return b
	}
	return out
}

// RewriteOldNameString is RewriteOldName for a string.
func RewriteOldNameString(s string) string {
	return string(RewriteOldName([]byte(s)))
}

// mayHoldOldName is a quick test: every step above needs "sp" or "SP" in
// some letter case, or "Sp".
func mayHoldOldName(b []byte) bool {
	return bytes.Contains(b, []byte("sp")) || bytes.Contains(b, []byte("SP")) ||
		bytes.Contains(b, []byte("Sp")) || bytes.Contains(b, []byte("[s"))
}

func asciiAlnum(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z'
}

func rewriteGlobs(b []byte) []byte {
	var out []byte
	last := 0
	for i := 0; i < len(b); {
		if b[i] != 's' && b[i] != '[' || i > 0 && asciiAlnum(b[i-1]) {
			i++
			continue
		}
		matched := false
		for _, g := range oldNameGlobs {
			from := g[0]
			if !bytes.HasPrefix(b[i:], []byte(from)) {
				continue
			}
			if j := i + len(from); j < len(b) && (asciiAlnum(b[j]) || b[j] == '[' || b[j] == '?') {
				continue
			}
			out = append(out, b[last:i]...)
			out = append(out, g[1]...)
			i += len(from)
			last = i
			matched = true
			break
		}
		if !matched {
			i++
		}
	}
	if out == nil {
		return append([]byte(nil), b...)
	}
	return append(out, b[last:]...)
}

func rewriteRuleIDPrefix(b []byte) []byte {
	const from, to = "SPR-", "HB-"
	var out []byte
	last := 0
	for i := 0; i+len(from) <= len(b); i++ {
		if b[i] != 'S' || !bytes.HasPrefix(b[i:], []byte(from)) {
			continue
		}
		if i > 0 && (asciiAlnum(b[i-1]) || b[i-1] == '_') {
			continue
		}
		out = append(out, b[last:i]...)
		out = append(out, to...)
		last = i + len(from)
		i = last - 1
	}
	if out == nil {
		return b
	}
	return append(out, b[last:]...)
}
