package format

import "strings"

// attackTactics maps Sigma-style tactic tags to ATT&CK Enterprise v20.1
// tactic ids and names (read from mitre-attack/attack-stix-data
// enterprise-attack-20.1.json). v19 renamed TA0005 from Defense Evasion to
// Stealth and added TA0112; the legacy tag spelling is kept as an alias so
// rules written against older Sigma taxonomies still map.
var attackTactics = map[string][2]string{
	"reconnaissance":       {"TA0043", "Reconnaissance"},
	"resource-development": {"TA0042", "Resource Development"},
	"initial-access":       {"TA0001", "Initial Access"},
	"execution":            {"TA0002", "Execution"},
	"persistence":          {"TA0003", "Persistence"},
	"privilege-escalation": {"TA0004", "Privilege Escalation"},
	"stealth":              {"TA0005", "Stealth"},
	"defense-evasion":      {"TA0005", "Stealth"},
	"credential-access":    {"TA0006", "Credential Access"},
	"discovery":            {"TA0007", "Discovery"},
	"lateral-movement":     {"TA0008", "Lateral Movement"},
	"collection":           {"TA0009", "Collection"},
	"command-and-control":  {"TA0011", "Command and Control"},
	"exfiltration":         {"TA0010", "Exfiltration"},
	"impact":               {"TA0040", "Impact"},
	"defense-impairment":   {"TA0112", "Defense Impairment"},
}

// attacksFromTags splits rule tags into OCSF attack objects and the rest.
// Tags follow Sigma style: attack.t1059.004, attack.execution,
// atlas.aml.t0051.001, atlas.aml.ta0005, owasp.asi05. Only ids are emitted:
// the tag is all a rule carries, and shipping a name table would mean
// shipping a copy of two matrices that change monthly. Everything that is
// not an ATT&CK or ATLAS reference is returned as a finding type.
func attacksFromTags(tags []string) (attacks []any, types []string) {
	for _, raw := range tags {
		tag := strings.ToLower(strings.TrimSpace(raw))
		if tag == "" {
			continue
		}
		if a := attackFromTag(tag); a != nil {
			if len(attacks) < maxRelated {
				attacks = append(attacks, a)
			}
			continue
		}
		if len(types) < maxRelated {
			types = append(types, tag)
		}
	}
	return attacks, types
}

func attackFromTag(tag string) map[string]any {
	switch {
	case strings.HasPrefix(tag, "attack."):
		rest := tag[len("attack."):]
		if t, sub, ok := techniqueID(rest, "T"); ok {
			return attackObj(AttackVersion, "", "", t, sub)
		}
		if id, ok := tacticID(rest, "TA"); ok {
			return attackObj(AttackVersion, id, "", "", "")
		}
		if tac, ok := attackTactics[strings.ReplaceAll(rest, "_", "-")]; ok {
			return attackObj(AttackVersion, tac[0], tac[1], "", "")
		}
	case strings.HasPrefix(tag, "atlas.aml."):
		rest := tag[len("atlas.aml."):]
		if t, sub, ok := techniqueID(rest, "AML.T"); ok {
			return attackObj(AtlasVersion, "", "", t, sub)
		}
		if id, ok := tacticID(rest, "AML.TA"); ok {
			return attackObj(AtlasVersion, id, "", "", "")
		}
	}
	return nil
}

func attackObj(version, tacticUID, tacticName, technique, sub string) map[string]any {
	a := map[string]any{"version": version}
	if tacticUID != "" {
		t := map[string]any{"uid": tacticUID}
		setStr(t, "name", tacticName)
		a["tactic"] = t
	}
	if technique != "" {
		a["technique"] = map[string]any{"uid": technique}
	}
	if sub != "" {
		a["sub_technique"] = map[string]any{"uid": sub}
	}
	return a
}

// techniqueID parses "t1059" or "t1059.004" into ("T1059", "T1059.004").
func techniqueID(s, prefix string) (technique, sub string, ok bool) {
	if len(s) < 5 || s[0] != 't' || !digits(s[1:5]) {
		return "", "", false
	}
	technique = prefix + s[1:5]
	switch {
	case len(s) == 5:
		return technique, "", true
	case len(s) == 9 && s[5] == '.' && digits(s[6:9]):
		return technique, technique + s[5:9], true
	}
	return "", "", false
}

// tacticID parses "ta0002" into prefix+"0002".
func tacticID(s, prefix string) (string, bool) {
	if len(s) != 6 || s[:2] != "ta" || !digits(s[2:]) {
		return "", false
	}
	return prefix + s[2:], true
}

func digits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}
