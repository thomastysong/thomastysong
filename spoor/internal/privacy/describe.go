package privacy

import (
	"fmt"
	"strings"
)

// Describe returns plain-language lines for `spoor privacy show`: what is
// collected, in which profile, and what never leaves the machine. The text
// is written for the person whose machine this is.
func (p *Policy) Describe() []string {
	s := p.settings()
	var out []string
	add := func(format string, a ...any) { out = append(out, fmt.Sprintf(format, a...)) }

	add("Privacy profile: %s.", s.profile)
	add("Detection runs on this machine. The profile only decides what is written for shipping; nothing is uploaded by this program itself.")
	switch s.profile {
	case ProfileMinimal:
		add("Leaves this machine: detection findings, inventory of AI tools and their configuration, posture check results, sensor health, and per-session summaries (counts, tool kinds, hosts contacted, classes of sensitive paths touched).")
		add("Stays on this machine: agent activity (commands, file paths, URLs, prompts). It is kept in a local ring buffer. Exception: when a finding is raised, the few preceding steps of that session are shipped with it, with commands redacted and no prompt text, tool input or tool output.")
	case ProfileStandard:
		add("Leaves this machine: everything in the minimal profile, plus agent activity: tool calls with commands redacted structurally (credentials removed from flags, assignments, headers, URLs and piped input), file paths, hosts, and URLs without query strings.")
		add("Not shipped in this profile: prompt text, web search queries, tool input and tool output. Only the names of tool arguments, lengths rounded up to a power of four, and keyed digests are shipped.")
	case ProfileFull:
		add("Leaves this machine: everything in the standard profile, plus prompt text, web search queries, tool input (which includes the beginning of file contents an agent writes) and the beginning of tool output (at most %d bytes per field), all with credentials redacted.", s.maxField)
		add("Redaction of free text is pattern-based: \"password=hunter2\" is removed, \"my password is hunter2\" is not. Treat this profile as content collection.")
	}
	if s.profile == ProfileFull {
		add("Never leaves this machine in any profile: values of detected credentials (or any unkeyed fingerprint of them), the path of the agent's session transcript, and anything from excluded sessions.")
	} else {
		add("Never leaves this machine in this profile: values of detected credentials (or any unkeyed fingerprint of them), prompt text, tool output (except the first %d bytes of a failed tool's error message, redacted), file contents being written, the path of the agent's session transcript, and anything from excluded sessions.", maxErrStd)
	}
	add("Paths under your home directory are shown as ~/... .")
	if s.key != nil {
		id := s.keyID
		if id == "" {
			id = "unnamed"
		}
		add("A tenant key is configured (key id %s). Content digests (of prompts, tool input and output of at least %d characters) and identifiers are HMAC-SHA-256 with that key, so the log store cannot look values up by hashing guesses.", id, DigestMinLen)
		add("Limit of the key: it is present on every machine of the organisation, so it protects against readers of the central log store and against linking across organisations, not against someone with administrator rights on a machine.")
	} else {
		add("No tenant key is configured: no digest of any content and no pseudonym is shipped, and credential markers carry no fingerprint.")
	}
	switch {
	case s.pseudo && s.key != nil:
		add("User names are replaced by keyed pseudonyms (u_ followed by 16 hex digits); only the holder of the tenant key can link a pseudonym to a person.")
	case s.pseudo:
		add("User pseudonyms are requested but no tenant key is configured, so user names are removed instead.")
	default:
		add("User names are shipped as they are.")
	}
	if p != nil {
		ex := p.Exclude
		if len(ex.Paths)+len(ex.Repos)+len(ex.Users) == 0 {
			add("Exclusions: none.")
		} else {
			add("Excluded sessions are dropped before any content is looked at; only a count is kept.")
			if len(ex.Paths) > 0 {
				add("Excluded working directories: %s.", strings.Join(quoteAll(ex.Paths), ", "))
			}
			if len(ex.Repos) > 0 {
				add("Excluded repositories: %s.", strings.Join(quoteAll(ex.Repos), ", "))
			}
			if len(ex.Users) > 0 {
				add("Excluded accounts: %s.", strings.Join(quoteAll(ex.Users), ", "))
			}
		}
	}
	add("Detection evidence is limited to a fixed list of non-content fields (redacted command, paths, hosts, classes, counts, names and ids)%s.", map[bool]string{true: "; in this profile prompt text and tool output may be evidence, redacted and capped", false: "; prompt text and tool output are never evidence in this profile"}[s.profile == ProfileFull])
	add("Each record is at most %d bytes as written; longer fields are cut and named in the record's \"truncated\" list.", s.maxLine)
	return out
}

func quoteAll(in []string) []string {
	out := make([]string, 0, len(in))
	for i, s := range in {
		if i >= 32 {
			out = append(out, fmt.Sprintf("and %d more", len(in)-i))
			break
		}
		out = append(out, fmt.Sprintf("%q", capBytes(cleanUTF8(s), 256)))
	}
	return out
}
