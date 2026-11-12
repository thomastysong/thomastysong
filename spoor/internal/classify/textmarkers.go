package classify

import (
	"encoding/base64"
	"regexp"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// Instruction-override markers reported in TextFindings.Markers. A marker
// says the text is SHAPED like an attempt to steer an agent; whether it is an
// attack depends on where the text came from (a web page, a tool result, the
// user's own instruction file), which is the caller's knowledge.
const (
	MarkerIgnorePrevious       = "ignore_previous"
	MarkerSystemPromptOverride = "system_prompt_override"
	MarkerDoNotTellUser        = "do_not_tell_user"
	MarkerExfilInstruction     = "exfil_instruction"
	MarkerToolCallInjection    = "tool_call_injection"
	MarkerRoleTagInjection     = "role_tag_injection"
	MarkerBase64Blob           = "base64_blob_instruction"
	MarkerHiddenHTMLComment    = "hidden_html_comment_instruction"
	MarkerMarkdownImageExfil   = "markdown_image_exfil"
)

type markerID uint8

const (
	mkIgnorePrevious markerID = iota
	mkSystemPromptOverride
	mkDoNotTellUser
	mkExfilInstruction
	mkToolCallInjection
	mkRoleTagInjection
	mkBase64Blob
	mkHiddenHTMLComment
	mkMarkdownImageExfil
	mkCount
)

var markerNames = [mkCount]string{
	MarkerIgnorePrevious, MarkerSystemPromptOverride, MarkerDoNotTellUser,
	MarkerExfilInstruction, MarkerToolCallInjection, MarkerRoleTagInjection,
	MarkerBase64Blob, MarkerHiddenHTMLComment, MarkerMarkdownImageExfil,
}

// MarkerVocabulary returns every value TextFindings.Markers can hold.
func MarkerVocabulary() []string {
	out := make([]string, len(markerNames))
	copy(out, markerNames[:])
	return out
}

type markerSet uint16

func (m *markerSet) add(id markerID)     { *m |= 1 << id }
func (m markerSet) has(id markerID) bool { return m&(1<<id) != 0 }

func (m markerSet) names() []string {
	if m == 0 {
		return nil
	}
	out := make([]string, 0, 2)
	for id := markerID(0); id < mkCount; id++ {
		if m.has(id) {
			out = append(out, markerNames[id])
		}
	}
	return out
}

// seqRule is a phrase pattern over words: the first step must match a word,
// and each later step must match a word at most gap words after the previous
// match. Matching words instead of characters makes the rules indifferent to
// punctuation, line breaks and filler ("ignore ALL of the previous
// instructions"), and it runs in one linear pass with no regular expression.
type seqRule struct {
	marker markerID
	steps  []seqStep
}

type seqStep struct {
	gap   int
	words map[string]bool
}

func ws(words ...string) map[string]bool {
	m := make(map[string]bool, len(words))
	for _, w := range words {
		m[w] = true
	}
	return m
}

func rule(marker markerID, first map[string]bool, rest ...seqStep) seqRule {
	steps := append([]seqStep{{0, first}}, rest...)
	return seqRule{marker, steps}
}

func then(gap int, words ...string) seqStep { return seqStep{gap, ws(words...)} }

// Word lists shared by several rules. They are static data; the sets the
// rules match against are built with the rules, on first use.
var (
	wIgnore       = []string{"ignore", "disregard", "forget", "ignoring", "disregarding"}
	wOverride     = []string{"override", "bypass", "discard", "neglect", "overlook", "dismiss"}
	wStrongQual   = []string{"previous", "prior", "above", "earlier", "preceding", "former", "foregoing", "original", "initial", "system", "safety"}
	wWeakQual     = []string{"all", "any", "every", "your", "these", "those"}
	wInstructions = []string{"instruction", "instructions", "prompt", "prompts", "direction", "directions", "directive", "directives", "guideline", "guidelines", "programming", "training", "safeguards", "guardrails"}
	wRulesLike    = []string{"rule", "rules", "command", "commands", "context", "messages", "restrictions", "constraints", "policies", "orders"}
	wTellVerbs    = []string{"tell", "inform", "mention", "notify", "alert", "reveal", "disclose", "warn"}
	wTellGerunds  = []string{"telling", "informing", "notifying", "alerting", "mentioning", "warning"}
	wUser         = []string{"user", "users", "human", "humans", "operator", "anyone", "anybody", "them", "developer"}
	wStash        = []string{"env", "dotenv", "ssh", "id_rsa", "id_ed25519", "credentials", "secrets", "passwords", "tokens", "apikeys", "api_keys", "keys", "cookies", "keychain", "wallet", "history", "conversation", "environ", "environment", "kubeconfig", "netrc", "npmrc", "aws"}
	wSinks        = []string{"http", "https", "webhook", "pastebin", "ftp", "attacker", "mailto", "gist", "discord", "telegram", "slack"}
	wJailbreak    = []string{"dan", "jailbroken", "unrestricted", "unfiltered", "uncensored"}
)

func concat(lists ...[]string) []string {
	var out []string
	for _, l := range lists {
		out = append(out, l...)
	}
	return out
}

// buildSeqRules returns the phrase rules. It runs once per process, on the
// first scan (seqRuleIndex): the rules hold about a hundred small word sets,
// and building them at package init would cost every hook invocation.
func buildSeqRules() []seqRule {
	return []seqRule{
		// ---- ignore_previous ----
		// "ignore the previous instructions", "disregard all prior rules".
		rule(mkIgnorePrevious, ws(wIgnore...), then(3, wStrongQual...), then(3, concat(wInstructions, wRulesLike)...)),
		// The weaker verbs are everyday technical vocabulary ("this overrides
		// the previous rules" is CSS), so they need an unambiguous object.
		rule(mkIgnorePrevious, ws(wOverride...), then(3, wStrongQual...), then(3, wInstructions...)),
		// "ignore all instructions", "forget your guidelines": the weak qualifiers
		// only count with an unambiguous object ("ignore all rules" is lint talk).
		rule(mkIgnorePrevious, ws(wIgnore...), then(1, wWeakQual...), then(2, wInstructions...)),
		rule(mkIgnorePrevious, ws("forget"), then(1, "everything", "all", "anything", "what"), then(4, "above", "before", "previously", "told", "said", "learned", "instructed", "prior", "earlier")),
		rule(mkIgnorePrevious, ws("do"), then(0, "not"), then(0, "follow", "obey"), then(2, concat(wStrongQual, wWeakQual)...), then(2, wInstructions...)),
		rule(mkIgnorePrevious, ws("instructions", "instruction"), then(1, "above", "before"), then(3, "void", "invalid", "obsolete", "superseded", "outdated", "cancelled", "canceled", "revoked", "overridden", "ignored")),

		// ---- system_prompt_override ----
		rule(mkSystemPromptOverride, ws("new", "updated", "revised", "replacement"), then(0, "system"), then(0, "prompt", "message", "instructions", "instruction", "directive")),
		rule(mkSystemPromptOverride, ws("system"), then(0, "override", "overwrite")),
		rule(mkSystemPromptOverride, ws("override", "overriding", "overwrite", "replace", "replacing"), then(2, "system"), then(0, "prompt", "instructions", "message")),
		rule(mkSystemPromptOverride, ws("you"), then(0, "are"), then(0, "now"), then(3, concat(wJailbreak, []string{"evil", "free", "developer", "admin", "root", "god"})...)),
		rule(mkSystemPromptOverride, ws("you"), then(0, "are"), then(0, "no"), then(0, "longer"), then(3, "bound", "restricted", "limited", "constrained", "required", "obligated", "subject")),
		rule(mkSystemPromptOverride, ws("from"), then(0, "now"), then(0, "on"), then(1, "you"), then(4, "act", "behave", "respond", "answer", "obey", "ignore", "pretend", "roleplay", "only", "always", "never")),
		rule(mkSystemPromptOverride, ws(concat(wJailbreak, []string{"god", "jailbreak"})...), then(0, "mode"), then(1, "enabled", "activated", "on", "engaged", "active", "unlocked")),
		rule(mkSystemPromptOverride, ws("enter", "enable", "activate", "switch"), then(2, concat(wJailbreak, []string{"god", "jailbreak"})...), then(0, "mode")),
		rule(mkSystemPromptOverride, ws("reveal", "print", "show", "repeat", "output", "display", "leak", "reproduce", "recite", "dump", "disclose"), then(2, "your", "the"), then(0, "system", "initial", "hidden", "original", "secret", "full", "entire", "exact"), then(1, "prompt", "instructions", "instruction", "directives")),
		rule(mkSystemPromptOverride, ws("you"), then(0, "have"), then(0, "no"), then(2, "restrictions", "rules", "guidelines", "limitations", "limits", "filters")),
		rule(mkSystemPromptOverride, ws("act", "behave", "respond", "pretend"), then(1, "as", "like"), then(3, wJailbreak...)),
		rule(mkSystemPromptOverride, ws("end"), then(0, "of"), then(0, "system"), then(0, "prompt", "message", "instructions")),
		rule(mkSystemPromptOverride, ws("instructions", "message", "directive", "update"), then(0, "from"), then(1, "anthropic", "openai", "creators")),

		// ---- do_not_tell_user ----
		rule(mkDoNotTellUser, ws("do"), then(0, "not"), then(1, wTellVerbs...), then(5, wUser...)),
		rule(mkDoNotTellUser, ws("dont", "never"), then(1, wTellVerbs...), then(5, wUser...)),
		rule(mkDoNotTellUser, ws("do"), then(0, "not"), then(0, "mention", "reveal", "disclose"), then(0, "this", "these", "that", "it", "any"), then(1, "instruction", "instructions", "message", "step", "steps", "action", "actions", "to", "in")),
		rule(mkDoNotTellUser, ws("without"), then(0, wTellGerunds...), then(2, wUser...)),
		// Stealth, not consent: "without the user's approval" is what careful
		// instruction files say and must not match.
		rule(mkDoNotTellUser, ws("without"), then(2, "user", "users", "human", "their"), then(1, "knowledge", "noticing", "knowing", "awareness", "realizing")),
		rule(mkDoNotTellUser, ws("hide", "conceal", "withhold", "keep"), then(3, "from"), then(2, "user", "users", "human", "humans")),
		rule(mkDoNotTellUser, ws("user", "human"), then(1, "must", "should", "shall", "can", "need", "does"), then(0, "not", "never"), then(1, "know", "see", "notice", "realize", "suspect", "learn", "find")),
		rule(mkDoNotTellUser, ws("user", "human"), then(1, "must", "should", "shall", "can", "need"), then(0, "not", "never"), then(0, "be"), then(1, "told", "informed", "aware", "notified", "alerted", "shown")),
		rule(mkDoNotTellUser, ws("silently", "secretly", "covertly", "quietly", "discreetly", "stealthily"), then(2, "send", "upload", "post", "exfiltrate", "transmit", "forward", "copy", "collect", "read", "include", "append")),

		// ---- exfil_instruction ----
		// A transfer verb, a store of secrets, and an external sink. Collections
		// only ("credentials", "keys"): "send your API key to https://api..." is
		// what every API guide says.
		rule(mkExfilInstruction, ws("send", "post", "upload", "forward", "exfiltrate", "transmit", "leak", "email", "mail", "submit", "deliver", "paste", "transfer"), then(8, wStash...), then(8, wSinks...)),
		rule(mkExfilInstruction, ws("append", "include", "embed", "encode", "attach", "add", "put", "insert", "place"), then(8, wStash...), then(8, "url", "query", "parameter", "param", "querystring")),

		// ---- tool_call_injection (phrases; forged markup is matched as text) ----
		// "tool" only: "you must run the command" and "call the function first"
		// are what ordinary documentation says.
		rule(mkToolCallInjection, ws("you"), then(0, "must", "should", "need", "shall", "have", "will"), then(2, "call", "use", "invoke", "execute", "run", "trigger"), then(4, "tool", "mcp")),
		rule(mkToolCallInjection, ws("call", "use", "invoke", "run", "execute"), then(3, "tool", "mcp"), then(6, "without", "immediately", "silently", "automatically")),
		rule(mkToolCallInjection, ws("before", "prior"), then(1, "using", "calling", "invoking", "responding", "answering", "replying", "proceeding", "continuing", "any"), then(6, "read", "cat", "fetch", "call", "invoke", "send", "pass", "execute", "run"), then(6, "mcp", "ssh", "env", "id_rsa", "credentials", "config", "json", "tool")),

		// ---- base64_blob_instruction (the phrase; blobs are decoded separately) ----
		rule(mkBase64Blob, ws("decode", "decoding", "b64decode", "atob"), then(6, "and", "then"), then(2, "run", "execute", "eval", "follow", "obey", "pipe", "apply", "perform")),
	}
}

var (
	seqIndexOnce sync.Once
	seqIndex     map[string][]*seqRule
)

// seqRuleIndex builds the rules and indexes them by the words their first
// step accepts.
func seqRuleIndex() map[string][]*seqRule {
	seqIndexOnce.Do(func() {
		rules := buildSeqRules()
		idx := map[string][]*seqRule{}
		for i := range rules {
			r := &rules[i]
			for w := range r.steps[0].words {
				idx[w] = append(idx[w], r)
			}
		}
		seqIndex = idx
	})
	return seqIndex
}

// forgedMarkup are literal strings (matched in lower-cased text) that imitate
// the control syntax of chat templates and tool-call protocols.
var forgedMarkup = []struct {
	marker markerID
	text   string
}{
	{mkRoleTagInjection, "<|im_start|>"}, {mkRoleTagInjection, "<|im_end|>"},
	{mkRoleTagInjection, "<|system|>"}, {mkRoleTagInjection, "<|user|>"},
	{mkRoleTagInjection, "<|assistant|>"}, {mkRoleTagInjection, "<|endoftext|>"},
	{mkRoleTagInjection, "[inst]"}, {mkRoleTagInjection, "[/inst]"},
	{mkRoleTagInjection, "<<sys>>"}, {mkRoleTagInjection, "<</sys>>"},
	{mkRoleTagInjection, "<|start_header_id|>"}, {mkRoleTagInjection, "<|end_header_id|>"},
	{mkRoleTagInjection, "<|eot_id|>"}, {mkRoleTagInjection, "<start_of_turn>"},
	{mkRoleTagInjection, "<end_of_turn>"}, {mkRoleTagInjection, "<|begin_of_text|>"},
	{mkRoleTagInjection, "<system>"}, {mkRoleTagInjection, "</system>"},
	{mkRoleTagInjection, "<system-reminder>"}, {mkRoleTagInjection, "</system-reminder>"},
	{mkRoleTagInjection, "<system_instruction>"}, {mkRoleTagInjection, "<important>"},
	{mkRoleTagInjection, "<assistant>"}, {mkRoleTagInjection, "</assistant>"},
	{mkRoleTagInjection, "<human>"}, {mkRoleTagInjection, "</human>"},
	{mkRoleTagInjection, "\n\nhuman:"}, {mkRoleTagInjection, "\n\nassistant:"},
	{mkRoleTagInjection, "### system:"}, {mkRoleTagInjection, "### instruction:"},
	{mkToolCallInjection, "<function_calls>"}, {mkToolCallInjection, "<invoke name="},
	{mkToolCallInjection, "</invoke>"}, {mkToolCallInjection, "<tool_use>"},
	{mkToolCallInjection, "<tool_call>"}, {mkToolCallInjection, "</tool_call>"},
	{mkToolCallInjection, "<|tool_call|>"}, {mkToolCallInjection, "<|python_tag|>"},
	{mkToolCallInjection, "<tool_code>"}, {mkToolCallInjection, "[tool_call]"},
	{mkToolCallInjection, "<function="}, {mkToolCallInjection, "<|tool_calls_section_begin|>"},
}

var (
	textReOnce    sync.Once
	htmlCommentRe *regexp.Regexp
	mdCommentRe   *regexp.Regexp
	imageRe       *regexp.Regexp
	base64RunRe   *regexp.Regexp
	dropperRe     *regexp.Regexp
)

// maxImageURL bounds the image URL a regex capture hands to the URL checks
// (see textRegexes). Comment bodies are scanned whole: ScanText's input cap
// already bounds them, and a length bound would let padding hide an
// instruction.
const maxImageURL = 2000

// clipBytes cuts s to at most n bytes without splitting a UTF-8 sequence.
func clipBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	for n > 0 && n < len(s) && s[n]&0xC0 == 0x80 {
		n--
	}
	return s[:n]
}

func textRegexes() {
	// Go's RE2 rejects counted repeats above 1000 ({1,4096} panics in
	// MustCompile), so lengths are bounded after matching instead.
	textReOnce.Do(func() {
		htmlCommentRe = regexp.MustCompile(`(?s)<!--(.*?)-->`)
		mdCommentRe = regexp.MustCompile(`(?m)^\[(?://|comment)\]:\s*(?:#|<>)\s*[("](.+)[)"]\s*$`)
		imageRe = regexp.MustCompile(`(?i)(?:!\[[^\]]{0,200}\]\(\s*<?|<img\b[^>]{0,400}?\bsrc\s*=\s*["']?)(https?://[^)\s"'>]+)`)
		base64RunRe = regexp.MustCompile(`[A-Za-z0-9+/_\-]{40,}={0,2}`)
		dropperRe = regexp.MustCompile(`(?i)\b(?:curl|wget|bash|/bin/sh|sh -c|eval|powershell|iex|invoke-expression|invoke-webrequest|nc -|python3? -c|base64 -d|osascript|chmod \+x)\b`)
	})
}

// aiTerms name an assistant being addressed. "agent" and "model" are absent:
// they are ordinary programming words.
var aiTerms = lazySet{list: []string{"ai", "ais", "assistant", "assistants", "llm", "llms", "claude", "copilot", "cursor", "gemini", "codex", "chatgpt", "gpt"}}

var imperativeTerms = lazySet{list: []string{"must", "should", "please", "always", "never", "ignore", "execute", "send", "fetch", "download", "install", "dont"}}

// badgeHosts serve status badges, whose URLs legitimately carry long query
// strings. Dynamic shields.io badges are excluded from the exemption because
// they make the badge server fetch a caller-supplied URL.
var badgeHosts = lazySet{list: []string{
	"img.shields.io", "shields.io", "badgen.net",
	"codecov.io", "coveralls.io", "sonarcloud.io",
	"badge.fury.io", "api.codeclimate.com", "app.codacy.com",
	"github.com", "raw.githubusercontent.com",
	"user-images.githubusercontent.com", "github-readme-stats.vercel.app",
}}

// scanMarkers adds every marker found in text. full enables the structural
// checks (comments, images, base64 blobs) that only make sense for the
// original text, not for text that was itself decoded from a hidden channel.
func scanMarkers(text string, ms *markerSet, full bool) {
	low := normalizeForMarkers(text)
	words := tokenize(low)
	matchSeqRules(words, ms)
	for _, fm := range forgedMarkup {
		if !ms.has(fm.marker) && strings.Contains(low, fm.text) {
			ms.add(fm.marker)
		}
	}
	if !full {
		return
	}
	textRegexes()
	if strings.Contains(text, "<!--") || strings.Contains(text, "]:") {
		scanComments(text, ms)
	}
	if strings.Contains(low, "](") || strings.Contains(low, "<img") {
		scanImages(text, ms)
	}
	if !ms.has(mkBase64Blob) {
		scanBase64(text, ms)
	}
}

// tokenize splits lower-cased text into words: ASCII letters and digits,
// underscores, and non-ASCII letters. Apostrophes inside a word are dropped
// so "don't" and "user's" become "dont" and "users".
func tokenize(low string) []string {
	words := make([]string, 0, len(low)/6+1)
	start := -1
	apos := false
	flush := func(end int) {
		if start < 0 {
			return
		}
		w := low[start:end]
		if apos {
			w = strings.NewReplacer("'", "", "’", "").Replace(w)
		}
		if w != "" {
			words = append(words, w)
		}
		start, apos = -1, false
	}
	for i := 0; i < len(low); {
		c := low[i]
		if c < utf8.RuneSelf {
			switch {
			case c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_':
				if start < 0 {
					start = i
				}
			case c == '\'' && start >= 0 && i+1 < len(low) && low[i+1] >= 'a' && low[i+1] <= 'z':
				apos = true
			default:
				flush(i)
			}
			i++
			continue
		}
		r, size := utf8.DecodeRuneInString(low[i:])
		switch {
		case r == '’' && start >= 0:
			apos = true
		case unicode.IsLetter(r) || unicode.IsMark(r):
			if start < 0 {
				start = i
			}
		default:
			flush(i)
		}
		i += size
	}
	flush(len(low))
	return words
}

func matchSeqRules(words []string, ms *markerSet) {
	idx := seqRuleIndex()
	for i, w := range words {
		rules := idx[w]
		if rules == nil {
			continue
		}
	nextRule:
		for _, r := range rules {
			if ms.has(r.marker) {
				continue
			}
			pos := i
			for _, st := range r.steps[1:] {
				found := false
				for j := pos + 1; j <= pos+1+st.gap && j < len(words); j++ {
					if st.words[words[j]] {
						pos, found = j, true
						break
					}
				}
				if !found {
					continue nextRule
				}
			}
			ms.add(r.marker)
		}
	}
}

// scanComments looks for instructions in text a rendered page does not show:
// HTML comments and the Markdown link-definition idiom for comments.
func scanComments(text string, ms *markerSet) {
	if ms.has(mkHiddenHTMLComment) {
		return
	}
	bodies := make([]string, 0, 8)
	for _, m := range htmlCommentRe.FindAllStringSubmatch(text, 64) {
		bodies = append(bodies, m[1])
	}
	for _, m := range mdCommentRe.FindAllStringSubmatch(text, 64) {
		bodies = append(bodies, m[1])
	}
	for _, body := range bodies {
		low := normalizeForMarkers(body)
		words := tokenize(low)
		var inner markerSet
		matchSeqRules(words, &inner)
		if inner != 0 {
			*ms |= inner
			ms.add(mkHiddenHTMLComment)
			return
		}
		// An assistant addressed by name and told to do something.
		for i, w := range words {
			if !aiTerms.has(w) {
				continue
			}
			for j := i + 1; j <= i+4 && j < len(words); j++ {
				if imperativeTerms.has(words[j]) {
					ms.add(mkHiddenHTMLComment)
					return
				}
			}
		}
	}
}

// scanImages looks for remote images whose URL can carry data out when the
// agent's output is rendered: a long or templated query string, a long
// encoded path segment, or a credential.
func scanImages(text string, ms *markerSet) {
	if ms.has(mkMarkdownImageExfil) {
		return
	}
	for _, m := range imageRe.FindAllStringSubmatch(text, 64) {
		u := clipBytes(m[1], maxImageURL)
		p := splitURL(u)
		suspicious := false
		badge := badgeHosts.has(normalizeHost(p.hostport)) && !strings.Contains(p.path, "/dynamic") && !strings.Contains(p.path, "/endpoint")
		if p.hasQuery {
			if strings.ContainsAny(p.query, "{}$<[") || strings.Contains(strings.ToLower(p.query), "%7b") {
				suspicious = true
			}
			for _, pair := range strings.Split(p.query, "&") {
				if badge {
					break
				}
				if eq := strings.IndexByte(pair, '='); eq >= 0 && len(pair)-eq-1 >= 40 {
					suspicious = true
				} else if eq < 0 && len(pair) >= 40 {
					suspicious = true
				}
			}
		}
		if strings.ContainsAny(p.path, "{}$") {
			suspicious = true
		}
		for _, seg := range strings.Split(p.path, "/") {
			if len(seg) >= 64 && !strings.Contains(seg, ".") {
				suspicious = true
			}
		}
		if !suspicious && len(FindSecrets(u)) > 0 {
			suspicious = true
		}
		if suspicious {
			ms.add(mkMarkdownImageExfil)
			return
		}
	}
}

// scanBase64 decodes base64 runs and reports those whose plaintext is an
// instruction or a command: text hidden from a reader but trivially readable
// by a model.
func scanBase64(text string, ms *markerSet) {
	if len(text) < 40 {
		return
	}
	for _, run := range base64RunRe.FindAllString(text, 32) {
		if len(run) > 8192 {
			run = run[:8192]
		}
		plain := decodeBase64Loose(run)
		if len(plain) < 24 || !mostlyPrintable(plain) {
			continue
		}
		var inner markerSet
		matchSeqRules(tokenize(normalizeForMarkers(plain)), &inner)
		if inner != 0 || dropperRe.MatchString(plain) {
			*ms |= inner
			ms.add(mkBase64Blob)
			return
		}
	}
}

// decodeBase64Loose tries the standard and URL alphabets, with or without
// padding, and returns "" when none decodes.
func decodeBase64Loose(s string) string {
	s = strings.TrimRight(s, "=")
	if n := len(s) % 4; n == 1 {
		s = s[:len(s)-1]
	}
	enc := base64.RawStdEncoding
	if strings.ContainsAny(s, "-_") {
		if strings.ContainsAny(s, "+/") {
			return ""
		}
		enc = base64.RawURLEncoding
	}
	b, err := enc.DecodeString(s)
	if err != nil {
		return ""
	}
	return string(b)
}
