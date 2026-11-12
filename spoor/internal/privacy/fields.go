package privacy

import (
	"encoding/json"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/thomastysong/spoor/internal/event"
)

// Field policies, one method per part of the record. Each method applies
// the rule for its fields; the reflection-based safety pass afterwards
// covers every string again (pattern redaction, fingerprints, home paths,
// UTF-8, per-field cap), so a field forgotten here is still redacted by
// pattern, just not structurally.

const (
	maxListLen   = 64  // entries kept in emitted lists (paths, hosts, ...)
	maxArgs      = 128 // argv entries kept
	maxMapLen    = 64  // entries kept in labels, details, evidence
	maxNameLen   = 256 // identifiers, names, short fields
	maxKeyLen    = 128 // map keys
	maxErrStd    = 256 // outcome.error outside full
	maxInputKeys = 64
	maxInputNode = 2000 // tool input values kept in full
	maxInputDeep = 8
)

func (r *run) identity() {
	out := r.out
	if !r.s.pseudo {
		return
	}
	pseudo := func(v string) string {
		if v == "" {
			return ""
		}
		if r.s.key == nil {
			return "" // no key: removing the name is the only safe pseudonym
		}
		r.keyed = true
		return r.p.Pseudonym(v)
	}
	if out.User != nil {
		name := out.User.Name
		switch {
		case name != "":
			p := pseudo(name)
			out.User.Name, out.User.ID = p, p
		default:
			out.User.ID = pseudo(out.User.ID)
		}
	}
	if out.Process != nil {
		out.Process.User = pseudo(out.Process.User)
	}
	if out.Asset != nil {
		out.Asset.Owner = pseudo(out.Asset.Owner)
	}
	if out.Check != nil {
		out.Check.Owner = pseudo(out.Check.Owner)
	}
	if out.Health != nil {
		for i := range out.Health.Coverage {
			out.Health.Coverage[i].User = pseudo(out.Health.Coverage[i].User)
		}
	}
}

func (r *run) session() {
	s := r.out.Session
	if s == nil {
		return
	}
	// The transcript path locates the full conversation log on disk.
	s.Transcript = ""
	s.CWD = r.textStr(s.CWD, "session.cwd", r.s.maxField, false)
}

func (r *run) target() {
	t := r.out.Target
	if t == nil {
		return
	}
	mf := r.s.maxField
	t.Command = r.commandStr(t.Command, "target.command", mf)
	t.Path = r.textStr(t.Path, "target.path", mf, false)
	t.Paths = r.list(t.Paths, "target.paths", func(v string) string { return r.textStr(v, "target.paths", mf, false) })
	t.URL = r.urlStr(t.URL, "target.url", r.lv == levelFull, mf)
	t.Hosts = r.list(t.Hosts, "target.hosts", func(v string) string { return r.textStr(v, "target.hosts", maxNameLen, false) })
	if r.lv == levelFull {
		t.Query = r.textStr(t.Query, "target.query", mf, true)
	} else {
		// A web search query is prompt-derived content.
		t.Query = ""
	}
}

// list caps a string list and maps each element.
func (r *run) list(in []string, name string, fn func(string) string) []string {
	if len(in) == 0 {
		return in
	}
	if len(in) > maxListLen {
		in = in[:maxListLen]
		r.note(name)
	}
	out := make([]string, len(in))
	for i, v := range in {
		out[i] = fn(v)
	}
	return out
}

func (r *run) tool() {
	t := r.out.Tool
	if t == nil {
		return
	}
	var input map[string]any
	var output string
	haveOutput := false
	if c := r.src.Content; c != nil {
		input = c.ToolInput
		if c.ToolOutput != "" {
			output, haveOutput = c.ToolOutput, true
		}
	}
	if input == nil {
		input = r.src.Tool.Input
	}
	if !haveOutput && r.src.Tool.Output != "" {
		output, haveOutput = r.src.Tool.Output, true
	}

	// input_keys: names only, and long keys are scanned (a map keyed by a
	// token leaks through its keys).
	keys := t.InputKeys
	if len(keys) == 0 && len(input) > 0 {
		for k := range input {
			keys = append(keys, k)
		}
		sort.Strings(keys)
	}
	t.InputKeys = r.list(keys, "tool.input_keys", func(k string) string {
		k = r.clean(k)
		if len(k) >= 16 {
			k = redactText(k)
		}
		return r.finishStr(k, "tool.input_keys", maxKeyLen, false)
	})

	// Digests: keyed, of values of at least DigestMinLen, or nothing.
	inHash, inLen := t.InputSHA256, -1
	if input != nil {
		if b, err := json.Marshal(input); err == nil {
			inLen = len(b)
			if !isSHA256Hex(inHash) {
				inHash = sha256Hex(string(b))
			}
		}
	}
	t.InputSHA256 = r.digest(domInput, inHash, inLen)
	outLen := t.OutputLen
	if haveOutput && outLen == 0 {
		outLen = len(output)
	}
	outHash := t.OutputSHA256
	if haveOutput && !isSHA256Hex(outHash) {
		outHash = sha256Hex(output)
	}
	t.OutputSHA256 = r.digest(domOutput, outHash, outLen)
	t.OutputLen = r.length(outLen)

	if r.lv != levelFull {
		t.Input = nil
		t.Output = ""
		return
	}
	t.Input = r.toolInput(input)
	if haveOutput {
		t.Output = r.textStr(output, "tool.output", r.s.maxField, true)
	} else {
		t.Output = ""
	}
}

// digest returns the keyed digest of a value given its unkeyed SHA-256 and
// length (-1 when unknown). Unknown or short values get none.
func (r *run) digest(domain, sha string, n int) string {
	if r.s.key == nil || !isSHA256Hex(sha) || n < DigestMinLen {
		return ""
	}
	r.keyed = true
	return contentDigest(r.s.key, domain, sha)
}

// length is exact in full and bucketed otherwise.
func (r *run) length(n int) int {
	if n <= 0 || r.lv == levelFull {
		return n
	}
	b := bucket(n)
	r.bucketed = true
	return b
}

// toolInput redacts a decoded tool input for the full profile: shell
// commands structurally, argument lists flag-aware, everything else through
// classify.RedactMap; bounded in size and depth first.
func (r *run) toolInput(in map[string]any) map[string]any {
	if len(in) == 0 {
		return nil
	}
	budget := maxInputNode
	b, cut := boundAny(in, 1, &budget)
	bounded, _ := b.(map[string]any)
	if cut {
		r.note("tool.input")
	}
	pre := make(map[string]any, len(bounded))
	for k, v := range bounded {
		pre[k] = v
		switch lk := strings.ToLower(k); lk {
		case "command", "cmd", "script", "commandline", "command_line", "shell_command":
			switch t := v.(type) {
			case string:
				red, _ := redactCommand(r.clean(t), r.dialectHint())
				pre[k] = red
			case []any:
				if args, ok := stringList(t); ok {
					red := redactArgv(args)
					l := make([]any, len(red))
					for i, a := range red {
						l[i] = a
					}
					pre[k] = l
				}
			}
		}
	}
	red, truncated := redactMap(pre, r.s.maxField)
	for _, p := range truncated {
		r.note("tool.input." + p)
	}
	return red
}

func stringList(l []any) ([]string, bool) {
	out := make([]string, len(l))
	for i, v := range l {
		s, ok := v.(string)
		if !ok {
			return nil, false
		}
		out[i] = s
	}
	return out, true
}

// boundAny copies decoded JSON with a node budget, a depth cap and per-map
// and per-list caps. It reports whether anything was dropped.
func boundAny(v any, depth int, budget *int) (any, bool) {
	*budget--
	if *budget < 0 {
		return truncOpen + "nodes]", true
	}
	switch t := v.(type) {
	case map[string]any:
		if depth > maxInputDeep {
			return truncOpen + "depth]", true
		}
		keys := make([]string, 0, len(t))
		for k := range t {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		cut := false
		if len(keys) > 256 {
			keys, cut = keys[:256], true
		}
		out := make(map[string]any, len(keys))
		for _, k := range keys {
			c, cc := boundAny(t[k], depth+1, budget)
			out[k] = c
			cut = cut || cc
		}
		return out, cut
	case []any:
		if depth > maxInputDeep {
			return truncOpen + "depth]", true
		}
		cut := false
		n := len(t)
		if n > 256 {
			n, cut = 256, true
		}
		out := make([]any, n)
		for i := 0; i < n; i++ {
			c, cc := boundAny(t[i], depth+1, budget)
			out[i] = c
			cut = cut || cc
		}
		return out, cut
	case []string:
		l := make([]any, len(t))
		for i, s := range t {
			l[i] = s
		}
		return boundAny(l, depth, budget)
	case string:
		if len(t) > maxTextScan {
			return t[:safeCut(t, maxTextScan)], true
		}
		return t, false
	}
	return v, false
}

func (r *run) prompt() {
	pr := r.out.Prompt
	if pr == nil {
		return
	}
	text := pr.Text
	if c := r.src.Content; c != nil && c.PromptText != "" {
		text = c.PromptText
	}
	n := pr.Len
	if n == 0 && text != "" {
		n = utf8.RuneCountInString(text)
	}
	sha := pr.SHA256
	if text != "" {
		sha = sha256Hex(text)
	}
	pr.SHA256 = r.digest(domPrompt, sha, n)
	pr.Len = r.length(n)
	if r.lv == levelFull {
		pr.Text = r.textStr(text, "prompt.text", r.s.maxField, true)
	} else {
		pr.Text = ""
	}
}

func (r *run) process() {
	pr := r.out.Process
	if pr == nil {
		return
	}
	pr.Args = r.argsStr(pr.Args, "process.args", r.s.maxField, maxArgs)
	pr.Exe = r.textStr(pr.Exe, "process.exe", r.s.maxField, false)
	pr.Ancestors = r.list(pr.Ancestors, "process.ancestors", func(v string) string { return r.textStr(v, "process.ancestors", maxNameLen, false) })
	pr.EnvMarkers = r.list(pr.EnvMarkers, "process.env_markers", func(v string) string { return r.textStr(v, "process.env_markers", maxNameLen, false) })
	pr.Flags = r.list(pr.Flags, "process.flags", func(v string) string { return r.valueStr(v, "process.flags", maxNameLen) })
}

func (r *run) outcome() {
	o := r.out.Outcome
	if o == nil {
		return
	}
	max := maxErrStd
	if r.lv == levelFull {
		max = r.s.maxField
	}
	o.Error = r.textStr(o.Error, "outcome.error", max, true)
}

func (r *run) repo() {
	rp := r.out.Repo
	if rp == nil {
		return
	}
	rp.Root = r.textStr(rp.Root, "repo.root", r.s.maxField, false)
	if rp.Remote != "" {
		rp.Remote = r.urlStr(rp.Remote, "repo.remote", false, r.s.maxField)
	}
	rp.Branch = r.valueStr(rp.Branch, "repo.branch", maxNameLen)
}

func (r *run) account() {
	a := r.out.Account
	if a == nil || a.ID == "" {
		return
	}
	if r.lv == levelFull {
		a.ID = r.valueStr(a.ID, "account.id", maxNameLen)
		return
	}
	if r.s.key == nil {
		a.ID = ""
		return
	}
	r.keyed = true
	a.ID = "a_" + keyed(r.s.key, domAccount, []byte(a.ID))[:digestHex]
}

// userAuthoredAssets have definition hashes over text a user wrote (MCP
// launch lines with inline env values, hook commands, rules files): those
// hashes are content-derived and must be keyed. Binary and package hashes
// identify public software and stay as they are, so they can be matched
// against threat intelligence.
var userAuthoredAssets = map[event.AssetKind]bool{
	event.AssetMCPServer: true, event.AssetHook: true, event.AssetRulesFile: true,
	event.AssetSubagent: true, event.AssetCommand: true, event.AssetProjectConfig: true,
}

func (r *run) asset() {
	a := r.out.Asset
	if a == nil {
		return
	}
	mf := r.s.maxField
	a.Path = r.textStr(a.Path, "asset.path", mf, false)
	if userAuthoredAssets[a.Kind] && a.SHA256 != "" {
		if r.s.key != nil && isSHA256Hex(a.SHA256) {
			r.keyed = true
			a.SHA256 = contentDigest(r.s.key, domAsset, a.SHA256)
		} else {
			a.SHA256 = ""
		}
	}
	if m := a.MCP; m != nil {
		// Redact the launch line as one argument vector, so "bash -c ..."
		// and tool-specific flags are recognised, then drop the program.
		if len(m.Args) > 0 {
			full := r.argsStr(append([]string{m.Command}, m.Args...), "asset.mcp.args", mf, maxArgs+1)
			m.Args = full[1:]
		}
		cmd := r.clean(m.Command)
		if r.lv != levelFull {
			cmd = baseName(cmd)
		}
		m.Command = r.textStr(cmd, "asset.mcp.command", mf, false)
		m.URLHost = r.textStr(m.URLHost, "asset.mcp.url_host", maxNameLen, false)
		if m.URLPath != "" {
			// Redact the path in the context of its host: provider patterns
			// such as Slack webhooks are anchored on the host name.
			host := m.URLHost
			if host == "" || strings.ContainsAny(host, "/?#@ ") {
				host = "h.invalid"
			}
			prefix := "https://" + host
			red := redactURL(prefix+ensureSlash(r.clean(m.URLPath)), r.lv == levelFull)
			if strings.HasPrefix(red, prefix) {
				red = red[len(prefix):]
			} else {
				red = redactText(r.clean(m.URLPath))
			}
			m.URLPath = r.finishStr(red, "asset.mcp.url_path", mf, false)
		}
	}
	a.Detail = r.strMap(a.Detail, "asset.detail", mf)
}

func ensureSlash(p string) string {
	if strings.HasPrefix(p, "/") {
		return p
	}
	return "/" + p
}

// baseName is the last path element of a command, either separator.
func baseName(c string) string {
	if i := strings.LastIndexAny(c, `/\`); i >= 0 && i < len(c)-1 {
		return c[i+1:]
	}
	return c
}

// strMap redacts the values of a string map as structured values and caps
// its size.
func (r *run) strMap(m map[string]string, name string, max int) map[string]string {
	if len(m) == 0 {
		return m
	}
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > maxMapLen {
		keys = keys[:maxMapLen]
		r.note(name)
	}
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		out[k] = r.valueStr(m[k], joinName(name, k), max)
	}
	return out
}

func (r *run) check() {
	c := r.out.Check
	if c == nil {
		return
	}
	mf := r.s.maxField
	c.Subject = r.valueStr(c.Subject, "check.subject", mf)
	c.Expected = r.valueStr(c.Expected, "check.expected", mf)
	c.Actual = r.valueStr(c.Actual, "check.actual", mf)
}

func (r *run) detection() {
	d := r.out.Detection
	if d == nil {
		return
	}
	if d.DedupKey != "" {
		// The engine's dedup key can include a command or path: re-key it,
		// or drop it when there is no key (rule id + session still group).
		if r.s.key != nil {
			r.keyed = true
			d.DedupKey = keyed(r.s.key, domDedup, []byte(d.DedupKey))[:digestHex]
		} else {
			d.DedupKey = ""
		}
	}
	if len(d.Evidence) > 0 {
		d.Evidence = r.sanitizeEvidence(d.Evidence)
	}
}

func (r *run) health() {
	h := r.out.Health
	if h == nil {
		return
	}
	h.Detail = r.textStr(h.Detail, "health.detail", r.s.maxField, true)
	for i := range h.Surfaces {
		h.Surfaces[i].Reason = r.textStr(h.Surfaces[i].Reason, "health.surfaces", maxNameLen, true)
	}
}

func (r *run) summary() {
	s := r.out.Summary
	if s == nil {
		return
	}
	text := func(name string) func(string) string {
		return func(v string) string { return r.textStr(v, name, maxNameLen, false) }
	}
	s.Hosts = r.list(s.Hosts, "summary.hosts", text("summary.hosts"))
	s.HostClasses = r.list(s.HostClasses, "summary.host_classes", text("summary.host_classes"))
	s.PathClasses = r.list(s.PathClasses, "summary.path_classes", text("summary.path_classes"))
	s.MCPServers = r.list(s.MCPServers, "summary.mcp_servers", text("summary.mcp_servers"))
	// "manager:package": a package can be a git URL with a token in it.
	s.Installs = r.list(s.Installs, "summary.installs", func(v string) string { return r.valueStr(v, "summary.installs", maxNameLen) })
	s.Detections = r.list(s.Detections, "summary.detections", text("summary.detections"))
	s.Flags = r.list(s.Flags, "summary.flags", text("summary.flags"))
}

func (r *run) labels() {
	if len(r.out.Labels) == 0 {
		return
	}
	in := r.out.Labels
	keys := make([]string, 0, len(in))
	for k := range in {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	if len(keys) > maxMapLen {
		keys = keys[:maxMapLen]
		r.note("labels")
	}
	out := make(map[string]string, len(keys))
	for _, k := range keys {
		out[k] = r.labelStr(k, in[k])
	}
	r.out.Labels = out
}

// safetyPass runs every string of the record, whatever its field, through
// UTF-8 cleaning, pattern redaction, fingerprint rewriting, home-relative
// paths and the per-field cap. Map keys get the same treatment.
func (r *run) safetyPass() {
	rekeyMaps(r.out, func(k string) string {
		k = r.clean(k)
		if len(k) >= 16 {
			k = redactText(k)
		}
		k = rewriteMarkers(k, r.s.key)
		return capBytes(r.home.rewrite(k), maxKeyLen)
	})
	for _, sl := range collectSlots(r.out) {
		v := sl.get()
		if v == "" {
			continue
		}
		nv := r.clean(v)
		if len(nv) > maxTextScan {
			nv = nv[:safeCut(nv, maxTextScan)]
			r.note(sl.name)
		}
		if len(nv) >= 8 {
			nv = redactText(nv)
		}
		nv = r.finishStr(nv, sl.name, r.slotCap(sl.name, nv), false)
		if nv != v {
			sl.set(nv)
		}
	}
}
