package features

import (
	"sort"
	"strings"
	"sync"

	"github.com/thomastysong/spoor/internal/classify"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/shellx"
)

// Type is the value type of a field in the flattened view.
type Type string

const (
	TypeString  Type = "string"
	TypeBool    Type = "bool"
	TypeNumber  Type = "number"   // float64
	TypeStrings Type = "[]string" // equality and string modifiers apply to any element
	TypeObjects Type = "[]object" // []map[string]any; only the any_command / any_install quantifiers read it
)

// Field origins.
const (
	OriginEvent   = "event"   // an emitted event field, by JSON path
	OriginFeature = "feature" // computed by Compute
	OriginSession = "session" // filled by the rule engine from per-session state before matching
	OriginEngine  = "engine"  // filled by the rule engine from its options
)

// FieldInfo describes one name rules may reference.
type FieldInfo struct {
	Name   string
	Type   Type
	Origin string
	// Vocab is the closed set of values the field can hold, or nil when the
	// field is open (paths, hosts, command names). The rule linter rejects
	// a literal outside the vocabulary: such a rule could never match.
	Vocab []string
	Doc   string
}

// Closed vocabularies owned by this package.
var (
	// UntrustedSources is the vocabulary of output.untrusted_source.
	UntrustedSources = []string{"web_fetch", "web_search", "mcp", "browser", "file", "shell"}
)

// CommandKeys are the keys of one shell.cmds entry, for the any_command
// quantifier.
var CommandKeys = map[string]Type{
	"name": TypeString, "path": TypeString, "args": TypeStrings, "origin": TypeString, "dynamic": TypeBool,
}

// InstallKeys are the keys of one shell.install_entries entry, for the
// any_install quantifier.
var InstallKeys = map[string]Type{
	"manager": TypeString, "packages": TypeStrings, "global": TypeBool, "exec": TypeBool, "flags": TypeStrings,
}

type featDef struct {
	name  string
	typ   Type
	vocab func() []string
	doc   string
}

func shellVocab(field string) func() []string {
	return func() []string { return shellx.Vocabulary()[field] }
}

var (
	pathVocab   = classify.PathClassVocabulary
	hostVocab   = classify.HostClassVocabulary
	markerVocab = classify.MarkerVocabulary
	secretVocab = classify.SecretKinds
)

func fixed(v []string) func() []string { return func() []string { return v } }

// featureDefList returns the feature vocabulary. doc.go explains each
// family; rule packs depend on these exact names. It is a function rather
// than a package-level table because its vocab closures are built at run
// time: as a var it was init work in every process that links features,
// while only registry reads it, once, in the processes that look field
// names up (rule loading and lint, the engine, the privacy stage).
func featureDefList() []featDef {
	return []featDef{
		// Shell, from shellx.Analyze over target.command (or process args).
		{"shell.parse_ok", TypeBool, nil, "the real parser accepted the command line (false: heuristic tokenising was used)"},
		{"shell.dialect", TypeString, fixed([]string{"posix", "powershell", "cmd"}), "syntax family the command was analysed as"},
		{"shell.truncated", TypeBool, nil, "the analyzer or a shell feature list hit a size or depth cap; the analysis is incomplete"},
		{"shell.commands", TypeStrings, nil, "command names (basename, lower-case, .exe stripped) at any nesting depth"},
		{"shell.argv", TypeStrings, nil, "every literal argument of every command (first and last 2048 when there are more)"},
		{"shell.cmds", TypeObjects, nil, "parsed commands {name, path, args, origin, dynamic}; use any_command"},
		{"shell.urls", TypeStrings, nil, "URLs in the command line"},
		{"shell.hosts", TypeStrings, nil, "network hosts the command contacts"},
		{"shell.host_classes", TypeStrings, hostVocab, "classify.HostClasses over shell.hosts"},
		{"shell.reads", TypeStrings, nil, "paths read"},
		{"shell.writes", TypeStrings, nil, "paths written (redirects, cp/mv/tee destinations ...)"},
		{"shell.deletes", TypeStrings, nil, "paths deleted"},
		{"shell.changes", TypeStrings, nil, "paths changed other than by a content write or delete: created empty (touch, mkdir, md, install -d), permissions, ownership or attributes changed, a move source, a mount point"},
		{"shell.aliases", TypeStrings, nil, "existing paths a new link or bind mount makes reachable under another name (ln target, mount --bind source, mklink and New-Item link targets)"},
		{"shell.change_classes", TypeStrings, pathVocab, "classify.PathClasses over shell.changes"},
		{"shell.proc_root", TypeStrings, shellVocab("ProcRoot"), "kinds of path operand (read, write, delete, change, alias, execute) named through a process's root directory (/proc/<pid>/root, /proc/self/root)"},
		{"shell.read_classes", TypeStrings, pathVocab, "classify.PathClasses over shell.reads"},
		{"shell.write_classes", TypeStrings, pathVocab, "classify.PathClasses over shell.writes"},
		{"shell.delete_classes", TypeStrings, pathVocab, "classify.PathClasses over shell.deletes"},
		{"shell.interpreters", TypeStrings, nil, "interpreters that receive code (pipe, -c/-e, heredoc, process substitution)"},
		{"shell.inline_langs", TypeStrings, shellVocab("InlineCode.Lang"), "languages of inline code handed to interpreters"},
		{"shell.downloads", TypeBool, nil, "a network fetch tool or API is used"},
		{"shell.pipe_to_interpreter", TypeBool, nil, "a pipeline stage or process substitution feeds an interpreter"},
		{"shell.download_and_execute", TypeBool, nil, "downloaded content reaches an interpreter or is executed"},
		{"shell.eval", TypeBool, nil, "eval / Invoke-Expression style execution of a string"},
		{"shell.sudo", TypeBool, nil, "privilege elevation wrapper used"},
		{"shell.background", TypeBool, nil, "something is started in the background or detached"},
		{"shell.heredoc", TypeBool, nil, "a heredoc or here-string is present"},
		{"shell.dynamic", TypeBool, nil, "a command name or argument depends on an expansion that cannot be resolved statically"},
		{"shell.obfuscation", TypeStrings, shellVocab("Obfuscation"), "obfuscation techniques"},
		{"shell.opaque", TypeStrings, shellVocab("Opaque"), "constructs whose effect a static parse cannot see"},
		{"shell.executes_paths", TypeStrings, nil, "scripts or binaries run by path (./x.sh, sh x.sh, python x.py, chmod +x targets)"},
		{"shell.destructive", TypeStrings, shellVocab("Destructive"), "destructive operations"},
		{"shell.persistence", TypeStrings, shellVocab("Persistence"), "persistence mechanisms touched"},
		{"shell.defense_evasion", TypeStrings, shellVocab("DefenseEvasion"), "defense evasion"},
		{"shell.cred_access", TypeStrings, shellVocab("CredAccess"), "credential access"},
		{"shell.exfil", TypeStrings, shellVocab("Exfil"), "exfiltration-shaped operations"},
		{"shell.net_tools", TypeStrings, shellVocab("NetTools"), "tunnel and raw socket tools"},
		{"shell.recon", TypeStrings, shellVocab("Recon"), "reconnaissance commands"},
		{"shell.privilege", TypeStrings, shellVocab("Privilege"), "privilege changes"},
		{"shell.git_ops", TypeStrings, shellVocab("GitOps"), "git operations of interest"},
		{"shell.installs", TypeStrings, nil, `package installs as "manager:package" exactly as written`},
		{"shell.install_entries", TypeObjects, nil, "installs {manager, packages, global, exec, flags}; use any_install"},
		{"shell.install_managers", TypeStrings, shellVocab("PkgInstall.Manager"), "package managers used"},
		{"shell.install_exec", TypeBool, nil, "a fetch-and-run install (npx, uvx, bunx, pipx run ...)"},
		{"shell.install_sources", TypeStrings, nil, "registries, indexes and URL/git package sources named on the command line"},
		{"shell.env_assign", TypeStrings, nil, "names of variables assigned on the command line"},
		{"shell.decoded", TypeBool, nil, "an encoded payload (base64, hex, -EncodedCommand) was decoded"},
		{"shell.has_secret", TypeBool, nil, "a literal credential appears in the command line"},
		{"shell.secret_kinds", TypeStrings, secretVocab, "kinds of literal credentials in the command line"},

		// Paths of file tools.
		{"path.classes", TypeStrings, pathVocab, "classify.PathClasses over target.path and target.paths"},
		{"path.targets", TypeStrings, nil, "target.path and target.paths in canonical form (joined with the session directory, . and .. resolved, duplicate separators collapsed, /proc/<pid>/root stripped)"},
		{"path.proc_root", TypeBool, nil, "a target path went through a process's root directory (/proc/<pid>/root, /proc/self/root)"},
		{"path.sensitive_read", TypeBool, nil, "a read/list tool touches a credential-class path"},
		{"path.sensitive_write", TypeBool, nil, "a write/edit tool touches a persistence- or control-class path"},
		{"path.outside_cwd", TypeBool, nil, "a target path resolves outside the session working directory"},
		{"path.ext", TypeString, nil, `lower-case extension of target.path (".json")`},
		{"path.normalization_evasion", TypeBool, nil, "a target differs from an agent control file only by case, trailing dot/space, NTFS ADS or 8.3 form"},
		{"path.control_file", TypeBool, nil, "a target path is an agent, IDE or VCS control file (classes agent_*, mcp_config, vcs_*, startup_item)"},

		// Network.
		{"net.host", TypeStrings, nil, "hosts from target.url/host(s), shell and MCP arguments"},
		{"net.host_classes", TypeStrings, hostVocab, "classify.HostClasses over net.host"},
		{"net.scheme", TypeStrings, nil, "URL schemes (lower-case)"},
		{"net.is_ip", TypeBool, nil, "a host is an IP literal"},
		{"net.url_has_secret", TypeBool, nil, "a URL carries a credential (userinfo, token in the query ...)"},
		{"net.query_len", TypeNumber, nil, "longest URL query string, in bytes"},

		// Content scans (local only; values never leave the endpoint).
		{"prompt.secret_kinds", TypeStrings, secretVocab, "credentials in the prompt"},
		{"prompt.hidden_unicode", TypeBool, nil, "the prompt carries invisible Unicode"},
		{"prompt.markers", TypeStrings, markerVocab, "instruction-override markers in the prompt"},
		{"write.secret_kinds", TypeStrings, secretVocab, "credentials in content being written"},
		{"write.hidden_unicode", TypeBool, nil, "content being written carries invisible Unicode"},
		{"write.markers", TypeStrings, markerVocab, "instruction-override markers in content being written"},
		{"write.autorun", TypeBool, nil, "content written to an agent control file makes something run or escalates permissions"},
		{"write.autorun_kinds", TypeStrings, fixed(AutorunVocabulary), "what write.autorun found"},
		{"write.exec_keys", TypeStrings, fixed(GitExecKeyVocabulary), "git exec-sink keys in content written to a git config"},
		{"output.markers", TypeStrings, markerVocab, "instruction-override markers in tool output"},
		{"output.hidden_unicode", TypeBool, nil, "tool output carries invisible Unicode"},
		{"output.secret_kinds", TypeStrings, secretVocab, "credentials in tool output"},
		{"output.untrusted", TypeBool, nil, "the tool result is content an attacker can author (web, MCP, issues, downloads, third-party trees)"},
		{"output.untrusted_source", TypeString, fixed(UntrustedSources), "why output.untrusted is true"},
		{"content.truncated_scan", TypeBool, nil, "a value over 128 KiB was scanned head 64 KiB + tail 64 KiB only"},
		{"content.analyzer_error", TypeBool, nil, "an analyzer failed on this event; features are incomplete"},
		{"content.truncated_fields", TypeStrings, nil, "features whose value is incomplete because a size cap was hit; in_list on them and operator suppressions matching them do not hold"},

		// MCP calls.
		{"mcp.server", TypeString, nil, "MCP server name"},
		{"mcp.tool", TypeString, nil, "MCP tool name"},
		{"mcp.arg_paths", TypeStrings, nil, "path-like strings in the tool input (walked to depth 8)"},
		{"mcp.arg_path_classes", TypeStrings, pathVocab, "classify.PathClasses over mcp.arg_paths"},
		{"mcp.arg_hosts", TypeStrings, nil, "hosts of URL-like strings in the tool input"},
		{"mcp.arg_host_classes", TypeStrings, hostVocab, "classify.HostClasses over mcp.arg_hosts"},
		{"mcp.arg_secret_kinds", TypeStrings, secretVocab, "credentials in the tool input"},
	}
}

// sessionDefs are filled by the rule engine before matching.
var sessionDefs = []featDef{
	{"session.flags", TypeStrings, nil, "session flags visible to this thread (its own and session-scoped ones)"},
	{"session.tool_calls", TypeNumber, nil, "tool calls seen in the session so far, this one included"},
	{"session.prompts", TypeNumber, nil, "prompts seen in the session so far, this one included"},
	{"session.age_s", TypeNumber, nil, "seconds since the first event of the session"},
	{"session.first_event", TypeBool, nil, "this is the first event the engine has seen for the session"},
	{"session.runs_written_file", TypeBool, nil, "the command executes a path an earlier event of the session wrote"},
	{"session.written_exec_path", TypeString, nil, "the executed path that was written earlier"},
	{"shell.inherited_kinds", TypeStrings, fixed(InheritedKinds), "the shell and network facts of this event include a script's: written_script (written by a file tool earlier in the session and executed here), edit_fragment (those facts include an edit analysed apart from the text around it, which may miss what the edit completes)"},
	{"session.secret_flow", TypeBool, nil, "outbound data carries a value read earlier from a credential-class path"},
	{"session.secret_flow_kinds", TypeStrings, nil, "kinds of the values in session.secret_flow"},
	{"session.secret_flow_truncated", TypeBool, nil, "the outbound data was too large to scan whole for remembered values (padding); treat as opaque"},
}

var engineDefs = []featDef{
	{"host.tags", TypeStrings, nil, "operator-configured tags of this host"},
}

// eventVocabulary returns the closed vocabularies of event fields. Like
// featureDefList it is read once, inside registry.
func eventVocabulary() map[string][]string {
	return map[string][]string{
		"kind":      {"activity", "inventory", "posture", "detection", "health", "summary"},
		"source":    {"hook", "transcript", "process", "scan", "otel", "osquery", "adapter", "sensor"},
		"sources":   {"hook", "transcript", "process", "scan", "otel", "osquery", "adapter", "sensor"},
		"fidelity":  {"observed", "inferred"},
		"integrity": {"root", "user"},
		"type": {
			event.TypeSessionStart, event.TypeSessionEnd, event.TypePromptSubmit, event.TypeToolPre,
			event.TypeToolPost, event.TypeTurnEnd, event.TypeSubagentStart, event.TypeSubagentStop,
			event.TypePermissionDecision, event.TypeConfigChange, event.TypeNotification, event.TypeCompact,
			event.TypeAgentProcessStart, event.TypeAgentProcessStop, event.TypeProcessExec,
			event.TypeInventoryAsset, event.TypePostureCheck, event.TypeDetectionFinding,
			event.TypeHealthHeartbeat, event.TypeHealthError, event.TypeSessionSummary,
		},
		"tool.kind": {
			string(event.ToolShell), string(event.ToolFileRead), string(event.ToolFileWrite), string(event.ToolFileEdit),
			string(event.ToolFileList), string(event.ToolWebFetch), string(event.ToolWebSearch), string(event.ToolMCP),
			string(event.ToolSubagent), string(event.ToolBrowser), string(event.ToolOther),
		},
		"session.permission_mode": {"default", "plan", "accept_edits", "auto", "dont_ask", "bypass"},
		"asset.kind": {
			string(event.AssetAgent), string(event.AssetApp), string(event.AssetIDEExtension), string(event.AssetBrowser),
			string(event.AssetBrowserExtension), string(event.AssetModelRuntime), string(event.AssetMCPServer),
			string(event.AssetSkill), string(event.AssetPlugin), string(event.AssetHook), string(event.AssetRulesFile),
			string(event.AssetSubagent), string(event.AssetCommand), string(event.AssetCIAgent), string(event.AssetProjectConfig),
		},
		"asset.scope":  {"managed", "system", "user", "project", "plugin"},
		"asset.change": {"new", "changed", "removed", "unchanged"},
		"check.scope":  {"managed", "system", "user", "project", "plugin"},
	}
}

var (
	regOnce  sync.Once
	regNames map[string]FieldInfo
	regList  []FieldInfo
)

func registry() map[string]FieldInfo {
	regOnce.Do(func() {
		regNames = map[string]FieldInfo{}
		eventVocab := eventVocabulary()
		for name, typ := range eventPlan().names {
			regNames[name] = FieldInfo{Name: name, Type: typ, Origin: OriginEvent, Vocab: eventVocab[name]}
		}
		add := func(defs []featDef, origin string) {
			for _, d := range defs {
				fi := FieldInfo{Name: d.name, Type: d.typ, Origin: origin, Doc: d.doc}
				if d.vocab != nil {
					fi.Vocab = d.vocab()
				}
				regNames[d.name] = fi
			}
		}
		add(featureDefList(), OriginFeature)
		add(sessionDefs, OriginSession)
		add(engineDefs, OriginEngine)
		regList = make([]FieldInfo, 0, len(regNames))
		for _, fi := range regNames {
			regList = append(regList, fi)
		}
		sort.Slice(regList, func(i, j int) bool { return regList[i].Name < regList[j].Name })
	})
	return regNames
}

// Registry returns every field name rules may reference, sorted. Map-valued
// event fields appear as a "prefix.*" pattern (labels.*, asset.detail.*).
// The returned slices are copies.
func Registry() []FieldInfo {
	registry()
	out := make([]FieldInfo, len(regList))
	for i, fi := range regList {
		fi.Vocab = append([]string(nil), fi.Vocab...)
		out[i] = fi
	}
	return out
}

// Lookup returns the description of a field name, resolving map-valued
// event fields through their "prefix.*" pattern.
func Lookup(name string) (FieldInfo, bool) {
	r := registry()
	if fi, ok := r[name]; ok {
		return fi, true
	}
	for i := strings.LastIndexByte(name, '.'); i > 0; i = strings.LastIndexByte(name[:i], '.') {
		if fi, ok := r[name[:i]+".*"]; ok && i < len(name)-1 {
			fi.Name = name
			return fi, true
		}
	}
	return FieldInfo{}, false
}
