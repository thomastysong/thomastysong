package shellx

// Dialect is the command-line syntax family a string is analysed as.
type Dialect string

const (
	Posix      Dialect = "posix"
	PowerShell Dialect = "powershell"
	Cmd        Dialect = "cmd"
)

// Command.Origin values. Inline code handed to an interpreter uses
// OriginInlinePrefix followed by the interpreter's command name, for example
// "inline:bash" or "inline:python3".
const (
	OriginTop          = "top"
	OriginSubshell     = "subshell"
	OriginSubstitution = "substitution"
	OriginEval         = "eval"
	OriginDecoded      = "decoded"
	OriginWrapper      = "wrapper"
	OriginInlinePrefix = "inline:"
)

// Limits applied to every Analyze call. They exist because the input is
// attacker-controlled: each one bounds memory or time, and hitting any of
// them sets Facts.Truncated so an incomplete analysis is never silent.
const (
	// MaxInput is the number of leading bytes of the command line analysed.
	MaxInput = 256 << 10
	// MaxDecoded is the largest decoded payload kept and re-analysed.
	MaxDecoded = 64 << 10
	// MaxDepth is the nesting cap for re-parsed code: subshells,
	// substitutions, inline code, eval strings and decoded payloads.
	MaxDepth = 6
)

// Command is one simple command found at any nesting depth.
type Command struct {
	Name    string   // basename, lower-cased, ".exe" stripped
	Path    string   // command word as written
	Args    []string // literal args with quotes removed; unresolvable parts rendered as "$VAR" or "$(...)"
	Origin  string   // top | subshell | substitution | inline:<interp> | eval | decoded | wrapper
	Dynamic bool     // name or an argument depends on an expansion that could not be resolved statically
}

// InlineCode is code handed to an interpreter with -c / -e / --eval, a
// heredoc, a here-string or a statically known pipe.
type InlineCode struct{ Lang, Code string }

// PkgInstall is one package-manager install or fetch-and-run invocation.
type PkgInstall struct {
	Manager  string   // see the package doc for the vocabulary
	Packages []string // "name" or "name@version" / "name==version" exactly as written, registry URLs and git URLs kept
	Global   bool
	Exec     bool // npx/uvx/bunx/pipx run style fetch-and-run
	Flags    []string
}

// Facts is everything Analyze derived from one command line. All slices are
// de-duplicated and keep first-seen order, so output is deterministic.
type Facts struct {
	Dialect   Dialect
	ParseOK   bool // false when the real parser failed and tokenised heuristics were used
	Truncated bool
	Commands  []Command // every simple command found, at any nesting depth (depth cap 6)
	Pipelines [][]int   // indexes into Commands, one slice per pipeline with 2+ stages
	URLs      []string
	Hosts     []string // from URLs, scp/ssh targets, nc/curl host args, /dev/tcp/host/port
	Reads     []string // paths read
	Writes    []string // paths written
	Deletes   []string // paths deleted
	EnvAssign []string // names of variables assigned on the command line

	Interpreters []string // interpreters that receive code from a pipe, -c/-e, heredoc or process substitution
	Inline       []InlineCode
	Decoded      []string // text recovered from base64/hex/-EncodedCommand payloads
	Installs     []PkgInstall

	Downloads          bool // a network fetch tool or API is used
	PipeToInterpreter  bool // a pipeline stage or process substitution feeds an interpreter
	DownloadAndExecute bool // download output reaches an interpreter, or a downloaded file is executed/chmod +x'd in the same command line
	Eval               bool
	Sudo               bool
	Background         bool
	HereDoc            bool

	Obfuscation []string
	// Opaque names constructs whose effect a static parse cannot see:
	// eval, inline_code (code in another language), heredoc_interpreter,
	// dynamic_command, decoded_exec, process_substitution_exec, deep_nesting.
	// Rules score the opacity itself instead of pretending to see inside.
	Opaque []string
	// ExecutesPaths are scripts or binaries run by path (./x.sh, sh x.sh,
	// python x.py, C:\t\a.exe), so a file written earlier in the session
	// and executed here can be correlated across events.
	ExecutesPaths []string

	// Semantic categories (closed vocabularies, documented in the package doc).
	Destructive    []string
	Persistence    []string
	DefenseEvasion []string
	CredAccess     []string
	Exfil          []string
	NetTools       []string
	Recon          []string
	Privilege      []string
	GitOps         []string
}

// Vocabulary returns the closed vocabulary of every categorical field, keyed
// by the Facts field name ("Obfuscation", "Destructive", ...), plus
// "PkgInstall.Manager", "InlineCode.Lang" and "Command.Origin". Rule loaders
// use it to reject rules that reference a value Analyze can never produce.
// The returned map and slices are fresh copies.
func Vocabulary() map[string][]string {
	ensureTables()
	out := make(map[string][]string, len(vocabulary))
	for k, v := range vocabulary {
		out[k] = append([]string(nil), v...)
	}
	return out
}

var vocabulary map[string][]string

func buildVocabulary() {
	vocabulary = map[string][]string{
		"Obfuscation": {
			"base64_decode_exec", "hex_escape", "ifs_abuse", "var_indirection", "eval",
			"char_concat", "encoded_command", "rev_exec", "long_single_token", "deep_nesting",
		},
		"Opaque": {
			"eval", "inline_code", "heredoc_interpreter", "dynamic_command", "decoded_exec",
			"process_substitution_exec", "deep_nesting",
		},
		"Destructive": {
			"rm_recursive_root", "rm_recursive_home", "rm_recursive_wildcard", "disk_wipe", "mkfs",
			"git_force_push", "git_reset_hard", "git_clean_force", "git_history_rewrite",
			"db_drop", "db_truncate", "kubectl_delete", "kubectl_delete_namespace",
			"terraform_destroy", "cloud_delete", "docker_prune_all", "chmod_recursive_open",
			"truncate_file", "find_delete", "shadow_copy_delete",
		},
		"Persistence": {
			"cron", "launchd", "systemd", "shell_profile", "registry_run", "scheduled_task",
			"ssh_authorized_keys", "git_hook", "login_item", "at_job",
		},
		"DefenseEvasion": {
			"stop_security_tool", "disable_gatekeeper", "disable_sip", "defender_tamper",
			"firewall_disable", "history_clear", "log_clear", "sensor_tamper", "agent_hook_tamper",
			"selinux_disable", "audit_disable",
		},
		"CredAccess": {
			"keychain_dump", "token_print", "env_dump", "ssh_key_read", "browser_cred",
			"cloud_metadata", "secret_file_read", "password_store", "proc_environ_read",
		},
		"Exfil": {
			"http_upload_file", "http_post_data", "scp_out", "rsync_out", "dns_tunnel", "netcat_out",
			"git_push_new_remote", "paste_post", "webhook_post", "email_send", "cloud_bucket_upload",
		},
		"NetTools": {
			"nc", "ncat", "socat", "ssh_reverse_tunnel", "ngrok", "cloudflared", "tailscale_funnel",
			"chisel", "frp", "bore", "localtunnel", "tor",
		},
		"Recon": {
			"whoami", "id", "uname", "hostname", "ifconfig", "ip", "netstat", "ss", "ps", "env",
			"find_secrets", "cloud_identity", "nmap",
		},
		"Privilege": {
			"sudo", "su", "setuid_chmod", "sudoers_edit", "docker_privileged", "docker_socket_mount", "cap_add",
		},
		"GitOps": {
			"push", "push_force", "remote_add", "config_credential", "clone", "commit_no_verify",
		},
		"PkgInstall.Manager": {
			"npm", "pnpm", "yarn", "bun", "pip", "uv", "pipx", "cargo", "go", "gem", "brew", "apt",
			"dnf", "winget", "choco", "scoop", "npx", "uvx", "bunx",
			"apk", "pacman", "zypper", "snap", "flatpak", "conda", "poetry", "composer", "vscode",
		},
		"InlineCode.Lang": {
			"sh", "python", "javascript", "perl", "ruby", "php", "lua", "powershell", "cmd",
			"applescript", "awk", "vbscript", "sql",
		},
		"Command.Origin": {
			OriginTop, OriginSubshell, OriginSubstitution, OriginEval, OriginDecoded, OriginWrapper,
			OriginInlinePrefix + "<interp>",
		},
	}
}
