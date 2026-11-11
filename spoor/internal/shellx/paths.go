package shellx

import (
	"strings"
)

// normPath returns the comparison form of a path: forward slashes, lower
// case, duplicate separators collapsed, a leading "./" removed and every
// spelling of the home directory folded to "~". Lower-casing is deliberate:
// macOS and Windows file systems are case-insensitive, and on Linux the cost
// is a slightly broader match on names that are never legitimately mixed
// case.
func normPath(p string) string {
	p = strings.TrimSpace(p)
	if len(p) > 4096 {
		p = p[:4096]
	}
	p = strings.Trim(p, "\"'")
	p = strings.ReplaceAll(p, "\\", "/")
	p = strings.ToLower(p)
	for strings.Contains(p, "//") {
		p = strings.ReplaceAll(p, "//", "/")
	}
	for strings.HasPrefix(p, "./") {
		p = p[2:]
	}
	for _, h := range homeSpellings {
		if strings.HasPrefix(p, h) && (len(p) == len(h) || p[len(h)] == '/') {
			return "~" + p[len(h):]
		}
	}
	for _, pre := range homeParents {
		if strings.HasPrefix(p, pre) {
			rest := p[len(pre):]
			if rest == "" {
				continue
			}
			if i := strings.IndexByte(rest, '/'); i >= 0 {
				return "~" + rest[i:]
			}
			return "~"
		}
	}
	return p
}

var homeSpellings = []string{
	"$home", "${home}", "%userprofile%", "$env:userprofile", "$env:home", "%homepath%",
	"%homedrive%%homepath%", "/root", "/var/root", "$userprofile",
}

var homeParents = []string{"/home/", "/users/", "c:/users/", "/mnt/c/users/"}

// isHomeRoot reports whether p is a home directory itself, optionally with a
// trailing slash or a catch-all glob.
func isHomeRoot(norm string) bool {
	switch norm {
	case "~", "~/", "~/*", "~/.", "~/.*", "~/**":
		return true
	}
	return false
}

// Top-level directories whose recursive removal breaks the machine.
var systemDirs = []string{
	"/bin", "/boot", "/dev", "/etc", "/home", "/lib", "/lib64", "/opt", "/proc", "/sbin", "/srv",
	"/sys", "/usr", "/var", "/users", "/system", "/library", "/applications", "/private", "/volumes",
	"/usr/bin", "/usr/lib", "/usr/local", "/usr/sbin", "/usr/share", "/var/lib", "/private/etc", "/private/var",
	"c:/windows", "c:/users", "c:/program files", "c:/program files (x86)", "c:/programdata",
	"c:/windows/system32", "%systemroot%", "%windir%", "$env:systemroot", "$env:windir",
	"%programfiles%", "%programdata%", "$env:programfiles", "$env:programdata",
}

// isRootLike reports whether norm is the file system root or a top-level
// system directory, optionally with a trailing slash or catch-all glob.
func isRootLike(norm string) bool {
	n := strings.TrimSuffix(norm, "/*")
	n = strings.TrimSuffix(n, "/.")
	n = strings.TrimSuffix(n, "/**")
	if n == "" && norm != "" {
		return true // "/", "/*", "/."
	}
	n = strings.TrimSuffix(n, "/")
	if n == "" {
		return norm != ""
	}
	if n == "c:" || n == "c:/*" || (len(n) == 2 && n[1] == ':') {
		return true
	}
	for _, d := range systemDirs {
		if n == d {
			return true
		}
	}
	return false
}

// unsetVarRoot recognises "$VAR/", "$VAR/*" and "$VAR/<system dir>": the
// expansion is empty when the variable is unset, and the command then acts
// on the root. The check is on the rendered argument, where an unresolved
// variable is still spelled "$NAME".
func unsetVarRoot(s string) bool {
	if !strings.HasPrefix(s, "$") {
		return false
	}
	i := 1
	if i < len(s) && s[i] == '{' {
		j := strings.IndexByte(s, '}')
		if j < 0 {
			return false
		}
		i = j + 1
	} else {
		for i < len(s) && isIdentByte(s[i]) {
			i++
		}
	}
	if i <= 1 {
		return false
	}
	name := strings.ToUpper(strings.Trim(s[1:i], "{}"))
	if name == "HOME" || name == "PWD" || name == "OLDPWD" {
		return false // handled as home / cwd
	}
	rest := s[i:]
	if rest == "" || rest[0] != '/' {
		return false
	}
	return isRootLike(strings.ToLower(rest))
}

func isDevicePath(norm string) bool {
	if strings.HasPrefix(norm, "//./physicaldrive") || strings.HasPrefix(norm, "//./harddisk") {
		return true
	}
	if !strings.HasPrefix(norm, "/dev/") {
		return false
	}
	d := norm[len("/dev/"):]
	for _, p := range []string{"sd", "hd", "vd", "xvd", "nvme", "disk", "rdisk", "mmcblk", "dm-", "md", "mapper/", "loop", "sr"} {
		if strings.HasPrefix(d, p) {
			return true
		}
	}
	return false
}

func pathHasSeg(norm, seg string) bool {
	return strings.Contains(norm, "/"+seg+"/") || strings.HasSuffix(norm, "/"+seg) ||
		strings.HasPrefix(norm, seg+"/") || norm == seg
}

var sshPrivateNames = []string{"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk", "id_xmss", "identity"}

var browserDirs = []string{
	"google/chrome", "google-chrome", "/chromium", "bravesoftware", "microsoft/edge", "microsoft edge",
	".mozilla/firefox", "firefox/profiles", "/vivaldi", "opera software", "com.operasoftware", "/arc/user data",
}

var browserFiles = []string{"login data", "cookies", "web data", "logins.json", "key4.db", "key3.db", "cookies.sqlite", "signons.sqlite", "cookies.binarycookies", "local state"}

// secretFiles are matched against the home-relative path ("~/<entry>") or as
// a path suffix. Sources: threats.md SECRET_PATHS.
var secretHomeFiles = []string{
	".aws/credentials", ".aws/sso/cache", ".aws/cli/cache", ".config/gcloud", ".azure", ".kube/config", ".docker/config.json",
	".npmrc", ".pypirc", ".netrc", "_netrc", ".git-credentials", ".config/gh/hosts.yml", ".vault-token",
	".gnupg", ".config/git/credentials", ".terraform.d/credentials.tfrc.json", ".terraformrc",
	".claude/.credentials.json", ".codex/auth.json", ".gemini/oauth_creds.json", ".config/op",
	".config/doctl/config.yaml", ".oci/config", ".s3cfg", ".boto", ".pgpass", ".my.cnf", ".config/hub",
	".cargo/credentials", ".cargo/credentials.toml", ".gem/credentials", ".m2/settings.xml",
	".config/rclone/rclone.conf", ".config/solana/id.json", ".bitcoin/wallet.dat", ".ethereum/keystore",
	".snowsql/config", ".databrickscfg", ".config/heroku", ".config/stripe/config.toml",
	".config/github-copilot/hosts.json", ".config/github-copilot/apps.json",
}

var secretAbsFiles = []string{
	"/etc/shadow", "/etc/gshadow", "/etc/master.passwd", "/etc/security/opasswd",
	"/var/run/secrets/kubernetes.io/serviceaccount", "/run/secrets/kubernetes.io/serviceaccount",
	"/run/secrets", "/etc/kubernetes/admin.conf", "/etc/rancher/k3s/k3s.yaml",
	"/etc/ssl/private", "/etc/letsencrypt/live", "/etc/letsencrypt/archive",
}

var secretBaseNames = []string{
	"credentials.json", "client_secret.json", "service-account.json", "service_account.json",
	"secrets.yaml", "secrets.yml", "secrets.json", "secret.yaml", "secret.yml", ".htpasswd",
	"terraform.tfstate", "terraform.tfstate.backup", "wallet.dat", ".dockercfg", "kubeconfig",
	"application_default_credentials.json", "access_tokens.db", "credentials.db",
}

var secretExts = []string{".pem", ".key", ".p12", ".pfx", ".jks", ".keystore", ".kdbx", ".ppk", ".asc.key"}

// isSecretEnv matches .env and .env.<stage> but not the templates that are
// committed on purpose.
func isSecretEnv(base string) bool {
	if base != ".env" && !strings.HasPrefix(base, ".env.") && !strings.HasSuffix(base, ".env") {
		return false
	}
	for _, s := range []string{".example", ".sample", ".template", ".dist", ".defaults", ".schema"} {
		if strings.HasSuffix(base, s) {
			return false
		}
	}
	return base == ".env" || strings.HasPrefix(base, ".env.") || base == "prod.env" || base == "production.env" || base == "local.env" || base == "secrets.env"
}

// readClass maps a path that is read to a CredAccess value, or "".
func readClass(p string) string {
	n := normPath(p)
	if n == "" {
		return ""
	}
	base := baseName(n)
	if strings.HasPrefix(n, "/proc/") && strings.HasSuffix(n, "/environ") {
		return "proc_environ_read"
	}
	// SSH private keys.
	if pathHasSeg(n, ".ssh") {
		switch {
		case strings.HasSuffix(base, ".pub"), base == "known_hosts", base == "known_hosts.old",
			base == "config", base == "authorized_keys", base == "authorized_keys2", base == "environment", base == "rc":
		default:
			return "ssh_key_read"
		}
		return ""
	}
	for _, k := range sshPrivateNames {
		if base == k {
			return "ssh_key_read"
		}
	}
	if strings.HasPrefix(n, "/etc/ssh/ssh_host_") && !strings.HasSuffix(base, ".pub") {
		return "ssh_key_read"
	}
	// OS credential stores.
	if strings.Contains(n, "/library/keychains") || strings.HasSuffix(base, ".keychain") || strings.HasSuffix(base, ".keychain-db") {
		return "keychain_dump"
	}
	if strings.HasSuffix(n, "/system32/config/sam") || strings.HasSuffix(n, "/system32/config/security") ||
		strings.HasSuffix(n, "/system32/config/system") || base == "ntds.dit" {
		return "keychain_dump"
	}
	// Browser stores.
	for _, d := range browserDirs {
		if strings.Contains(n, d) {
			return "browser_cred"
		}
	}
	switch base {
	case "login data", "logins.json", "key4.db", "cookies.sqlite", "cookies.binarycookies":
		return "browser_cred"
	}
	// Password managers.
	if pathHasSeg(n, ".password-store") || strings.Contains(n, "/keyrings/") || strings.HasSuffix(base, ".kdbx") ||
		strings.Contains(n, "1password") || strings.Contains(n, "bitwarden") {
		return "password_store"
	}
	if strings.HasPrefix(n, "~/") {
		rel := n[2:]
		for _, s := range secretHomeFiles {
			if rel == s || strings.HasPrefix(rel, s+"/") {
				return "secret_file_read"
			}
		}
	}
	for _, s := range secretHomeFiles {
		// Also catch "$SOMEDIR/.aws/credentials" and relative spellings.
		if strings.HasSuffix(n, "/"+s) || n == s {
			return "secret_file_read"
		}
	}
	for _, s := range secretAbsFiles {
		if n == s || strings.HasPrefix(n, s+"/") {
			return "secret_file_read"
		}
	}
	for _, s := range secretBaseNames {
		if base == s {
			return "secret_file_read"
		}
	}
	for _, e := range secretExts {
		if strings.HasSuffix(base, e) {
			return "secret_file_read"
		}
	}
	if isSecretEnv(base) {
		return "secret_file_read"
	}
	return ""
}

var shellProfiles = []string{
	".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc", ".zshenv",
	".zprofile", ".zlogin", ".zlogout", ".kshrc", ".cshrc", ".tcshrc", ".login", ".xprofile", ".xinitrc",
	"config.fish", "microsoft.powershell_profile.ps1", "profile.ps1", "microsoft.vscode_profile.ps1",
}

var historyFiles = []string{
	".bash_history", ".zsh_history", ".sh_history", ".history", ".zhistory", ".python_history",
	".mysql_history", ".psql_history", ".node_repl_history", ".lesshst", ".viminfo",
	"consolehost_history.txt", "fish_history", ".local/share/fish/fish_history",
}

// Directories of telemetry sensors whose files must not change under an
// agent. Process and service names are in tools.go.
var sensorDirs = []string{
	"/etc/spoor", "/var/lib/spoor", "/run/spoor", "/var/run/spoor", "/var/log/spoor", "/opt/spoor",
	"application support/spoor", "programdata/spoor", "program files/spoor", ".local/state/spoor",
	"/etc/osquery", "/var/osquery", "/var/log/osquery", "/opt/osquery", "program files/osquery", "/usr/local/osquery",
	"/opt/orbit", "/var/lib/orbit", "program files/orbit", "/etc/default/orbit", "com.fleetdm.orbit",
	"/etc/fluent-bit", "/etc/td-agent-bit", "/opt/fluent-bit", "/opt/td-agent-bit", "program files/fluent-bit",
	"/etc/audit", "/etc/falcon", "/opt/crowdstrike", "/library/cs", "/opt/sentinelone", "/library/sentinel",
	"/etc/santa", "/var/db/santa", "/var/ossec", "/library/ossec", "/opt/elastic", "/library/elastic",
	"/etc/opt/microsoft/mdatp", "/opt/microsoft/mdatp", "/usr/local/jamf", "/library/application support/jamf",
	"/usr/bin/osqueryd", "/usr/local/bin/osqueryd", "/usr/bin/osqueryi", "/usr/local/bin/spoor", "/usr/bin/spoor",
}

// Managed hook and settings locations of the hook-capable agents
// (agent-surfaces-a.md sections 2 to 6, threats.md AGENT_CONTROL_FILES).
var agentHookPaths = []string{
	"managed-settings", "managed-mcp.json", "/etc/claude-code", "application support/claudecode",
	"program files/claudecode", "programdata/claudecode",
	"/etc/codex", "programdata/openai/codex", "managed_config.toml", ".codex/config.toml", ".codex/hooks.json",
	"policy.d", "/etc/github-copilot", "programdata/github/copilot", "application support/githubcopilot",
	"program files/githubcopilot", ".copilot/hooks", ".copilot/settings.json", ".github/hooks/", ".github/copilot/settings",
	".claude/settings", "hooks.json", "/etc/cursor", "programdata/cursor", "application support/cursor/hooks",
	".gemini/settings.json", "/etc/gemini-cli", "programdata/gemini-cli", "application support/geminicli",
	// Windows policy keys and macOS managed-preference domains.
	"policies/claudecode", "policies/github/copilot", "policies/githubcopilot",
	"com.anthropic.claudecode", "com.openai.codex", "com.github.copilot",
}

func isAgentHookPath(norm string) bool {
	for _, s := range agentHookPaths {
		if strings.Contains(norm, s) {
			return true
		}
	}
	return false
}

func isSensorPath(norm string) bool {
	for _, s := range sensorDirs {
		if strings.Contains(norm, s) {
			return true
		}
	}
	return false
}

func isHistoryFile(norm string) bool {
	base := baseName(norm)
	for _, h := range historyFiles {
		if base == h || strings.HasSuffix(norm, "/"+h) {
			return true
		}
	}
	return false
}

func isLogPath(norm string) bool {
	switch {
	case strings.HasPrefix(norm, "/var/log/"), norm == "/var/log", strings.HasPrefix(norm, "/library/logs/"),
		strings.HasPrefix(norm, "/private/var/log/"), strings.Contains(norm, "/winevt/logs"),
		strings.HasPrefix(norm, "/var/audit/"), strings.HasPrefix(norm, "/var/run/utmp"),
		strings.HasSuffix(norm, ".evtx"):
		return true
	}
	return false
}

func isShellProfile(norm string) bool {
	base := baseName(norm)
	for _, s := range shellProfiles {
		if base == s {
			return true
		}
	}
	switch {
	case norm == "/etc/profile", strings.HasPrefix(norm, "/etc/profile.d/"), norm == "/etc/bash.bashrc",
		norm == "/etc/bashrc", norm == "/etc/zshrc", norm == "/etc/zprofile", norm == "/etc/zshenv",
		strings.HasPrefix(norm, "/etc/zsh/"), norm == "/etc/environment", norm == "$profile",
		strings.HasPrefix(norm, "$profile."), strings.HasPrefix(norm, "/etc/fish/"):
		return true
	}
	return false
}

// persistClass maps a path that is created or modified to a Persistence
// value, or "".
func persistClass(norm string) string {
	base := baseName(norm)
	switch {
	case base == "authorized_keys" || base == "authorized_keys2":
		return "ssh_authorized_keys"
	case strings.Contains(norm, ".git/hooks/") || strings.HasPrefix(norm, "hooks/") && strings.HasSuffix(norm, ".sample") == false && gitHookName(base):
		return "git_hook"
	case strings.Contains(norm, "/launchagents/") || strings.Contains(norm, "/launchdaemons/"):
		return "launchd"
	case strings.HasPrefix(norm, "/etc/cron") || strings.HasPrefix(norm, "/var/spool/cron") ||
		strings.HasPrefix(norm, "/var/at/tabs") || strings.HasPrefix(norm, "/usr/lib/cron"):
		return "cron"
	case strings.Contains(norm, "/systemd/system/") || strings.Contains(norm, "/systemd/user/") ||
		strings.HasPrefix(norm, "/etc/init.d/") || norm == "/etc/rc.local" || strings.HasPrefix(norm, "/etc/rc.d/") ||
		strings.HasPrefix(norm, "/etc/init/"):
		return "systemd"
	case isShellProfile(norm):
		return "shell_profile"
	case strings.Contains(norm, "/.config/autostart/") || strings.Contains(norm, "/start menu/programs/startup") ||
		strings.Contains(norm, "com.apple.loginitems") || strings.Contains(norm, "backgrounditems.btm") ||
		strings.HasPrefix(norm, "/etc/xdg/autostart/"):
		return "login_item"
	}
	return ""
}

func gitHookName(base string) bool {
	switch base {
	case "pre-commit", "pre-push", "post-checkout", "post-merge", "post-commit", "prepare-commit-msg",
		"commit-msg", "pre-rebase", "post-rewrite", "pre-receive", "update", "post-receive", "pre-applypatch",
		"post-applypatch", "applypatch-msg", "pre-merge-commit", "reference-transaction", "fsmonitor-watchman":
		return true
	}
	return false
}

func isSudoersPath(norm string) bool {
	return norm == "/etc/sudoers" || strings.HasPrefix(norm, "/etc/sudoers.d/") || norm == "/etc/sudoers.d" ||
		norm == "/private/etc/sudoers" || strings.HasPrefix(norm, "/private/etc/sudoers.d/") || norm == "/etc/doas.conf"
}

// secretName reports whether a variable or key name denotes a credential.
func secretName(name string) bool {
	l := strings.ToLower(name)
	for _, k := range []string{"token", "secret", "passw", "api_key", "apikey", "api-key", "credential", "private_key", "privatekey", "access_key", "auth_key", "session_key", "pat"} {
		if k == "pat" {
			if l == "pat" || strings.HasSuffix(l, "_pat") {
				return true
			}
			continue
		}
		if strings.Contains(l, k) {
			return true
		}
	}
	return false
}
