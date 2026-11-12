package classify

// pathRules is the data half of the path classifier (pattern syntax in
// pathmatch.go). Classes that need more than a pattern (secret_env, the
// contents of ~/.ssh, cert_private_key exclusions, token_file, the agent
// directory layout, .git, temp, device, home_root, system_dir, outside_cwd)
// are in path.go and pathagents.go.
//
// Provenance. Agent paths come from research/agent-surfaces-a.md and
// agent-surfaces-b.md (vendor documentation and source read for this
// project), the AGENT_CONTROL_FILES and SECRET_PATHS lists in
// research/threats.md, and code.claude.com/docs/en/claude-directory.md. The
// credential-store locations are the documented defaults of each tool.
// UNVERIFIED: entries for less common tools (hcloud, scw, aliyun, bluemix,
// linode, snowflake, railway, stripe CLI, supabase) are from general
// knowledge and were not checked against the tools' documentation here.
var pathRules = []ruleGroup{
	// ---- SSH (the contents of a .ssh directory are classified in code) ----
	{class: pcSSHPrivateKey, pats: []string{
		"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", "id_ecdsa_sk", "id_ed25519_sk", "id_xmss",
		"/etc/ssh/ssh_host_*_key",
	}},
	{class: pcSSHPrivateKey, ci: true, pats: []string{"*.ppk"}},
	{class: pcSSHPrivateKey, os: osWindows, pats: []string{"/programdata/ssh/ssh_host_*_key"}},
	{class: pcSSHConfig, pats: []string{
		"/etc/ssh/ssh_config", "/etc/ssh/sshd_config", "/etc/ssh/ssh_config.d/**", "/etc/ssh/sshd_config.d/**",
	}},
	{class: pcSSHConfig, os: osWindows, pats: []string{"/programdata/ssh/sshd_config", "/programdata/ssh/ssh_config"}},
	{class: pcSSHAuthorizedKeys, os: osWindows, pats: []string{"/programdata/ssh/administrators_authorized_keys"}},

	// ---- Cloud credentials ----
	{class: pcCloudCredentials, pats: []string{
		// AWS. ~/.aws/config is deliberately not here: it holds no secret and
		// reading it is routine.
		".aws", ".aws/credentials", ".aws/sso/cache/**", ".aws/cli/cache/**", ".aws/login/cache/**",
		".s3cfg", ".boto",
		// Google Cloud.
		".config/gcloud", "gcloud/application_default_credentials.json", "gcloud/credentials.db",
		"gcloud/access_tokens.db", "gcloud/legacy_credentials/**",
		// Azure.
		".azure", ".azure/accessTokens.json", ".azure/msal_token_cache.json", ".azure/msal_token_cache.bin",
		".azure/service_principal_entries.json", ".azure/service_principal_entries.bin", ".azure/TokenCache.dat",
		// Oracle, DigitalOcean, Terraform, Pulumi, Databricks, rclone.
		".oci", ".oci/config", ".oci/sessions/**", "doctl/config.yaml",
		".terraform.d/credentials.tfrc.json", ".terraformrc", "terraform.rc",
		".pulumi/credentials.json", ".databrickscfg", "rclone/rclone.conf", "rclone.conf",
		// Platform CLIs.
		".fly/config.yml", ".wrangler/config/default.toml", "com.vercel.cli/auth.json",
		"netlify/config.json", ".config/hcloud/cli.toml", ".config/scw/config.yaml",
		".aliyun/config.json", ".bluemix/config.json", ".config/linode-cli", ".snowsql/config",
		".snowflake/connections.toml", "configstore/firebase-tools.json", ".railway/config.json",
		".config/stripe/config.toml", ".supabase/access-token", ".vault-token",
		// Workload identity inside containers.
		"/var/run/secrets/kubernetes.io/**", "/run/secrets/kubernetes.io/**",
		"/var/run/secrets/eks.amazonaws.com/**", "/var/run/secrets/azure/**", "/var/run/secrets/tokens/**",
	}},
	{class: pcCloudCredentials, ci: true, pats: []string{
		"*service-account*.json", "*service_account*.json", "*serviceaccount*.json",
	}},

	// ---- Kubernetes, containers ----
	{class: pcKubeConfig, pats: []string{
		".kube", ".kube/config", ".kube/config.d/**", "/etc/kubernetes/*.conf", "/etc/kubernetes/pki/**",
		"/etc/rancher/k3s/k3s.yaml", "/etc/rancher/rke2/rke2.yaml", "/var/lib/kubelet/kubeconfig",
		"kubeconfig", "*.kubeconfig", "kubeconfig.yaml", "kubeconfig.yml",
	}},
	{class: pcDockerConfig, pats: []string{
		".docker/config.json", ".docker/daemon.json", ".dockercfg", "/etc/docker/daemon.json",
		"containers/auth.json",
		// The engine sockets: whoever can open one controls the host.
		"docker.sock", "podman.sock", "containerd.sock", "crio.sock",
	}},

	// ---- Source control and package credentials ----
	{class: pcGitCredentials, pats: []string{
		".git-credentials", ".config/git/credentials", ".config/gh/hosts.yml", "GitHub CLI/hosts.yml",
		".config/glab-cli/config.yml", ".config/hub", ".gitcookies", ".git-credential-cache/**",
		".cache/git/credential/**",
	}},
	{class: pcNetrc, pats: []string{".netrc", "_netrc", ".netrc.gpg", ".authinfo", ".authinfo.gpg"}},
	{class: pcNPMToken, pats: []string{
		".npmrc", ".yarnrc", ".yarnrc.yml", ".pnpmrc", ".config/pnpm/rc", "/etc/npmrc", "etc/npmrc",
	}},
	{class: pcPyPIToken, pats: []string{
		".pypirc", "pip.conf", "pip.ini", "pypoetry/auth.toml", ".config/uv/uv.toml", "/etc/uv/uv.toml",
	}},
	{class: pcTokenFile, pats: []string{
		// AI credential stores (research/threats.md SECRET_PATHS, "AI").
		".claude/.credentials.json", ".codex/auth.json", ".gemini/oauth_creds.json",
		// UNVERIFIED: GitHub Copilot editor plugins keep OAuth tokens here.
		"github-copilot/hosts.json", "github-copilot/apps.json",
		// UNVERIFIED: opencode provider keys.
		".local/share/opencode/auth.json",
		// Build tool credentials whose names do not say so.
		".m2/settings.xml", ".m2/settings-security.xml", ".gradle/gradle.properties",
		"composer/auth.json", ".composer/auth.json", "NuGet/NuGet.Config",
		// Container and orchestrator secret mounts.
		"/run/secrets/**", "/var/run/secrets/**",
	}},
	{class: pcTokenFile, ci: true, pats: []string{
		// Cursor keeps its session token in the same SQLite file as chats.
		"Cursor/User/globalStorage/state.vscdb",
	}},

	// ---- Key stores ----
	{class: pcGPGKeyring, pats: []string{
		".gnupg/**", "private-keys-v1.d/**", "secring.gpg", "trustdb.gpg",
	}},
	{class: pcGPGKeyring, os: osWindows, pats: []string{"appdata/roaming/gnupg/**"}},
	{class: pcPasswordStore, pats: []string{
		".password-store/**", ".config/op/**", ".lpass/**", ".local/share/lpass/**", ".local/share/gopass/**",
		"Bitwarden/data.json", "Bitwarden CLI/data.json", "2BUA8C4S2C.com.1password/**",
	}},
	{class: pcPasswordStore, ci: true, pats: []string{
		"*.kdbx", "*.kdb", "1Password/**", "*.agilekeychain/**", "*.opvault/**",
	}},
	{class: pcKeychain, pats: []string{
		"Library/Keychains/**", ".local/share/keyrings/**", ".local/share/kwalletd/**", ".gnome2/keyrings/**",
	}},
	{class: pcKeychain, ci: true, pats: []string{"*.keychain", "*.keychain-db"}},
	{class: pcKeychain, os: osWindows, pats: []string{
		// DPAPI-protected credential blobs and the master keys that open them.
		"microsoft/credentials/**", "microsoft/protect/**", "microsoft/vault/**",
	}},
	{class: pcCertPrivateKey, pats: []string{
		"/etc/ssl/private/**", "/etc/pki/tls/private/**", "/etc/letsencrypt/live/**",
		"/etc/letsencrypt/archive/**", "/etc/wireguard/**", "sops/age/keys.txt",
	}},
	{class: pcCertPrivateKey, os: osWindows, pats: []string{"microsoft/crypto/**"}},

	// ---- Browsers and wallets ----
	{class: pcBrowserData, ci: true, pats: []string{
		"Google/Chrome/**", "Google/Chrome Beta/**", "Google/Chrome Canary/**", "Google/Chrome SxS/**",
		".config/google-chrome/**", ".config/google-chrome-beta/**", ".config/chromium/**",
		"Application Support/Chromium/**", "AppData/Local/Chromium/**", "snap/chromium/**",
		"Microsoft Edge/**", "Microsoft/Edge/**", ".config/microsoft-edge/**",
		"BraveSoftware/**", "Application Support/Vivaldi/**", "AppData/Local/Vivaldi/**", ".config/vivaldi/**",
		"com.operasoftware.Opera/**", "Opera Software/**", ".config/opera/**",
		"Application Support/Arc/**", "Firefox/Profiles/**", ".mozilla/firefox/**", ".librewolf/**",
		"Library/Safari/**", "Library/Cookies/**", "Containers/com.apple.Safari/**",
		// AI browsers (research/agent-surfaces-b.md section 1b).
		"Application Support/Comet/**", "Application Support/com.openai.atlas/**", "OpenAI/ChatGPT Atlas/**",
		// The credential files themselves, for Chromium and Gecko forks whose
		// profile directory is not listed above.
		"Login Data", "Login Data For Account", "Web Data", "Network/Cookies", "Default/Cookies",
		"cookies.sqlite", "logins.json", "key4.db", "key3.db", "signons.sqlite", "Cookies.binarycookies",
		"places.sqlite", "formhistory.sqlite",
	}},
	{class: pcCryptoWallet, ci: true, pats: []string{
		".bitcoin/**", "wallet.dat", ".ethereum/keystore/**", "Ethereum/keystore/**", ".electrum/**",
		"Electrum/wallets/**", "Application Support/Exodus/**", ".config/Exodus/**", "AppData/Roaming/Exodus/**",
		".config/solana/**", "Ledger Live/**", "atomic/Local Storage/**", "Monero/wallets/**",
		// MetaMask and Phantom extension storage inside any Chromium profile.
		"nkbihfbeogaeaoehlefnkodbefgpgknn/**", "bfnaelmomeimhlpmgjnjophhpkkoljpa/**",
		".near-credentials/**", ".aptos/config.yaml", "sui.keystore", ".foundry/keystores/**",
		".brownie/accounts/**", "*seed-phrase*", "*seed_phrase*", "*recovery-phrase*", "*recovery_phrase*",
		"mnemonic.txt",
	}},

	// ---- Shell ----
	{class: pcShellHistory, pats: []string{
		".bash_history", ".zsh_history", ".zhistory", ".sh_history", ".histfile", ".history",
		".python_history", ".node_repl_history", ".psql_history", ".mysql_history", ".sqlite_history",
		".rediscli_history", ".irb_history", ".lesshst", "fish/fish_history", ".zsh_sessions/**",
	}},
	{class: pcShellHistory, ci: true, pats: []string{"PSReadLine/ConsoleHost_history.txt"}},
	{class: pcShellProfile, pats: []string{
		".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".bash_aliases", ".profile",
		".zshrc", ".zshenv", ".zprofile", ".zlogin", ".zlogout", ".kshrc", ".cshrc", ".tcshrc", ".login",
		".xprofile", ".xinitrc", ".xsessionrc", ".pam_environment",
		"fish/config.fish", "fish/conf.d/**", "fish/functions/**", "nushell/config.nu", "nushell/env.nu",
		"/etc/profile", "/etc/profile.d/**", "/etc/bash.bashrc", "/etc/bashrc", "/etc/zshrc", "/etc/zshenv",
		"/etc/zprofile", "/etc/zsh/**", "/etc/environment", "/etc/paths", "/etc/paths.d/**",
	}},
	{class: pcShellProfile, ci: true, pats: []string{"profile.ps1", "*_profile.ps1"}},

	// ---- System authentication ----
	{class: pcSystemAuth, pats: []string{
		"/etc/shadow", "/etc/shadow-", "/etc/gshadow", "/etc/gshadow-", "/etc/master.passwd",
		"/etc/sudoers", "/etc/sudoers.d/**", "/etc/doas.conf", "/etc/pam.d/**", "/etc/security/**",
		"/etc/polkit-1/**", "/etc/krb5.keytab", "/var/db/dslocal/nodes/Default/users/**", "ntds.dit",
	}},
	{class: pcSystemAuth, ci: true, pats: []string{"*.keytab"}},
	{class: pcSystemAuth, os: osWindows, pats: []string{
		"/windows/system32/config/sam", "/windows/system32/config/system", "/windows/system32/config/security",
		"/windows/system32/config/regback/**", "/windows/repair/sam", "/windows/repair/system",
		"/windows/ntds/**",
	}},

	// ---- Scheduled and boot-time execution ----
	{class: pcCron, pats: []string{
		"/etc/crontab", "/etc/cron.d/**", "/etc/cron.daily/**", "/etc/cron.hourly/**", "/etc/cron.weekly/**",
		"/etc/cron.monthly/**", "/etc/anacrontab", "/etc/periodic/**", "/var/spool/cron/**",
		"/var/spool/at/**", "/var/at/**", "/usr/lib/cron/tabs/**",
	}},
	// Scheduled Tasks are the Windows counterpart of cron.
	{class: pcCron, os: osWindows, pats: []string{"/windows/system32/tasks/**", "/windows/tasks/**"}},
	{class: pcLaunchd, pats: []string{"Library/LaunchAgents/**", "Library/LaunchDaemons/**"}},
	{class: pcSystemdUnit, pats: []string{
		"/etc/systemd/**", "/usr/lib/systemd/**", "/lib/systemd/**", "/usr/local/lib/systemd/**",
		"/run/systemd/system/**", ".config/systemd/**", ".local/share/systemd/**",
		"/etc/init.d/**", "/etc/rc.local", "/etc/rc.d/**",
	}},
	{class: pcStartupItem, pats: []string{
		".config/autostart/**", "/etc/xdg/autostart/**", "/etc/ld.so.preload", "/etc/udev/rules.d/**",
		"/etc/NetworkManager/dispatcher.d/**", "/etc/update-motd.d/**",
		"/Library/StartupItems/**", "/Library/Security/SecurityAgentPlugins/**",
		"/Library/PrivilegedHelperTools/**", "/etc/emond.d/**",
		"Library/Preferences/com.apple.loginitems.plist", "Library/Preferences/com.apple.loginwindow.plist",
		"com.apple.backgroundtaskmanagementagent/**",
		// Python runs these at interpreter start (threat research rule R39).
		"sitecustomize.py", "usercustomize.py", "site-packages/*.pth", "dist-packages/*.pth",
		// Editors run these when a folder is opened.
		".vscode/tasks.json", ".vscode/launch.json",
	}},
	{class: pcStartupItem, os: osWindows, pats: []string{
		"start menu/programs/startup/**", "/windows/system32/grouppolicy/machine/scripts/**",
		"/windows/system32/grouppolicy/user/scripts/**",
	}},

	// ---- Agent files that the directory layout in pathagents.go does not imply ----
	{class: pcMCPConfig, pats: []string{
		".mcp.json", "mcp.json", "mcp_config.json", "mcp-config.json", "mcp_settings.json",
		"cline_mcp_settings.json", "managed-mcp.json", "claude_desktop_config.json", ".claude.json",
		".codex/config.toml", "/etc/codex/config.toml", ".gemini/settings.json", ".qwen/settings.json",
		".config/zed/settings.json", ".zed/settings.json", "Zed/settings.json",
		"amp/settings.json", ".amp/settings.json", "opencode.json", "opencode.jsonc",
		".config/goose/config.yaml", "goose/config/config.yaml",
		".continue/config.yaml", ".continue/config.json", ".continue/mcpServers/**",
		".hermes/config.yaml", ".openclaw/openclaw.json", "crush.json", ".crush.json",
		"Code/User/mcp.json", "Code - Insiders/User/mcp.json",
	}},
	{class: pcAgentHook, pats: []string{
		// Settings files that carry hook definitions, and dedicated hook files.
		".claude/settings.json", ".claude/settings.local.json", ".gemini/settings.json", ".qwen/settings.json",
		"hooks.json", ".github/hooks/**", "/etc/github-copilot/policy.d/**",
	}},
	{class: pcAgentHook, os: osWindows, pats: []string{"/programdata/github/copilot/policy.d/**"}},
	{class: pcAgentConfig, pats: []string{
		".claude.json", "claude_desktop_config.json", "opencode.json", "opencode.jsonc", "crush.json",
		".crushrc", "crushrc", ".aider.conf.yml", ".roomodes", ".cursorignore",
		// IDE settings an agent can use to reach execution (IDEsaster class,
		// research/threats.md items 3, 5, 6).
		".vscode/settings.json", "*.code-workspace", ".idea/workspace.xml",
		"Code/User/settings.json", "Code - Insiders/User/settings.json",
		".github/copilot/**",
	}},
	{class: pcAgentManagedPolicy, pats: []string{
		// Claude Code (research/agent-surfaces-a.md section 2).
		"/Library/Application Support/ClaudeCode/**", "/etc/claude-code/**",
		"managed-settings.json", "managed-settings.d/**", "managed-mcp.json",
		"/Library/Managed Preferences/com.anthropic.claudecode.plist",
		"/Library/Managed Preferences/*/com.anthropic.claudecode.plist",
		// Codex (section 3).
		"/etc/codex/**", "codex/requirements.toml", "codex/managed_config.toml",
		"/Library/Managed Preferences/com.openai.codex.plist",
		"/Library/Managed Preferences/*/com.openai.codex.plist",
		// GitHub Copilot (section 4).
		"/etc/github-copilot/**", "/Library/Application Support/GitHubCopilot/**",
		"/Library/Managed Preferences/com.github.copilot.plist",
		"/Library/Managed Preferences/*/com.github.copilot.plist",
		// Gemini CLI (section 5) and Cursor (section 6).
		"/etc/gemini-cli/**", "/Library/Application Support/GeminiCli/**",
		"/etc/cursor/**", "/Library/Application Support/Cursor/hooks.json",
	}},
	{class: pcAgentManagedPolicy, os: osWindows, pats: []string{
		"/program files/claudecode/**", "/programdata/claudecode/**", "/programdata/openai/codex/**",
		"/programdata/github/copilot/**", "/program files/githubcopilot/**",
		"/programdata/gemini-cli/**", "/programdata/cursor/**",
	}},
	{class: pcAgentMemory, pats: []string{
		"CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", "AGENTS.override.md", "GEMINI.md", "CRUSH.md",
		"QWEN.md", "SOUL.md", ".cursorrules", ".windsurfrules", ".clinerules", ".clinerules/**",
		".roorules", ".goosehints", "copilot-instructions.md", ".github/instructions/**",
		".junie/guidelines.md",
	}},
	{class: pcAgentSkill, pats: []string{"SKILL.md"}},
	{class: pcAgentTranscript, pats: []string{
		".aider.chat.history.md", ".aider.input.history", ".aider.llm.history",
	}},
	{class: pcAgentTranscript, ci: true, pats: []string{
		// Cursor chat state (research/agent-surfaces-a.md section 6).
		"Cursor/User/globalStorage/state.vscdb", "Cursor/User/globalStorage/state.vscdb-wal",
		"Cursor/User/workspaceStorage/*/state.vscdb",
	}},

	// ---- The sensor and its neighbours ----
	{class: pcSensorFiles, pats: []string{
		// hawkbell (design: platform.DefaultDirs and UserDirs).
		"/etc/hawkbell/**", "/var/lib/hawkbell/**", "/var/log/hawkbell/**", "/run/hawkbell/**", "/var/run/hawkbell/**",
		"/opt/hawkbell/**", "/usr/local/bin/hawkbell", "/usr/bin/hawkbell", "/Library/Application Support/hawkbell/**",
		".local/state/hawkbell/**", "Application Support/hawkbell/**", ".config/hawkbell/**",
		// osquery and Fleet's orbit.
		"/etc/osquery/**", "/var/osquery/**", "/var/log/osquery/**", "/opt/osquery/**", "/opt/orbit/**",
		"/var/lib/orbit/**", "/var/log/orbit/**", "/usr/local/bin/osqueryd", "/usr/bin/osqueryd",
		"com.fleetdm.orbit.plist", "io.osquery.agent.plist", "/usr/lib/systemd/system/orbit.service",
		"/usr/lib/systemd/system/osqueryd.service",
		// Fluent Bit.
		"/etc/fluent-bit/**", "/opt/fluent-bit/**", "/etc/td-agent-bit/**", "/opt/td-agent-bit/**",
		"/var/log/fluent-bit/**", "/usr/lib/systemd/system/fluent-bit.service",
		// Other endpoint security tooling an agent has no business editing.
		"/opt/CrowdStrike/**", "/Library/CS/**", "/Library/Application Support/CrowdStrike/**",
		"/opt/sentinelone/**", "/Library/Sentinel/**", "/opt/microsoft/mdatp/**", "/etc/opt/microsoft/mdatp/**",
		"/Library/Application Support/Microsoft/Defender/**", "/var/db/santa/**", "/etc/santa/**",
		"/etc/audit/**", "/var/log/audit/**", "/var/ossec/**", "/opt/Elastic/**", "/Library/Elastic/**",
		"/usr/local/jamf/**", "/Library/Application Support/JAMF/**", "/opt/sysmon/**", "/etc/falco/**",
	}},
	// This sensor's own install locations only (platform.DefaultDirs and
	// UserDirs, the packages' binary and service paths), rooted, so that a
	// glob or a path relative to the session directory is matched with the
	// same anchors as the HB-EVADE-002 path list. Case-insensitive like
	// that rule.
	{class: pcSensorSelf, ci: true, named: true, pats: []string{
		"/etc/hawkbell/**", "/var/lib/hawkbell/**", "/var/log/hawkbell/**", "/run/hawkbell/**", "/var/run/hawkbell/**",
		"/private/var/run/hawkbell/**", "/opt/hawkbell/**",
		"/usr/bin/hawkbell/**", "/usr/sbin/hawkbell/**", "/usr/lib/hawkbell/**", "/usr/libexec/hawkbell/**",
		"/usr/local/bin/hawkbell/**", "/usr/local/sbin/hawkbell/**", "/usr/local/lib/hawkbell/**", "/usr/local/libexec/hawkbell/**",
		"/bin/hawkbell/**", "/sbin/hawkbell/**", "/lib/hawkbell/**", "/libexec/hawkbell/**",
		"/usr/lib/systemd/system/hawkbell.service/**", "/lib/systemd/system/hawkbell.service/**", "/etc/systemd/system/hawkbell.service/**",
		"/usr/lib/systemd/system/hawkbell.service.d/**", "/lib/systemd/system/hawkbell.service.d/**", "/etc/systemd/system/hawkbell.service.d/**",
		"/Library/Application Support/hawkbell/**", "/Library/Logs/hawkbell/**",
		"/Library/LaunchDaemons/com.github.thomastysong.hawkbell.plist",
		"/root/.local/state/hawkbell/**", "/var/root/.local/state/hawkbell/**", "/home/*/.local/state/hawkbell/**", "/Users/*/.local/state/hawkbell/**",
		"/root/Library/Application Support/hawkbell/**", "/var/root/Library/Application Support/hawkbell/**",
		"/home/*/Library/Application Support/hawkbell/**", "/Users/*/Library/Application Support/hawkbell/**",
	}},
	{class: pcSensorSelf, os: osWindows, named: true, pats: []string{
		"/program files/hawkbell/**", "/programdata/hawkbell/**", "/users/*/appdata/local/hawkbell/**",
	}},
	{class: pcSensorFiles, os: osWindows, pats: []string{
		"/programdata/hawkbell/**", "/program files/hawkbell/**", "appdata/local/hawkbell/**",
		"/program files/osquery/**", "/program files/orbit/**", "/programdata/osquery/**",
		"/program files/fluent-bit/**", "/program files/crowdstrike/**",
		"/windows/system32/drivers/crowdstrike/**", "/program files/sentinelone/**",
		"/programdata/microsoft/windows defender/**", "/program files/windows defender/**",
		"/program files (x86)/ossec-agent/**", "/program files/elastic/**",
		"/windows/system32/winevt/logs/**",
	}},

	// ---- Source control (the inside of .git is classified in code) ----
	{class: pcVCSHook, pats: []string{
		".husky/**", ".githooks/**", ".pre-commit-config.yaml", "lefthook.yml", "lefthook.yaml", ".lefthook.yml",
	}},
	{class: pcVCSInternal, pats: []string{
		// User and system git configuration carry the same execution sinks as
		// a repository's .git/config (core.fsmonitor, core.sshCommand, aliases).
		".gitconfig", ".config/git/config", "/etc/gitconfig", ".hg/hgrc",
	}},

	// ---- Project files ----
	{class: pcCIConfig, pats: []string{
		".github/workflows/**", ".github/actions/**", ".github/dependabot.yml", ".gitlab-ci.yml",
		".gitlab/ci/**", "Jenkinsfile", "Jenkinsfile.*", ".circleci/**", "azure-pipelines.yml",
		"azure-pipelines.yaml", ".azure-pipelines/**", ".travis.yml", "bitbucket-pipelines.yml",
		".buildkite/**", ".drone.yml", ".woodpecker.yml", ".woodpecker/**", ".teamcity/**",
		"cloudbuild.yaml", "cloudbuild.yml", "buildspec.yml", "buildspec.yaml", ".tekton/**",
		"appveyor.yml", ".appveyor.yml", ".semaphore/**", ".forgejo/workflows/**", ".gitea/workflows/**",
	}},
	{class: pcPackageManifest, pats: []string{
		"package.json", "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt", "requirements-*.txt",
		"requirements_*.txt", "requirements/*.txt", "Pipfile", "Cargo.toml", "go.mod", "Gemfile",
		"*.gemspec", "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts",
		"composer.json", "*.csproj", "*.fsproj", "*.vbproj", "packages.config", "Directory.Packages.props",
		"Package.swift", "Podfile", "pubspec.yaml", "mix.exs", "deno.json", "deno.jsonc", "bunfig.toml",
		"pnpm-workspace.yaml", "environment.yml", "environment.yaml", "build.sbt", "project.clj", "deps.edn",
		"Brewfile", "flake.nix", "vcpkg.json", "conanfile.txt", "conanfile.py", "go.work",
	}},
	{class: pcLockfile, pats: []string{
		"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lock", "bun.lockb",
		"Cargo.lock", "go.sum", "go.work.sum", "poetry.lock", "uv.lock", "Pipfile.lock", "pdm.lock",
		"Gemfile.lock", "composer.lock", "packages.lock.json", "Podfile.lock", "pubspec.lock", "mix.lock",
		"flake.lock", "gradle.lockfile", "deno.lock", "Package.resolved", "conan.lock", "pixi.lock",
		".terraform.lock.hcl",
	}},
	{class: pcDockerfile, pats: []string{
		"Dockerfile", "Dockerfile.*", "*.Dockerfile", "dockerfile", "*.dockerfile", "Containerfile",
		"Containerfile.*", "docker-compose.yml", "docker-compose.yaml", "docker-compose.*.yml",
		"docker-compose.*.yaml", "compose.yml", "compose.yaml", "compose.*.yml", "compose.*.yaml",
		".devcontainer/**", ".devcontainer.json", "docker-bake.hcl",
	}},
	{class: pcIaC, ci: true, pats: []string{
		"*.tf", "*.tf.json", "*.tfvars", "*.tfvars.json", "*.tfstate", "*.tfstate.backup", "*.hcl",
		".terraform/**", "*.bicep", "*.bicepparam", "*.nomad",
	}},
	{class: pcIaC, pats: []string{
		"Chart.yaml", "values.yaml", "values-*.yaml", "values.*.yaml", "kustomization.yaml",
		"kustomization.yml", "helmfile.yaml", "skaffold.yaml", "Pulumi.yaml", "Pulumi.*.yaml",
		"serverless.yml", "serverless.yaml", "cdk.json", "ansible.cfg", "playbook.yml", "playbook.yaml",
		"Vagrantfile", "k8s/**", "kubernetes/**", "manifests/**", "helm/**", "playbooks/**",
		"terraform/**", "cloudformation/**",
	}},
}
