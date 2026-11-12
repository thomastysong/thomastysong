// Package classify turns the raw strings of an agent event (paths, hosts,
// URLs, argument vectors, free text) into closed-vocabulary facts that
// detection rules match on, and removes credentials from anything that is
// about to leave the endpoint.
//
// Everything here is a pure function of its arguments: no filesystem access,
// no DNS, no network, no global mutable state. Every input is treated as
// attacker controlled (the attacker writes the web page, the tool output and
// the repository the agent reads): sizes and recursion depth are bounded,
// regular expressions are RE2 (linear time), and every exported function
// recovers from panics. Detection functions then return "nothing found";
// redaction functions return a "[REDACTED:error:00000000]" marker instead of
// the input, because an unredacted value must never escape through a bug.
//
// # Paths
//
// PathClasses resolves a path lexically (see PathCtx) and returns classes
// from this vocabulary (PathClassVocabulary):
//
//	secret_env            .env, .env.*, *.env, .envrc (not .example/.sample/.template)
//	ssh_private_key       private keys; anything in ~/.ssh that is not a known public file; host keys
//	ssh_config            ssh client and daemon configuration, known_hosts
//	ssh_authorized_keys   authorized_keys files
//	cloud_credentials     aws, gcloud, azure, oci, doctl, terraform, pulumi ... credential stores
//	kube_config           kubeconfig files and cluster PKI
//	docker_config         registry auth, daemon config, and the engine sockets
//	git_credentials       .git-credentials, gh/glab host files, credential caches
//	netrc                 .netrc and equivalents
//	npm_token             .npmrc, .yarnrc(.yml), pnpm rc
//	pypi_token            .pypirc, pip.conf, poetry auth, uv config
//	gpg_keyring           ~/.gnupg and secret keyrings
//	password_store        pass, KeePass, 1Password, Bitwarden, LastPass data
//	keychain              macOS keychains, GNOME keyring, KWallet, Windows credential vault and DPAPI keys
//	browser_data          browser profiles (cookies, saved logins), including AI browsers
//	crypto_wallet         wallet files, keystores, seed phrases
//	shell_history         shell and REPL history files
//	shell_profile         files a shell runs at start
//	system_auth           shadow, sudoers, PAM, SAM/SECURITY hives, keytabs
//	cron                  cron, at, periodic; Windows Scheduled Tasks
//	launchd               LaunchAgents and LaunchDaemons
//	systemd_unit          systemd units and SysV init scripts
//	startup_item          autostart entries, login items, ld.so.preload, Python startup files, registry Run keys, .vscode/tasks.json
//	agent_config          settings and state of any known agent; IDE settings an agent can abuse
//	agent_managed_policy  the admin-controlled tier: managed settings, requirements, policy.d, managed preference plists and registry policy keys
//	agent_hook            hook definitions, and settings files that carry them
//	agent_memory          instruction files always loaded into context: CLAUDE.md, AGENTS.md, GEMINI.md, .cursorrules, rules/ and memory/ directories
//	agent_skill           skills, slash commands, subagent definitions, plugins, extensions
//	agent_transcript      session logs and prompt history
//	mcp_config            files that declare MCP servers
//	sensor_files          spoor, osquery/orbit, Fluent Bit and other endpoint security tooling
//	vcs_hook              .git/hooks (not *.sample), husky, pre-commit configuration
//	vcs_internal          the rest of .git, and user/system git configuration
//	ci_config             CI pipeline definitions
//	package_manifest      dependency manifests
//	lockfile              dependency lockfiles
//	dockerfile            Dockerfiles, compose files, devcontainers
//	iac                   Terraform, Helm, Kustomize, Kubernetes manifests, Pulumi, Ansible
//	cert_private_key      *.pem, *.key, *.p12, *.pfx and friends, minus certificates and public keys
//	token_file            data files named after token/secret/credential/password; AI credential stores; secret mounts
//	temp                  temporary directories
//	device                block devices and raw memory
//	proc_environ          /proc/<pid>/environ and /proc/<pid>/mem
//	outside_cwd           resolves outside the session's working directory
//	home_root             a home directory or an entry directly in it
//	system_dir            directories owned by the operating system
//	downloads             a user's Downloads directory (addition to the specified vocabulary)
//
// IsSensitiveRead and IsSensitiveWrite group these into "reading this is
// credential access" and "writing this is persistence or tampering".
//
// Not supported, by design of a lexical classifier: symlink targets, Windows
// 8.3 short names other than GIT~1, and per-drive working directories. A
// caller that can stat should classify the resolved path too.
//
// # Hosts
//
// HostClasses returns classes from HostClassVocabulary: llm_api, paste_site,
// file_share, tunnel, webhook_sink, chat_webhook, url_shortener, code_host,
// package_registry, cloud_metadata, raw_ip, private_ip, loopback,
// dynamic_dns, onion, object_storage, mail, and free_hosting (an addition to
// the specified vocabulary). A class describes the host, not the request:
// discord.com is chat_webhook whether or not the path is a webhook.
//
// # Secrets and redaction
//
// FindSecrets reports credentials (kinds in SecretKinds). Redact replaces
// them with "[REDACTED:<kind>:<fingerprint>]"; the fingerprint (first 8 hex
// digits of SHA-256) lets an analyst see that two events carried the same
// key. RedactArgs, RedactURL and RedactMap add structure-aware redaction for
// argument vectors, URLs and decoded tool inputs. References to a secret
// ($TOKEN, ${VAR}, %VAR%, @file, op://...) are never redacted: they are the
// useful, non-sensitive part.
//
// Two things callers should know. First, free-text detection of passwords
// is necessarily heuristic: "password=hunter2" is redacted, "the password is
// hunter2" is not. Use RedactArgs (or structural redaction from a shell
// parser) where the structure is known. Second, RedactArgs does not treat
// prompt text passed on a command line ("claude -p '...'") as a secret;
// whether prompts leave the endpoint is the privacy tier's decision.
//
// # Text
//
// ScanText counts invisible Unicode (tag characters, bidirectional controls,
// zero-width characters, variation-selector runs), detects look-alike letters
// in identifier-like tokens, and reports instruction-override markers
// (MarkerVocabulary). Markers describe the SHAPE of text; an instruction file
// written by the user will legitimately contain some of them. They become
// findings only when combined with where the text came from.
package classify
