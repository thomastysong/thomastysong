package classify

// Path classes. The vocabulary is closed; PathClassVocabulary lists it.
const (
	PathSecretEnv          = "secret_env"
	PathSSHPrivateKey      = "ssh_private_key"
	PathSSHConfig          = "ssh_config"
	PathSSHAuthorizedKeys  = "ssh_authorized_keys"
	PathCloudCredentials   = "cloud_credentials"
	PathKubeConfig         = "kube_config"
	PathDockerConfig       = "docker_config"
	PathGitCredentials     = "git_credentials"
	PathNetrc              = "netrc"
	PathNPMToken           = "npm_token"
	PathPyPIToken          = "pypi_token"
	PathGPGKeyring         = "gpg_keyring"
	PathPasswordStore      = "password_store"
	PathKeychain           = "keychain"
	PathBrowserData        = "browser_data"
	PathCryptoWallet       = "crypto_wallet"
	PathShellHistory       = "shell_history"
	PathShellProfile       = "shell_profile"
	PathSystemAuth         = "system_auth"
	PathCron               = "cron"
	PathLaunchd            = "launchd"
	PathSystemdUnit        = "systemd_unit"
	PathStartupItem        = "startup_item"
	PathAgentConfig        = "agent_config"
	PathAgentManagedPolicy = "agent_managed_policy"
	PathAgentHook          = "agent_hook"
	PathAgentMemory        = "agent_memory"
	PathAgentSkill         = "agent_skill"
	PathAgentTranscript    = "agent_transcript"
	PathMCPConfig          = "mcp_config"
	PathSensorFiles        = "sensor_files"
	PathVCSHook            = "vcs_hook"
	PathVCSInternal        = "vcs_internal"
	PathCIConfig           = "ci_config"
	PathPackageManifest    = "package_manifest"
	PathLockfile           = "lockfile"
	PathDockerfile         = "dockerfile"
	PathIaC                = "iac"
	PathCertPrivateKey     = "cert_private_key"
	PathTokenFile          = "token_file"
	PathTemp               = "temp"
	PathDevice             = "device"
	PathProcEnviron        = "proc_environ"
	PathOutsideCWD         = "outside_cwd"
	PathHomeRoot           = "home_root"
	PathSystemDir          = "system_dir"
	// PathDownloads is an addition to the specified vocabulary: files that
	// arrived from elsewhere (a browser download directory) are the untrusted
	// location several threat rules key on.
	PathDownloads = "downloads"
)

// pathClass is a bit index into a set; the order here is the order classes
// are returned in.
type pathClass uint8

const (
	pcSecretEnv pathClass = iota
	pcSSHPrivateKey
	pcSSHConfig
	pcSSHAuthorizedKeys
	pcCloudCredentials
	pcKubeConfig
	pcDockerConfig
	pcGitCredentials
	pcNetrc
	pcNPMToken
	pcPyPIToken
	pcGPGKeyring
	pcPasswordStore
	pcKeychain
	pcBrowserData
	pcCryptoWallet
	pcShellHistory
	pcShellProfile
	pcSystemAuth
	pcCron
	pcLaunchd
	pcSystemdUnit
	pcStartupItem
	pcAgentConfig
	pcAgentManagedPolicy
	pcAgentHook
	pcAgentMemory
	pcAgentSkill
	pcAgentTranscript
	pcMCPConfig
	pcSensorFiles
	pcVCSHook
	pcVCSInternal
	pcCIConfig
	pcPackageManifest
	pcLockfile
	pcDockerfile
	pcIaC
	pcCertPrivateKey
	pcTokenFile
	pcTemp
	pcDevice
	pcProcEnviron
	pcOutsideCWD
	pcHomeRoot
	pcSystemDir
	pcDownloads
	pcCount
)

var pathClassNames = [pcCount]string{
	PathSecretEnv, PathSSHPrivateKey, PathSSHConfig, PathSSHAuthorizedKeys,
	PathCloudCredentials, PathKubeConfig, PathDockerConfig, PathGitCredentials,
	PathNetrc, PathNPMToken, PathPyPIToken, PathGPGKeyring, PathPasswordStore,
	PathKeychain, PathBrowserData, PathCryptoWallet, PathShellHistory,
	PathShellProfile, PathSystemAuth, PathCron, PathLaunchd, PathSystemdUnit,
	PathStartupItem, PathAgentConfig, PathAgentManagedPolicy, PathAgentHook,
	PathAgentMemory, PathAgentSkill, PathAgentTranscript, PathMCPConfig,
	PathSensorFiles, PathVCSHook, PathVCSInternal, PathCIConfig,
	PathPackageManifest, PathLockfile, PathDockerfile, PathIaC,
	PathCertPrivateKey, PathTokenFile, PathTemp, PathDevice, PathProcEnviron,
	PathOutsideCWD, PathHomeRoot, PathSystemDir, PathDownloads,
}

// pathSet is a set of path classes.
type pathSet uint64

func (s *pathSet) add(c pathClass)     { *s |= 1 << c }
func (s pathSet) has(c pathClass) bool { return s&(1<<c) != 0 }

func (s pathSet) names() []string {
	if s == 0 {
		return nil
	}
	out := make([]string, 0, 4)
	for c := pathClass(0); c < pcCount; c++ {
		if s.has(c) {
			out = append(out, pathClassNames[c])
		}
	}
	return out
}

// PathClassVocabulary returns every class PathClasses can return.
func PathClassVocabulary() []string {
	out := make([]string, len(pathClassNames))
	copy(out, pathClassNames[:])
	return out
}

// sensitiveRead are the classes whose READ is credential access: the file
// holds a secret, or lets its reader act as the user.
var sensitiveRead = lazySet{list: []string{
	PathSecretEnv, PathSSHPrivateKey, PathCloudCredentials,
	PathKubeConfig, PathDockerConfig, PathGitCredentials,
	PathNetrc, PathNPMToken, PathPyPIToken,
	PathGPGKeyring, PathPasswordStore, PathKeychain,
	PathBrowserData, PathCryptoWallet, PathShellHistory,
	PathSystemAuth, PathCertPrivateKey, PathTokenFile,
	PathProcEnviron,
}}

// sensitiveWrite are the classes whose WRITE is persistence or tampering: the
// file is executed or trusted later by the OS, a tool, an agent or the sensor.
// agent_memory and ci_config are deliberately absent: agents edit CLAUDE.md
// and workflow files in ordinary work, so a write there is a signal for
// sequence rules (untrusted read, then memory write), not a finding alone.
var sensitiveWrite = lazySet{list: []string{
	PathSSHAuthorizedKeys, PathSSHConfig, PathShellProfile,
	PathCron, PathLaunchd, PathSystemdUnit,
	PathStartupItem, PathSystemAuth, PathAgentConfig,
	PathAgentManagedPolicy, PathAgentHook, PathAgentSkill,
	PathMCPConfig, PathSensorFiles, PathVCSHook,
	PathVCSInternal, PathNPMToken, PathPyPIToken,
	PathDockerConfig, PathKubeConfig, PathGitCredentials,
	PathDevice, PathSystemDir,
}}

// IsSensitiveRead reports whether any class marks a path whose read is
// credential access.
func IsSensitiveRead(classes []string) bool {
	for _, c := range classes {
		if sensitiveRead.has(c) {
			return true
		}
	}
	return false
}

// IsSensitiveWrite reports whether any class marks a path whose write is
// persistence or tampering.
func IsSensitiveWrite(classes []string) bool {
	for _, c := range classes {
		if sensitiveWrite.has(c) {
			return true
		}
	}
	return false
}

// SensitiveReadClasses returns the classes IsSensitiveRead accepts, in
// vocabulary order.
func SensitiveReadClasses() []string { return filterVocab(&sensitiveRead) }

// SensitiveWriteClasses returns the classes IsSensitiveWrite accepts, in
// vocabulary order.
func SensitiveWriteClasses() []string { return filterVocab(&sensitiveWrite) }

func filterVocab(set *lazySet) []string {
	out := make([]string, 0, len(set.list))
	for _, n := range pathClassNames {
		if set.has(n) {
			out = append(out, n)
		}
	}
	return out
}

// Host classes. The vocabulary is closed; HostClassVocabulary lists it.
const (
	HostLLMAPI          = "llm_api"
	HostPasteSite       = "paste_site"
	HostFileShare       = "file_share"
	HostTunnel          = "tunnel"
	HostWebhookSink     = "webhook_sink"
	HostChatWebhook     = "chat_webhook"
	HostURLShortener    = "url_shortener"
	HostCodeHost        = "code_host"
	HostPackageRegistry = "package_registry"
	HostCloudMetadata   = "cloud_metadata"
	HostRawIP           = "raw_ip"
	HostPrivateIP       = "private_ip"
	HostLoopback        = "loopback"
	HostDynamicDNS      = "dynamic_dns"
	HostOnion           = "onion"
	HostObjectStorage   = "object_storage"
	HostMail            = "mail"
	// HostFreeHosting is an addition to the specified vocabulary: platforms
	// where anyone can stand up an endpoint under a shared domain in minutes
	// (*.workers.dev, *.onrender.com, *.vercel.app). Attack infrastructure
	// lives there because the parent domain is rarely blocked.
	HostFreeHosting = "free_hosting"
)

type hostBits uint32

const (
	hbLLM hostBits = 1 << iota
	hbPaste
	hbFileShare
	hbTunnel
	hbWebhookSink
	hbChatWebhook
	hbShortener
	hbCodeHost
	hbRegistry
	hbMetadata
	hbRawIP
	hbPrivateIP
	hbLoopback
	hbDynDNS
	hbOnion
	hbObjectStorage
	hbMail
	hbFreeHosting
)

var hostClassNames = []string{
	HostLLMAPI, HostPasteSite, HostFileShare, HostTunnel, HostWebhookSink,
	HostChatWebhook, HostURLShortener, HostCodeHost, HostPackageRegistry,
	HostCloudMetadata, HostRawIP, HostPrivateIP, HostLoopback, HostDynamicDNS,
	HostOnion, HostObjectStorage, HostMail, HostFreeHosting,
}

func (b hostBits) names() []string {
	if b == 0 {
		return nil
	}
	out := make([]string, 0, 3)
	for i, n := range hostClassNames {
		if b&(1<<uint(i)) != 0 {
			out = append(out, n)
		}
	}
	return out
}

// HostClassVocabulary returns every class HostClasses can return.
func HostClassVocabulary() []string {
	return append([]string(nil), hostClassNames...)
}
