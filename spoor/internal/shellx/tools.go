package shellx

import "strings"

// securityTools are substrings of process, service, package and launchd
// label names of the endpoint security and telemetry tools named in the
// spec: osqueryd, orbit, fleetd, fluent-bit, td-agent-bit, spoor,
// falcon/crowdstrike, sentinelone, defender (MsMpEng, mdatp), santa, auditd,
// sysmon, wazuh, elastic-agent, jamf.
//
// UNVERIFIED: the service and daemon aliases beyond the names in the spec
// (falcond, csfalconservice, sentineld, wdavdaemon, windefend, wazuhsvc,
// elastic-endpoint, jamfprotect) are from general knowledge of those products,
// not from a primary source read for this build.
var securityTools = []string{
	"osqueryd", "osquery", "orbit", "fleetd", "fleet-desktop", "fluent-bit", "fluentbit", "td-agent-bit", "td-agent",
	"spoor", "falcon-sensor", "falcond", "falconctl", "falcon", "crowdstrike", "csagent", "csfalcon",
	"sentinelone", "sentinelctl", "sentinelagent", "sentineld", "sentinel-agent",
	"msmpeng", "mdatp", "wdavdaemon", "windefend", "windows defender", "defender", "mssense", "microsoft.mdatp",
	"santa", "santad", "auditd", "sysmon", "sysmon64", "sysmondrv", "wazuh", "wazuh-agent", "wazuhsvc", "ossec",
	"elastic-agent", "elastic-endpoint", "elastic_agent", "jamf", "jamfprotect",
}

// exactSecurityTools match only as a whole token: they are too short or too
// generic to match as substrings.
var exactSecurityTools = []string{"sense", "sysmon", "santa", "orbit", "jamf", "spoor", "falcon"}

// securityTool returns the canonical tool name when token names a security
// tool's process, service, unit, package or launchd label.
func securityTool(token string) (string, bool) {
	t := strings.ToLower(strings.TrimSpace(token))
	t = strings.Trim(t, "\"'")
	if t == "" || len(t) > 256 {
		return "", false
	}
	// Reduce paths, unit names and plists to their identifying part.
	t = baseName(t)
	for _, suf := range []string{".service", ".plist", ".exe", ".socket", ".timer"} {
		t = strings.TrimSuffix(t, suf)
	}
	for _, e := range exactSecurityTools {
		if t == e {
			return e, true
		}
	}
	for _, s := range securityTools {
		if len(s) <= 6 {
			// Short names must match a whole dotted or dashed component so
			// that "orbital" or "falconry" do not match.
			if tokenHasWord(t, s) {
				return s, true
			}
			continue
		}
		if strings.Contains(t, s) {
			return s, true
		}
	}
	return "", false
}

func tokenHasWord(t, w string) bool {
	for i := 0; ; {
		j := strings.Index(t[i:], w)
		if j < 0 {
			return false
		}
		j += i
		before := j == 0 || !isAlnum(t[j-1])
		after := j+len(w) == len(t) || !isAlnum(t[j+len(w)])
		if before && after {
			return true
		}
		i = j + 1
		if i >= len(t) {
			return false
		}
	}
}

// isAuditTool reports tools whose stop also means audit logging is off.
func isAuditTool(tool string) bool { return tool == "auditd" }

func isDefenderTool(tool string) bool {
	switch tool {
	case "msmpeng", "mdatp", "wdavdaemon", "windefend", "windows defender", "defender", "mssense", "microsoft.mdatp", "sense":
		return true
	}
	return false
}

// firewallServices and loggingServices are matched as whole tokens.
func isFirewallService(t string) bool {
	t = strings.TrimSuffix(strings.ToLower(baseName(t)), ".service")
	switch t {
	case "firewalld", "ufw", "nftables", "iptables", "ip6tables", "mpssvc", "pf", "netfilter-persistent":
		return true
	}
	return false
}

func isLoggingService(t string) bool {
	t = strings.TrimSuffix(strings.ToLower(baseName(t)), ".service")
	switch t {
	case "rsyslog", "syslog", "syslog-ng", "systemd-journald", "journald", "eventlog", "com.apple.syslogd", "syslogd":
		return true
	}
	return false
}

func isMACService(t string) bool {
	t = strings.TrimSuffix(strings.ToLower(baseName(t)), ".service")
	return t == "apparmor" || t == "selinux"
}

// stopTool records the facts for "this service/process/unit is being
// stopped, killed, disabled or unloaded".
func (a *analyzer) stopTool(token string) {
	if tool, ok := securityTool(token); ok {
		a.evasion("stop_security_tool")
		if isAuditTool(tool) {
			a.evasion("audit_disable")
		}
		if isDefenderTool(tool) {
			a.evasion("defender_tamper")
		}
		return
	}
	switch {
	case isFirewallService(token):
		a.evasion("firewall_disable")
	case isLoggingService(token):
		a.evasion("audit_disable")
	case isMACService(token):
		a.evasion("selinux_disable")
	}
}
