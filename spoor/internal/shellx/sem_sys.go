package shellx

import "strings"

func init() {
	register(hSystemctl, "systemctl")
	register(hService, "service", "rc-service", "initctl", "sv")
	register(hLaunchctl, "launchctl")
	register(hKill, "kill", "pkill", "killall", "skill")
	register(hCrontab, "crontab")
	register(hAt, "at", "batch")
	register(hSpctl, "spctl")
	register(hCsrutil, "csrutil")
	register(hXattr, "xattr")
	register(hDefaults, "defaults")
	register(hSetenforce, "setenforce", "aa-disable", "aa-teardown", "aa-complain", "apparmor_parser")
	register(hAudit, "auditctl", "audit")
	register(hFirewall, "ufw", "iptables", "ip6tables", "nft", "pfctl", "firewall-cmd", "socketfilterfw")
	register(hHistory, "history", "unset", "set")
	register(hExport, "export", "declare", "typeset", "readonly", "local")
	register(hRecon, "whoami", "id", "uname", "hostname", "ifconfig", "ip", "netstat", "ss", "ps", "printenv",
		"sw_vers", "lsb_release", "hostnamectl", "groups", "lsof", "arp", "route", "top", "pstree", "w", "who", "last")
	register(hEnvDump, "env")
	register(hSecurity, "security")
	register(hKeyring, "secret-tool", "keyring", "kwallet-query")
	register(hUserMgmt, "usermod", "gpasswd", "adduser", "useradd", "dseditgroup", "visudo", "passwd", "chpasswd")
	register(hPkgRemove, "dpkg", "rpm")
	register(hJournal, "journalctl", "log")
	register(hRead, "read", "mapfile", "readarray")
	register(hNohupLike, "disown", "screen", "tmux")
	register(hSshKeys, "ssh-copy-id", "ssh-add", "ssh-keygen")
	register(hUpdateRC, "update-rc.d", "chkconfig", "systemd-run")
	register(hInsmod, "insmod", "modprobe", "kextload", "kmutil")
	register(hOsqueryctl, "osqueryctl", "falconctl", "sentinelctl", "mdatp", "santactl", "fleetctl", "orbit", "spoor", "jamf")
}

func unitArgs(rest []arg) []arg {
	var out []arg
	for _, r := range rest {
		if strings.HasPrefix(r.s, "-") {
			continue
		}
		out = append(out, r)
	}
	return out
}

func hSystemctl(a *analyzer, c *simple, in flow, out *flow) {
	pos := unitArgs(c.rest())
	if len(pos) == 0 {
		return
	}
	verb := strings.ToLower(pos[0].s)
	units := pos[1:]
	switch verb {
	case "stop", "disable", "mask", "kill":
		for _, u := range units {
			a.stopTool(u.s)
		}
	case "enable", "reenable", "preset", "link", "add-wants", "add-requires":
		a.persist("systemd")
	case "edit", "set-property":
		a.persist("systemd")
	}
}

func hService(a *analyzer, c *simple, in flow, out *flow) {
	pos := unitArgs(c.rest())
	if len(pos) < 2 {
		return
	}
	name, verb := pos[0].s, strings.ToLower(pos[1].s)
	if c.name == "initctl" || c.name == "sv" {
		name, verb = pos[1].s, strings.ToLower(pos[0].s)
	}
	if verb == "stop" || verb == "disable" || verb == "kill" || verb == "down" || verb == "force-stop" {
		a.stopTool(name)
	}
}

func hLaunchctl(a *analyzer, c *simple, in flow, out *flow) {
	pos := unitArgs(c.rest())
	if len(pos) == 0 {
		return
	}
	verb := strings.ToLower(pos[0].s)
	switch verb {
	case "load", "bootstrap", "enable", "submit", "kickstart":
		a.persist("launchd")
		for _, p := range pos[1:] {
			if strings.HasSuffix(strings.ToLower(p.s), ".plist") {
				a.read(p.s)
			}
		}
	case "unload", "bootout", "remove", "disable", "stop", "kill":
		for _, p := range pos[1:] {
			a.stopTool(p.s)
			// "system/com.crowdstrike.falcond" style service targets.
			if i := strings.LastIndexByte(p.s, '/'); i >= 0 {
				a.stopTool(p.s[i+1:])
			}
			if strings.Contains(strings.ToLower(p.s), "com.apple.auditd") {
				a.evasion("audit_disable")
			}
		}
	}
}

func hKill(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	for i := 0; i < len(rest); i++ {
		s := rest[i].s
		if strings.HasPrefix(s, "-") {
			// pkill/killall value flags.
			if c.name != "kill" && (s == "-u" || s == "-U" || s == "-g" || s == "-G" || s == "-P" || s == "-t" || s == "-s" || s == "--signal") {
				i++
			}
			if c.name == "kill" && (s == "-s" || s == "-n") {
				i++
			}
			continue
		}
		if c.name == "kill" {
			// kill takes PIDs; the victim's name only shows up in a
			// pidof/pgrep lookup earlier on the line.
			continue
		}
		a.stopTool(s)
	}
	if c.name == "kill" {
		for _, name := range a.pendingKill {
			a.stopTool(name)
		}
		a.pendingKill = nil
	}
}

// hPidLookup handles pidof/pgrep. Looking up a security tool's PID is
// harmless on its own, so the name is only remembered; a later kill on the
// same line ("kill $(pidof osqueryd)", "pgrep orbit | xargs kill") turns it
// into stop_security_tool.
func hPidLookup(a *analyzer, c *simple, in flow, out *flow) {
	for _, p := range c.positionals() {
		if _, ok := securityTool(p.s); ok && len(a.pendingKill) < 16 {
			a.pendingKill = append(a.pendingKill, p.s)
		}
	}
}

func init() {
	register(hPidLookup, "pidof", "pgrep")
}

func hCrontab(a *analyzer, c *simple, in flow, out *flow) {
	o := parseOpts(c.rest(), &optSpec{short: "us"})
	switch {
	case o.has("-l"):
		// Listing is not a change; but "crontab -l | ... | crontab -" is,
		// and that second crontab is handled when it is reached.
	case o.has("-r"):
		a.del("crontab")
	case o.has("-e"):
		a.persist("cron")
	default:
		// crontab FILE or crontab - installs a table.
		if len(o.pos) > 0 || in.piped || c.stdin != nil || c.hasIn {
			a.persist("cron")
			for _, p := range o.pos {
				if p.s != "-" {
					a.read(p.s)
				}
			}
			if static, _, has := c.input(a, in); has && static != nil {
				a.cronBody(*static, c.depth)
			}
		}
	}
}

// cronBody analyses the command column of crontab lines.
func (a *analyzer) cronBody(body string, depth int) {
	n := 0
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		var cmd string
		switch {
		case strings.HasPrefix(line, "@") && len(f) >= 2:
			cmd = strings.TrimSpace(line[len(f[0]):])
		case len(f) >= 6:
			// Five schedule fields, then the command.
			idx := 0
			for k := 0; k < 5; k++ {
				idx += strings.Index(line[idx:], f[k]) + len(f[k])
			}
			cmd = strings.TrimSpace(line[idx:])
		default:
			continue
		}
		if cmd != "" && n < 8 {
			n++
			a.sub(cmd, Posix, OriginInlinePrefix+"crontab", depth+1, noFlow())
		}
	}
}

func hAt(a *analyzer, c *simple, in flow, out *flow) {
	if c.dialect != Posix {
		// Windows at.exe is the legacy task scheduler.
		a.persist("scheduled_task")
		return
	}
	o := parseOpts(c.rest(), &optSpec{short: "fqt"})
	if o.has("-l", "-r", "-d", "-c") {
		return
	}
	if len(o.pos) == 0 && !o.has("-f", "-t") && c.name == "at" {
		return
	}
	a.persist("at_job")
	if f, ok := o.get("-f"); ok {
		a.read(f.s)
		a.ranFile(f.s)
	}
	if static, t, has := c.input(a, in); has && static != nil {
		a.inline("sh", *static)
		origin := OriginInlinePrefix + c.name
		if t&tCoded != 0 {
			origin = OriginDecoded
		}
		a.sub(*static, Posix, origin, c.depth+1, noFlow())
	}
}

func hSpctl(a *analyzer, c *simple, in flow, out *flow) {
	if c.has("--master-disable", "--global-disable", "--disable") {
		a.evasion("disable_gatekeeper")
	}
	if c.has("--add") && c.has("--label") {
		a.evasion("disable_gatekeeper")
	}
}

func hCsrutil(a *analyzer, c *simple, in flow, out *flow) {
	if containsArgFold(c.rest(), "disable") {
		a.evasion("disable_sip")
	}
}

func hXattr(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	clearAll := c.hasShort('c')
	del := c.hasShort('d')
	quarantine := containsArgFold(rest, "com.apple.quarantine")
	if clearAll || del && quarantine {
		// Removing the quarantine attribute skips Gatekeeper's first-run check.
		a.evasion("disable_gatekeeper")
		for _, p := range c.positionals() {
			if !strings.HasPrefix(p.s, "com.apple.") {
				a.attr(p.s)
				a.ranFile(p.s)
			}
		}
	}
}

func hDefaults(a *analyzer, c *simple, in flow, out *flow) {
	pos := c.positionals()
	if len(pos) < 2 {
		return
	}
	verb := strings.ToLower(pos[0].s)
	domain := strings.ToLower(pos[1].s)
	all := strings.ToLower(joinArgs(c.rest()))
	if verb != "write" && verb != "delete" && verb != "import" {
		return
	}
	switch {
	case strings.Contains(domain, "com.apple.launchservices") && strings.Contains(all, "lsquarantine"):
		a.evasion("disable_gatekeeper")
	case strings.Contains(domain, "com.apple.alf") && strings.Contains(all, "globalstate"):
		a.evasion("firewall_disable")
	case strings.Contains(domain, "loginwindow") && (strings.Contains(all, "loginhook") || strings.Contains(all, "autolaunchedapplicationdictionary")):
		a.persist("login_item")
	case strings.Contains(domain, "com.apple.loginitems"):
		a.persist("login_item")
	}
	// Managed-preference domains of agents (Claude Code, Codex, Copilot).
	if isAgentHookPath(domain) {
		a.evasion("agent_hook_tamper")
	}
	if isSensorPath(domain) {
		a.evasion("sensor_tamper")
	}
}

func hSetenforce(a *analyzer, c *simple, in flow, out *flow) {
	switch c.name {
	case "setenforce":
		for _, p := range c.positionals() {
			if p.s == "0" || strings.EqualFold(p.s, "permissive") {
				a.evasion("selinux_disable")
			}
		}
	case "apparmor_parser":
		if c.hasShort('R', "--remove") {
			a.evasion("selinux_disable")
		}
	case "aa-complain":
		a.evasion("selinux_disable")
	default:
		a.evasion("selinux_disable")
	}
}

func hAudit(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	if c.name == "audit" {
		// macOS: audit -t terminates auditing.
		if c.hasShort('t') {
			a.evasion("audit_disable")
		}
		return
	}
	for i, r := range rest {
		switch r.s {
		case "-e":
			if i+1 < len(rest) && rest[i+1].s == "0" {
				a.evasion("audit_disable")
			}
		case "-D":
			a.evasion("audit_disable")
		}
	}
}

func hFirewall(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	all := strings.ToLower(joinArgs(rest))
	switch c.name {
	case "ufw":
		if len(rest) > 0 && (rest[0].s == "disable" || rest[0].s == "reset") {
			a.evasion("firewall_disable")
		}
	case "iptables", "ip6tables":
		if c.has("-F", "--flush", "-X", "--delete-chain") && !c.has("-t") {
			a.evasion("firewall_disable")
		}
		if strings.Contains(all, "-p input accept") || strings.Contains(all, "--policy input accept") {
			a.evasion("firewall_disable")
		}
	case "nft":
		if strings.Contains(all, "flush ruleset") || strings.Contains(all, "delete table") {
			a.evasion("firewall_disable")
		}
	case "pfctl":
		if c.hasShort('d') || c.has("-F") && strings.Contains(all, "all") {
			a.evasion("firewall_disable")
		}
	case "firewall-cmd":
		if strings.Contains(all, "--panic-off") || strings.Contains(all, "--set-default-zone=trusted") {
			a.evasion("firewall_disable")
		}
	case "socketfilterfw":
		if strings.Contains(all, "--setglobalstate off") {
			a.evasion("firewall_disable")
		}
	}
}

func hHistory(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	switch c.name {
	case "history":
		if c.dialect != Posix {
			return
		}
		if c.hasShort('c') || c.hasShort('d') {
			a.evasion("history_clear")
		}
		for i, r := range rest {
			if r.s == "-w" && i+1 < len(rest) && rest[i+1].s == "/dev/null" {
				a.evasion("history_clear")
			}
		}
	case "unset":
		for _, r := range rest {
			if r.s == "HISTFILE" || r.s == "HISTSIZE" || r.s == "HISTFILESIZE" {
				a.evasion("history_clear")
			}
			delete(a.vars, r.s)
		}
	case "set":
		if c.dialect != Posix {
			return // cmd's set and PowerShell's Set-Variable alias are handled by their front ends
		}
		if len(rest) == 0 {
			// Bare "set" prints every variable and function.
			a.cred("env_dump")
			return
		}
		for i, r := range rest {
			if r.s == "+o" && i+1 < len(rest) && rest[i+1].s == "history" {
				a.evasion("history_clear")
			}
		}
	}
}

func hExport(a *analyzer, c *simple, in flow, out *flow) {
	for _, r := range c.rest() {
		if !strings.HasPrefix(r.s, "-") {
			return // names given: an assignment or attribute change, not a dump
		}
	}
	switch c.name {
	case "export":
		a.cred("env_dump") // export, export -p
	case "declare", "typeset":
		if c.hasShort('x') || c.hasShort('p') {
			a.cred("env_dump")
		}
	}
}

func hRecon(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	switch c.name {
	case "whoami", "groups", "w", "who", "last":
		a.recon("whoami")
	case "id":
		a.recon("id")
	case "uname", "sw_vers", "lsb_release", "hostnamectl":
		a.recon("uname")
	case "hostname":
		if len(c.positionals()) == 0 {
			a.recon("hostname")
		}
	case "ifconfig", "arp", "route":
		a.recon("ifconfig")
	case "ip":
		sub, _ := subcommand(rest, &optSpec{short: "nfN", long: longSet("-netns", "-family", "-n")})
		switch sub {
		case "a", "addr", "address", "r", "route", "link", "l", "neigh", "n", "neighbor", "neighbour", "rule", "netns":
			if !containsArgFold(rest, "add") && !containsArgFold(rest, "del") && !containsArgFold(rest, "set") && !containsArgFold(rest, "flush") {
				a.recon("ip")
			}
		}
	case "netstat":
		a.recon("netstat")
	case "ss", "lsof":
		if c.name == "ss" || c.hasShort('i') {
			a.recon("ss")
		}
	case "ps", "top", "pstree":
		a.recon("ps")
		// "ps e" / "ps eww" prints every process's environment.
		for _, r := range rest {
			if !strings.HasPrefix(r.s, "-") && strings.Contains(r.s, "e") && strings.Trim(r.s, "auxwefjlmTH") == "" {
				a.cred("proc_environ_read")
			}
		}
	case "printenv":
		pos := c.positionals()
		if len(pos) == 0 {
			a.recon("env")
			a.cred("env_dump")
			return
		}
		for _, p := range pos {
			if secretName(p.s) {
				a.cred("token_print")
			}
		}
	}
}

// hEnvDump runs for "env" only when it did not act as a wrapper.
func hEnvDump(a *analyzer, c *simple, in flow, out *flow) {
	for _, r := range c.rest() {
		if !strings.HasPrefix(r.s, "-") {
			return
		}
	}
	a.recon("env")
	a.cred("env_dump")
}

func hSecurity(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	if len(rest) == 0 {
		return
	}
	switch strings.ToLower(rest[0].s) {
	case "dump-keychain", "export":
		a.cred("keychain_dump")
	case "find-generic-password", "find-internet-password":
		// -w and -g print the secret; without them only metadata is shown.
		if c.hasShort('w') || c.hasShort('g') {
			a.cred("keychain_dump")
		}
	case "authorizationdb":
		if len(rest) > 1 && strings.EqualFold(rest[1].s, "write") {
			a.sudo()
		}
	}
}

func hKeyring(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	if len(rest) == 0 {
		return
	}
	switch strings.ToLower(rest[0].s) {
	case "lookup", "search", "get", "-r", "--read-password":
		a.cred("keychain_dump")
	}
}

func hUserMgmt(a *analyzer, c *simple, in flow, out *flow) {
	all := strings.ToLower(joinArgs(c.rest()))
	admin := func(s string) bool {
		for _, g := range []string{"sudo", "wheel", "admin", "root", "docker", "adm"} {
			for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ' ' || r == ',' }) {
				if f == g {
					return true
				}
			}
		}
		return false
	}
	switch c.name {
	case "visudo":
		a.priv("sudoers_edit")
	case "usermod":
		if (c.hasShort('G') || c.hasShort('g') || c.has("--groups", "--append")) && admin(all) {
			a.priv("sudoers_edit")
		}
	case "gpasswd":
		if (c.hasShort('a') || c.hasShort('M')) && admin(all) {
			a.priv("sudoers_edit")
		}
	case "adduser", "useradd":
		if admin(all) && len(c.positionals()) >= 1 && (c.name == "adduser" && len(c.positionals()) >= 2 || c.hasShort('G') || c.hasShort('g') || c.hasShort('o')) {
			a.priv("sudoers_edit")
		}
	case "dseditgroup":
		if strings.Contains(all, "edit") && strings.Contains(all, "-a ") && admin(all) {
			a.priv("sudoers_edit")
		}
	}
}

// hPkgRemove notices a security tool being uninstalled with the low-level
// package tools; the high-level managers are handled in install.go.
func hPkgRemove(a *analyzer, c *simple, in flow, out *flow) {
	remove := false
	switch c.name {
	case "dpkg":
		remove = c.hasShort('r', "--remove") || c.hasShort('P', "--purge")
	case "rpm":
		remove = c.hasShort('e', "--erase")
	}
	if !remove {
		return
	}
	for _, p := range c.positionals() {
		a.uninstalled(p.s)
	}
}

// uninstalled records the removal of a package: taking a sensor off the
// machine is tampering with it.
func (a *analyzer) uninstalled(pkg string) {
	if _, ok := securityTool(pkg); ok {
		a.evasion("sensor_tamper")
		a.evasion("stop_security_tool")
	}
}

func hJournal(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	switch c.name {
	case "journalctl":
		for _, r := range rest {
			if strings.HasPrefix(r.s, "--vacuum-") {
				a.evasion("log_clear")
			}
		}
	case "log":
		// macOS: log erase --all
		if len(rest) > 0 && rest[0].s == "erase" {
			a.evasion("log_clear")
		}
	}
}

// hRead marks variables set from input as unknown.
func hRead(a *analyzer, c *simple, in flow, out *flow) {
	if c.dialect != Posix {
		return
	}
	o := parseOpts(c.rest(), &optSpec{short: "adeinNptuCcsO"})
	for _, p := range o.pos {
		if _, _, ok := splitAssign(p.s + "="); ok {
			a.setVar(p.s, value{t: in.t})
		}
	}
}

func hNohupLike(a *analyzer, c *simple, in flow, out *flow) {
	switch c.name {
	case "disown":
		a.f.Background = true
	case "screen":
		for i, r := range c.rest() {
			if strings.HasPrefix(r.s, "-d") && strings.Contains(r.s, "m") || r.s == "-dm" || r.s == "-dmS" {
				a.f.Background = true
				// screen -dmS name cmd args
				rest := c.rest()[i+1:]
				if r.s == "-dmS" || strings.HasSuffix(r.s, "S") {
					if len(rest) > 0 {
						rest = rest[1:]
					}
				}
				if len(rest) > 0 {
					a.runInner(c, rest, noFlow(), false, false)
				}
				return
			}
		}
	case "tmux":
		rest := c.rest()
		if len(rest) == 0 {
			return
		}
		sub := rest[0].s
		if sub == "new-session" || sub == "new" || sub == "new-window" || sub == "neww" || sub == "send-keys" || sub == "send" || sub == "run-shell" || sub == "run" || sub == "split-window" {
			o := parseOpts(rest[1:], &optSpec{short: "sntcxyFfe"})
			if o.has("-d") {
				a.f.Background = true
			}
			if len(o.pos) > 0 {
				// tmux hands the string to a shell.
				cmd := joinArgs(o.pos)
				cmd = strings.TrimSuffix(strings.TrimSuffix(cmd, " Enter"), " C-m")
				a.sub(cmd, Posix, OriginWrapper, c.depth+1, noFlow())
			}
		}
	}
}

func hSshKeys(a *analyzer, c *simple, in flow, out *flow) {
	switch c.name {
	case "ssh-copy-id":
		a.persist("ssh_authorized_keys")
		for _, p := range c.positionals() {
			a.host(sshTarget(p.s))
		}
	case "ssh-keygen":
		o := parseOpts(c.rest(), &optSpec{short: "fbtCNPmOsVnIDlzR"})
		if f, ok := o.get("-f"); ok && o.has("-y", "-e", "-p") {
			a.read(f.s)
		}
	}
}

func hUpdateRC(a *analyzer, c *simple, in flow, out *flow) {
	all := strings.ToLower(joinArgs(c.rest()))
	switch c.name {
	case "update-rc.d":
		if strings.Contains(all, "defaults") || strings.Contains(all, "enable") {
			a.persist("systemd")
		}
		if strings.Contains(all, "remove") || strings.Contains(all, "disable") {
			for _, p := range c.positionals() {
				a.stopTool(p.s)
			}
		}
	case "chkconfig":
		pos := c.positionals()
		if len(pos) >= 2 && pos[len(pos)-1].s == "on" {
			a.persist("systemd")
		}
		if len(pos) >= 2 && pos[len(pos)-1].s == "off" {
			a.stopTool(pos[0].s)
		}
	case "systemd-run":
		if strings.Contains(all, "--on-calendar") || strings.Contains(all, "--on-boot") || strings.Contains(all, "--on-startup") || strings.Contains(all, "--on-active") || strings.Contains(all, "--on-unit-active") {
			a.persist("systemd")
		}
		// The unit runs the trailing command.
		rest := c.rest()
		i := 0
		for i < len(rest) && strings.HasPrefix(rest[i].s, "-") {
			s := rest[i].s
			if !strings.Contains(s, "=") && (s == "-u" || s == "--unit" || s == "-p" || s == "--property" || s == "-E" || s == "--setenv" ||
				s == "--slice" || s == "--uid" || s == "--gid" || s == "-M" || s == "--machine" || s == "-H" || s == "--host" || s == "--description") {
				i++
			}
			i++
		}
		if i < len(rest) {
			a.runInner(c, rest[i:], noFlow(), false, false)
		}
	}
}

func hInsmod(a *analyzer, c *simple, in flow, out *flow) {
	// Loading a kernel module is the far end of privilege; record the file
	// so a downloaded module is linked to its execution.
	for _, p := range c.positionals() {
		a.ranFile(p.s)
	}
}

// hOsqueryctl covers the control CLIs of the security tools themselves.
func hOsqueryctl(a *analyzer, c *simple, in flow, out *flow) {
	all := " " + strings.ToLower(joinArgs(c.rest())) + " "
	switch c.name {
	case "mdatp":
		if strings.Contains(all, "real-time-protection") && strings.Contains(all, "disabled") ||
			strings.Contains(all, " exclusion ") && strings.Contains(all, " add") ||
			strings.Contains(all, "passive-mode") && strings.Contains(all, "enabled") ||
			strings.Contains(all, "tamper-protection") && strings.Contains(all, "disabled") {
			a.evasion("defender_tamper")
		}
	case "falconctl":
		if strings.Contains(all, " -d ") || strings.Contains(all, " unload") || strings.Contains(all, " uninstall") {
			a.evasion("stop_security_tool")
		}
	case "sentinelctl":
		if strings.Contains(all, " unload") || strings.Contains(all, " unprotect") || strings.Contains(all, " uninstall") || strings.Contains(all, " control stop") {
			a.evasion("stop_security_tool")
		}
	case "osqueryctl":
		if strings.Contains(all, " stop ") || strings.Contains(all, " uninstall ") {
			a.evasion("stop_security_tool")
		}
	case "santactl":
		if strings.Contains(all, " rule ") && strings.Contains(all, "--allow") || strings.Contains(all, "--whitelist") {
			a.evasion("sensor_tamper")
		}
	case "spoor", "orbit":
		if strings.Contains(all, " uninstall") || strings.Contains(all, " stop ") || strings.Contains(all, " disable") {
			a.evasion("stop_security_tool")
			a.evasion("sensor_tamper")
		}
	case "jamf":
		if strings.Contains(all, " removeframework") || strings.Contains(all, " removemdmprofile") {
			a.evasion("stop_security_tool")
			a.evasion("sensor_tamper")
		}
	}
}
