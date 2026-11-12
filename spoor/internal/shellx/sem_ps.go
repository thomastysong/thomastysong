package shellx

import "strings"

// psAliases maps PowerShell aliases to cmdlets. Aliases that collide with
// native tools (curl, wget, rm, cp, cat, sc ...) are only followed when the
// command line is PowerShell; see psCanonical.
var psAliases = map[string]string{
	"iwr": "invoke-webrequest", "irm": "invoke-restmethod", "iex": "invoke-expression",
	"saps": "start-process", "start": "start-process", "ri": "remove-item", "gc": "get-content",
	"ac": "add-content", "cpi": "copy-item", "mi": "move-item", "ni": "new-item", "sp": "set-itemproperty",
	"gci": "get-childitem", "gp": "get-itemproperty", "spps": "stop-process", "gps": "get-process",
	"sls": "select-string", "icm": "invoke-command", "sal": "set-alias", "nal": "new-alias",
	"gwmi": "get-wmiobject", "gcim": "get-ciminstance", "iwmi": "invoke-wmimethod", "rwmi": "remove-wmiobject",
	"sajb": "start-job", "clhy": "clear-history", "rp": "remove-itemproperty", "spsv": "stop-service",
	"sasv": "start-service", "ipmo": "import-module", "rni": "rename-item", "rcjb": "receive-job",
	"foreach": "foreach-object", "%": "foreach-object", "where": "where-object", "?": "where-object",
	"sv": "set-variable", "write": "write-output", "tee": "tee-object",
	// Colliding names, followed only in the PowerShell dialect.
	"curl": "invoke-webrequest", "wget": "invoke-webrequest", "rm": "remove-item", "rmdir": "remove-item",
	"del": "remove-item", "erase": "remove-item", "rd": "remove-item", "cat": "get-content", "type": "get-content",
	"cp": "copy-item", "copy": "copy-item", "mv": "move-item", "move": "move-item", "ls": "get-childitem",
	"dir": "get-childitem", "kill": "stop-process", "ps": "get-process", "echo": "write-output",
	"set": "set-variable", "history": "get-history", "h": "get-history",
}

// psWebParams are Invoke-WebRequest parameters. In PowerShell "curl" and
// "wget" are either that cmdlet (Windows PowerShell 5.1 aliases) or the real
// programs (PowerShell 7); the argument style tells them apart.
var psWebParams = []string{"uri", "outfile", "usebasicparsing", "method", "body", "headers", "infile", "contenttype",
	"credential", "websession", "sessionvariable", "timeoutsec", "maximumredirection", "useragent", "passthru", "form"}

func psWebStyle(c *simple) bool {
	for _, r := range c.rest() {
		s := r.s
		if len(s) < 4 || s[0] != '-' || s[1] == '-' {
			continue
		}
		name := strings.ToLower(s[1:])
		if i := strings.IndexByte(name, ':'); i > 0 {
			name = name[:i]
		}
		for _, p := range psWebParams {
			if psPrefix(name, p, 3) {
				return true
			}
		}
	}
	return false
}

// pick selects the handler for a command. PowerShell aliases win in the
// PowerShell dialect; full cmdlet names are recognised in any dialect.
func pick(c *simple) handler {
	if c.dialect == PowerShell {
		if (c.name == "curl" || c.name == "wget") && !psWebStyle(c) {
			return handlers[c.name]
		}
		if h, ok := psHandlers[psCanonical(c.name)]; ok {
			return h
		}
	}
	if h, ok := handlers[c.name]; ok {
		return h
	}
	if h, ok := psHandlers[c.name]; ok {
		return h
	}
	switch c.name {
	case "iex", "iwr", "irm":
		return psHandlers[psAliases[c.name]]
	}
	return nil
}

// psCanonical returns the cmdlet a command name refers to, or the name
// itself when it already is one.
func psCanonical(name string) string {
	if c, ok := psAliases[name]; ok {
		return c
	}
	return name
}

type psParam struct {
	name string // lower-case, without the dash
	val  arg
	has  bool
}

type psArgs struct {
	named []psParam
	pos   []arg
}

// psSwitches are parameters that take no value, with the shortest accepted
// abbreviation. Everything else is assumed to take the next word.
var psSwitches = []struct {
	name string
	min  int
}{
	{"recurse", 1}, {"force", 2}, {"usebasicparsing", 4}, {"passthru", 2}, {"wait", 2}, {"nonewwindow", 3},
	{"whatif", 2}, {"verbose", 2}, {"debug", 2}, {"asjob", 2}, {"append", 2}, {"nonewline", 4}, {"noclobber", 3},
	{"raw", 2}, {"hidden", 2}, {"skipcertificatecheck", 4}, {"allowunencryptedauthentication", 6}, {"confirm", 3},
	{"disablekeepalive", 4}, {"usedefaultcredentials", 4}, {"file", 4}, {"directory", 3}, {"asynchronous", 3},
	{"loaduserprofile", 4}, {"usenewenvironment", 4}, {"all", 3}, {"online", 3}, {"norestart", 4}, {"quiet", 2},
	{"simplematch", 3}, {"casesensitive", 2}, {"list", 4}, {"notmatch", 4}, {"allmatches", 4}, {"dynamic", 3},
	{"runelevated", 4}, {"readonly", 3}, {"system", 3}, {"asplaintext", 3}, {"keepalive", 5}, {"resume", 3},
}

func psIsSwitch(name string) bool {
	for _, s := range psSwitches {
		if psPrefix(name, s.name, s.min) {
			return true
		}
	}
	return false
}

func psParse(args []arg) psArgs {
	var p psArgs
	for i := 0; i < len(args); i++ {
		s := args[i].s
		if len(s) >= 2 && s[0] == '-' && !args[i].quoted && (s[1] >= 'a' && s[1] <= 'z' || s[1] >= 'A' && s[1] <= 'Z') {
			name := strings.ToLower(s[1:])
			if j := strings.IndexByte(name, ':'); j > 0 {
				p.named = append(p.named, psParam{name: name[:j], val: arg{s: s[j+2:], dyn: args[i].dyn, t: args[i].t}, has: true})
				continue
			}
			if psIsSwitch(name) || i+1 >= len(args) || (len(args[i+1].s) >= 2 && args[i+1].s[0] == '-' && !args[i+1].quoted && !isDigits(args[i+1].s[1:])) {
				p.named = append(p.named, psParam{name: name})
				continue
			}
			p.named = append(p.named, psParam{name: name, val: args[i+1], has: true})
			i++
			continue
		}
		p.pos = append(p.pos, args[i])
	}
	return p
}

// get returns the value of the parameter whose name abbreviates full.
func (p *psArgs) get(full string, min int) (arg, bool) {
	for i := range p.named {
		if p.named[i].has && psPrefix(p.named[i].name, full, min) {
			return p.named[i].val, true
		}
	}
	return arg{}, false
}

func (p *psArgs) has(full string, min int) bool {
	for i := range p.named {
		if psPrefix(p.named[i].name, full, min) {
			return true
		}
	}
	return false
}

// getOrPos returns a named parameter or, failing that, the idx-th positional.
func (p *psArgs) getOrPos(full string, min, idx int) (arg, bool) {
	if v, ok := p.get(full, min); ok {
		return v, true
	}
	if idx >= 0 && idx < len(p.pos) {
		return p.pos[idx], true
	}
	return arg{}, false
}

func psTrue(v string) bool {
	l := strings.ToLower(strings.TrimSpace(v))
	return l == "$true" || l == "true" || l == "1" || l == "enabled"
}

func psFalse(v string) bool {
	l := strings.ToLower(strings.TrimSpace(v))
	return l == "$false" || l == "false" || l == "0" || l == "disabled"
}

var psHandlers = map[string]handler{}

func init() {
	ps := func(h handler, names ...string) {
		for _, n := range names {
			psHandlers[n] = h
		}
	}
	ps(psWebRequest, "invoke-webrequest", "invoke-restmethod")
	ps(psInvokeExpression, "invoke-expression")
	ps(psStartProcess, "start-process")
	ps(psBits, "start-bitstransfer")
	ps(func(a *analyzer, c *simple, in flow, out *flow) { winDelete(a, c) }, "remove-item")
	ps(psGetContent, "get-content", "import-clixml", "get-filehash", "select-string", "import-csv")
	ps(psSetContent, "set-content", "add-content", "out-file", "export-clixml", "export-csv", "tee-object", "new-item", "clear-content")
	ps(func(a *analyzer, c *simple, in flow, out *flow) { winCopyMove(a, c) }, "copy-item", "move-item")
	ps(psItemProperty, "set-itemproperty", "new-itemproperty", "remove-itemproperty")
	ps(psMpPreference, "set-mppreference", "add-mppreference")
	ps(psStop, "stop-service", "stop-process", "set-service", "remove-service", "suspend-service", "disable-scheduledtask", "unregister-scheduledtask")
	ps(psLogs, "clear-eventlog", "remove-eventlog", "limit-eventlog", "clear-history", "set-psreadlineoption", "clear-recyclebin")
	ps(psSchedTask, "register-scheduledtask", "new-scheduledtask", "new-scheduledtaskaction", "register-scheduledjob", "set-scheduledtask", "new-service")
	ps(psFirewall, "set-netfirewallprofile", "disable-netfirewallrule", "remove-netfirewallrule")
	ps(psChildItem, "get-childitem")
	ps(psRecon, "get-process", "get-computerinfo", "get-localuser", "get-localgroupmember", "get-nettcpconnection", "get-netipaddress", "get-netipconfiguration", "get-service")
	ps(psWmi, "get-wmiobject", "get-ciminstance", "invoke-wmimethod", "invoke-cimmethod", "remove-wmiobject", "remove-ciminstance")
	ps(psMail, "send-mailmessage")
	ps(psInvokeCommand, "invoke-command", "enter-pssession", "new-pssession")
	ps(psDNS, "resolve-dnsname", "test-netconnection", "test-connection")
	ps(psArchive, "compress-archive", "expand-archive")
	ps(psAlias, "set-alias", "new-alias")
	ps(psGroupMember, "add-localgroupmember")
	ps(psUnblock, "unblock-file")
	ps(psUninstall, "uninstall-package", "uninstall-module", "uninstall-windowsfeature", "disable-windowsoptionalfeature", "remove-appxpackage")
	ps(psJob, "start-job", "start-threadjob")
	ps(psCredential, "get-storedcredential", "get-secret", "export-pfxcertificate")
	ps(psWrite, "write-output", "write-host")
	ps(psSetVariable, "set-variable", "new-variable")
	ps(psInstallModule, "install-module", "install-package", "install-script", "save-module")
}

func psWebRequest(a *analyzer, c *simple, in flow, out *flow) {
	p := psParse(c.rest())
	u, ok := p.getOrPos("uri", 1, 0)
	if !ok || u.s == "" {
		return
	}
	a.f.Downloads = true
	a.url(u.s)
	host := urlHost(u.s)
	method, _ := p.get("method", 1)
	m := strings.ToUpper(method.s)
	fileUp, hasData := false, false
	if f, ok := p.get("infile", 3); ok {
		a.read(f.s)
		fileUp = true
	}
	if b, ok := p.get("body", 1); ok {
		hasData = true
		if containsFold(b.s, "get-content") || containsFold(b.s, "readallbytes") || containsFold(b.s, "readalltext") {
			fileUp = true
		}
	}
	if _, ok := p.get("form", 2); ok {
		hasData = true
	}
	if in.piped && (m == "POST" || m == "PUT" || m == "PATCH") {
		hasData = true
	}
	if urlHasSubst(u) {
		hasData = true
	}
	a.netSend([]string{host}, []string{u.s}, fileUp, hasData || m == "POST" || m == "PUT" || m == "PATCH")
	out.static = nil
	if f, ok := p.get("outfile", 1); ok {
		a.write(f.s)
		a.drop(f.s, tDownload)
		out.t = 0
		return
	}
	out.t = tDownload
}

func psInvokeExpression(a *analyzer, c *simple, in flow, out *flow) {
	a.f.Eval = true
	a.obf("eval")
	a.interpreter(c.name)
	p := psParse(c.rest())
	code, ok := p.getOrPos("command", 1, 0)
	var t taint
	if ok {
		// iex "a" + "b" style arguments arrive as several words.
		rest := c.rest()
		t = anyTaint(rest)
		if _, named := p.get("command", 1); !named {
			code = arg{s: joinArgs(p.pos), dyn: anyDyn(p.pos), t: t}
		}
	}
	static, pt, piped := c.input(a, in)
	if piped {
		t |= pt
		if in.piped {
			a.f.PipeToInterpreter = true
		}
	}
	if t&tDownload != 0 {
		a.f.DownloadAndExecute = true
	}
	a.obfTaint(t)
	text := ""
	switch {
	case ok && code.s != "" && !wholeDynamic(code):
		text = code.s
	case static != nil:
		text = *static
	}
	if strings.TrimSpace(text) == "" {
		return
	}
	origin := OriginEval
	if t&tCoded != 0 {
		origin = OriginDecoded
		if !a.addDecoded(text) {
			return
		}
	}
	a.sub(text, PowerShell, origin, c.depth+1, noFlow())
}

// wholeDynamic reports an argument that is nothing but an unresolved
// expression, which is not worth re-parsing.
func wholeDynamic(v arg) bool {
	if !v.dyn {
		return false
	}
	s := strings.TrimSpace(v.s)
	return s == "$(...)" || strings.HasPrefix(s, "$") && !strings.ContainsAny(s, " ;|")
}

func psStartProcess(a *analyzer, c *simple, in flow, out *flow) {
	p := psParse(c.rest())
	if ws, ok := p.get("windowstyle", 1); ok && hasPrefixFold(ws.s, "h") {
		a.f.Background = true
	}
	if v, ok := p.get("verb", 4); ok && strings.EqualFold(v.s, "runas") {
		a.sudo()
	}
	file, ok := p.getOrPos("filepath", 1, 0)
	if !ok || file.s == "" {
		return
	}
	args := []arg{file}
	if al, ok := p.get("argumentlist", 1); ok {
		// One string holding the whole argument line, or a list the lexer
		// already split on commas.
		for _, f := range strings.Fields(al.s) {
			args = append(args, arg{s: f, dyn: al.dyn, t: al.t})
		}
	}
	// Remaining positionals are further argument-list elements.
	if _, named := p.get("filepath", 1); named {
		args = append(args, p.pos...)
	} else if len(p.pos) > 1 {
		args = append(args, p.pos[1:]...)
	}
	a.runInner(c, args, noFlow(), false, false)
}

func psBits(a *analyzer, c *simple, in flow, out *flow) {
	p := psParse(c.rest())
	src, ok := p.getOrPos("source", 1, 0)
	if !ok {
		return
	}
	a.f.Downloads = true
	a.url(src.s)
	if dst, ok := p.getOrPos("destination", 1, 1); ok {
		a.write(dst.s)
		a.drop(dst.s, tDownload)
	} else {
		a.drop(urlBase(src.s), tDownload)
	}
	if p.has("asynchronous", 3) {
		a.f.Background = true
	}
}

func psGetContent(a *analyzer, c *simple, in flow, out *flow) {
	p := psParse(c.rest())
	out.static, out.t = nil, 0
	idx := 0
	if c.name == "select-string" || psCanonical(c.name) == "select-string" {
		// Select-String -Pattern P -Path F
		if pat, ok := p.getOrPos("pattern", 2, 0); ok && secretPattern(pat.s) {
			a.recon("find_secrets")
		}
		idx = 1
	}
	if f, ok := p.getOrPos("path", 1, idx); ok {
		a.read(f.s)
		if t, ok := a.droppedTaint(f.s); ok {
			out.t |= t
		}
	}
	if f, ok := p.get("literalpath", 1); ok {
		a.read(f.s)
	}
}

func psSetContent(a *analyzer, c *simple, in flow, out *flow) {
	p := psParse(c.rest())
	name := psCanonical(c.name)
	f, ok := p.getOrPos("filepath", 1, 0)
	if v, ok2 := p.get("path", 1); ok2 {
		f, ok = v, true
	}
	if v, ok2 := p.get("literalpath", 1); ok2 {
		f, ok = v, true
	}
	if !ok || f.s == "" {
		return
	}
	text := ""
	if v, ok := p.getOrPos("value", 1, 1); ok {
		text = v.s
	} else if st, _, has := c.input(a, in); has && st != nil {
		text = *st
	}
	if strings.HasPrefix(winKey(f.s), "hk") && strings.Contains(f.s, "\\") {
		a.regFacts(f.s, "", text, true, c.depth)
		return
	}
	switch name {
	case "add-content":
		a.useText(f.s, mAppend, text)
	case "out-file", "tee-object":
		if p.has("append", 2) {
			a.useText(f.s, mAppend, text)
		} else {
			a.useText(f.s, mWrite, text)
		}
	case "clear-content":
		a.write(f.s)
		a.destructive("truncate_file")
	case "new-item":
		if p.has("force", 2) || text != "" {
			a.useText(f.s, mWrite, text)
		} else {
			a.attr(f.s)
		}
	default:
		a.useText(f.s, mWrite, text)
	}
	if in.t&(tDownload|tCoded) != 0 && in.piped {
		a.drop(f.s, in.t)
	}
	if name != "tee-object" {
		out.static, out.t = nil, 0
	}
}

func psItemProperty(a *analyzer, c *simple, in flow, out *flow) {
	p := psParse(c.rest())
	path, ok := p.getOrPos("path", 1, 0)
	if !ok {
		if v, ok2 := p.get("literalpath", 1); ok2 {
			path, ok = v, true
		}
	}
	if !ok {
		return
	}
	name, _ := p.getOrPos("name", 1, 1)
	val, _ := p.getOrPos("value", 1, 2)
	write := psCanonical(c.name) != "remove-itemproperty"
	if strings.HasPrefix(winKey(path.s), "hk") {
		a.regFacts(path.s, name.s, val.s, write, c.depth)
		return
	}
	a.attr(path.s)
}

func psMpPreference(a *analyzer, c *simple, in flow, out *flow) {
	p := psParse(c.rest())
	for _, n := range p.named {
		switch {
		case strings.HasPrefix(n.name, "disable") && (!n.has || psTrue(n.val.s)):
			a.evasion("defender_tamper")
		case strings.HasPrefix(n.name, "exclusion"):
			a.evasion("defender_tamper")
		case strings.HasPrefix(n.name, "enablecontrolledfolderaccess") || strings.HasPrefix(n.name, "puaprotection") || strings.HasPrefix(n.name, "mapsreporting") || strings.HasPrefix(n.name, "submitsamplesconsent"):
			if n.has && psFalse(n.val.s) {
				a.evasion("defender_tamper")
			}
		case strings.HasSuffix(n.name, "defaultaction") && n.has && (strings.EqualFold(n.val.s, "allow") || n.val.s == "6" || strings.EqualFold(n.val.s, "noaction") || n.val.s == "9"):
			a.evasion("defender_tamper")
		}
	}
}

func psStop(a *analyzer, c *simple, in flow, out *flow) {
	p := psParse(c.rest())
	name := psCanonical(c.name)
	var targets []arg
	if v, ok := p.get("name", 1); ok {
		targets = append(targets, v)
	}
	if v, ok := p.get("displayname", 1); ok {
		targets = append(targets, v)
	}
	if v, ok := p.get("processname", 2); ok {
		targets = append(targets, v)
	}
	if v, ok := p.get("taskname", 5); ok {
		targets = append(targets, v)
	}
	targets = append(targets, p.pos...)
	if name == "set-service" {
		st, _ := p.get("startuptype", 6)
		status, _ := p.get("status", 3)
		if !strings.EqualFold(st.s, "disabled") && !strings.EqualFold(status.s, "stopped") {
			return
		}
	}
	for _, t := range targets {
		a.stopTool(t.s)
	}
}

func psLogs(a *analyzer, c *simple, in flow, out *flow) {
	switch psCanonical(c.name) {
	case "clear-eventlog", "remove-eventlog":
		a.evasion("log_clear")
	case "limit-eventlog":
		a.evasion("audit_disable")
	case "clear-history":
		a.evasion("history_clear")
	case "set-psreadlineoption":
		p := psParse(c.rest())
		if v, ok := p.get("historysavestyle", 8); ok && strings.EqualFold(v.s, "savenothing") {
			a.evasion("history_clear")
		}
	}
}

func psSchedTask(a *analyzer, c *simple, in flow, out *flow) {
	p := psParse(c.rest())
	switch psCanonical(c.name) {
	case "new-service":
		// Service-manager persistence; see the package doc for "systemd".
		a.persist("systemd")
		if v, ok := p.get("binarypathname", 1); ok {
			a.sub(v.s, Cmd, OriginWrapper, c.depth+1, noFlow())
		}
	case "new-scheduledtaskaction":
		exe, ok := p.get("execute", 1)
		if !ok {
			return
		}
		args := []arg{exe}
		if al, ok := p.get("argument", 1); ok {
			for _, f := range strings.Fields(al.s) {
				args = append(args, arg{s: f, dyn: al.dyn})
			}
		}
		a.persist("scheduled_task")
		a.runInner(c, args, noFlow(), false, false)
	default:
		a.persist("scheduled_task")
	}
}

func psFirewall(a *analyzer, c *simple, in flow, out *flow) {
	p := psParse(c.rest())
	switch psCanonical(c.name) {
	case "set-netfirewallprofile":
		if v, ok := p.get("enabled", 1); ok && psFalse(v.s) {
			a.evasion("firewall_disable")
		}
	default:
		a.evasion("firewall_disable")
	}
}

func psChildItem(a *analyzer, c *simple, in flow, out *flow) {
	p := psParse(c.rest())
	if path, ok := p.getOrPos("path", 1, 0); ok && hasPrefixFold(path.s, "env:") {
		a.recon("env")
		a.cred("env_dump")
	}
	if p.has("recurse", 1) {
		for _, key := range []string{"include", "filter"} {
			if v, ok := p.get(key, 1); ok && secretPattern(v.s) {
				a.recon("find_secrets")
			}
		}
		if len(p.pos) > 1 && secretPattern(p.pos[1].s) {
			a.recon("find_secrets")
		}
	}
}

func psRecon(a *analyzer, c *simple, in flow, out *flow) {
	switch psCanonical(c.name) {
	case "get-process", "get-service":
		a.recon("ps")
	case "get-computerinfo":
		a.recon("uname")
	case "get-localuser", "get-localgroupmember":
		a.recon("id")
	case "get-nettcpconnection":
		a.recon("netstat")
	case "get-netipaddress", "get-netipconfiguration":
		a.recon("ifconfig")
	}
}

func psWmi(a *analyzer, c *simple, in flow, out *flow) {
	all := strings.ToLower(joinArgs(c.rest()))
	name := psCanonical(c.name)
	if strings.Contains(all, "win32_shadowcopy") {
		a.shadowSeen = true
	}
	if (name == "remove-wmiobject" || name == "remove-ciminstance") && a.shadowSeen {
		a.destructive("shadow_copy_delete")
	}
	if (name == "invoke-wmimethod" || name == "invoke-cimmethod") && strings.Contains(all, "win32_process") && strings.Contains(all, "create") {
		p := psParse(c.rest())
		if v, ok := p.get("argumentlist", 1); ok {
			a.sub(v.s, detectWinDialect(v.s), OriginWrapper, c.depth+1, noFlow())
		}
	}
	p := psParse(c.rest())
	if v, ok := p.get("computername", 2); ok {
		a.host(v.s)
	}
	switch {
	case strings.Contains(all, "win32_operatingsystem"), strings.Contains(all, "win32_computersystem"), strings.Contains(all, "win32_bios"):
		a.recon("uname")
	case strings.Contains(all, "win32_process") && name == "get-wmiobject", strings.Contains(all, "win32_process") && name == "get-ciminstance":
		a.recon("ps")
	case strings.Contains(all, "win32_useraccount"), strings.Contains(all, "win32_group"):
		a.recon("id")
	case strings.Contains(all, "antivirusproduct"):
		a.recon("ps")
	}
}

func psMail(a *analyzer, c *simple, in flow, out *flow) {
	a.exfil("email_send")
	p := psParse(c.rest())
	if v, ok := p.get("attachments", 1); ok {
		a.read(v.s)
	}
	if v, ok := p.get("smtpserver", 1); ok {
		a.host(v.s)
	}
}

func psInvokeCommand(a *analyzer, c *simple, in flow, out *flow) {
	p := psParse(c.rest())
	if v, ok := p.get("computername", 2); ok {
		for _, h := range strings.Split(v.s, ",") {
			a.host(h)
		}
	}
	if v, ok := p.get("filepath", 2); ok {
		a.ranFile(v.s)
	}
}

func psDNS(a *analyzer, c *simple, in flow, out *flow) {
	p := psParse(c.rest())
	name, ok := p.getOrPos("name", 1, 0)
	if !ok {
		name, ok = p.get("computername", 1)
	}
	if !ok {
		return
	}
	if psCanonical(c.name) == "resolve-dnsname" && dnsExfilName(name) {
		a.exfil("dns_tunnel")
	}
	a.host(name.s)
}

func psArchive(a *analyzer, c *simple, in flow, out *flow) {
	p := psParse(c.rest())
	if src, ok := p.getOrPos("path", 1, 0); ok {
		a.read(src.s)
		if psCanonical(c.name) == "expand-archive" {
			a.ranArchive(src.s)
		}
	}
	if dst, ok := p.getOrPos("destinationpath", 1, 1); ok {
		a.write(dst.s)
	}
}

// psAlias records Set-Alias so that "sal x iex; x (...)" resolves.
func psAlias(a *analyzer, c *simple, in flow, out *flow) {
	p := psParse(c.rest())
	name, ok1 := p.getOrPos("name", 1, 0)
	val, ok2 := p.getOrPos("value", 1, 1)
	if ok1 && ok2 && name.s != "" && val.s != "" {
		a.setVar("psalias:"+strings.ToLower(name.s), value{s: val.s, static: true})
	}
}

func psGroupMember(a *analyzer, c *simple, in flow, out *flow) {
	all := strings.ToLower(joinArgs(c.rest()))
	if strings.Contains(all, "administrators") || strings.Contains(all, "remote desktop users") {
		a.priv("sudoers_edit")
	}
}

// psUnblock: removing the Mark-of-the-Web is the Windows counterpart of
// stripping the macOS quarantine attribute.
func psUnblock(a *analyzer, c *simple, in flow, out *flow) {
	a.evasion("disable_gatekeeper")
	p := psParse(c.rest())
	if f, ok := p.getOrPos("path", 1, 0); ok {
		a.attr(f.s)
		a.ranFile(f.s)
	}
}

func psUninstall(a *analyzer, c *simple, in flow, out *flow) {
	p := psParse(c.rest())
	for _, n := range p.named {
		if n.has {
			a.uninstalled(n.val.s)
			if containsFold(n.val.s, "defender") {
				a.evasion("defender_tamper")
			}
		}
	}
	for _, v := range p.pos {
		a.uninstalled(v.s)
		if containsFold(v.s, "defender") {
			a.evasion("defender_tamper")
		}
	}
}

func psJob(a *analyzer, c *simple, in flow, out *flow) {
	a.f.Background = true
}

func psCredential(a *analyzer, c *simple, in flow, out *flow) {
	a.cred("keychain_dump")
}

func psWrite(a *analyzer, c *simple, in flow, out *flow) {
	args := c.rest()
	out.t = anyTaint(args)
	out.static = nil
	for i := range args {
		if args[i].dyn {
			if secretVarRef(args[i].s) {
				a.cred("token_print")
			}
			return
		}
	}
	s := joinArgs(args) + "\n"
	out.static = &s
}

func psSetVariable(a *analyzer, c *simple, in flow, out *flow) {
	p := psParse(c.rest())
	name, ok1 := p.getOrPos("name", 1, 0)
	val, ok2 := p.getOrPos("value", 1, 1)
	if ok1 && name.s != "" {
		a.envAssign(name.s)
		if ok2 {
			a.setVar("ps$"+strings.ToLower(name.s), value{s: val.s, static: !val.dyn, t: val.t})
		}
	}
}

func psInstallModule(a *analyzer, c *simple, in flow, out *flow) {
	// PowerShell Gallery installs have no Manager vocabulary entry; the
	// repository URL, when given, is still recorded.
	p := psParse(c.rest())
	if v, ok := p.get("repository", 3); ok && strings.Contains(v.s, "://") {
		a.url(v.s)
	}
	if v, ok := p.get("source", 2); ok && strings.Contains(v.s, "://") {
		a.url(v.s)
	}
}
