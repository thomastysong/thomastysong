package shellx

import "strings"

func init() {
	register(hCurl, "curl")
	register(hWget, "wget", "wget2")
	register(hFetchers, "fetch", "aria2c", "axel", "lwp-download", "lynx", "w3m", "links", "elinks", "tftp", "ftp", "lftp")
	register(hHTTPie, "http", "https", "xh", "curlie")
	register(hNc, "nc", "netcat", "ncat", "nc.traditional", "nc.openbsd")
	register(hSocat, "socat")
	register(hTelnet, "telnet")
	register(hScp, "scp", "sftp", "pscp")
	register(hRsync, "rsync")
	register(hDNS, "dig", "nslookup", "host", "drill", "kdig", "ping", "ping6", "resolvectl")
	register(hDNSTunnel, "iodine", "iodined", "dnscat", "dnscat2", "dns2tcp", "dns2tcpc")
	register(hTunnel, "ngrok", "cloudflared", "tailscale", "chisel", "frpc", "frps", "bore", "lt", "localtunnel", "tor")
	register(hMail, "mail", "mailx", "mutt", "sendmail", "msmtp", "ssmtp", "swaks", "s-nail", "neomutt")
	register(hScanner, "nmap", "masscan", "rustscan", "zmap", "arp-scan", "netdiscover")
}

var curlSpec = &optSpec{
	short: "AbcCdDeEFHKmoPQrtTuUwxXyYz",
	long: longSet("--user-agent", "--cookie", "--cookie-jar", "--continue-at", "--data", "--data-ascii", "--data-binary",
		"--data-raw", "--data-urlencode", "--dump-header", "--referer", "--cert", "--form", "--form-string", "--header",
		"--config", "--max-time", "--output", "--ftp-port", "--quote", "--range", "--telnet-option", "--upload-file",
		"--user", "--proxy-user", "--write-out", "--proxy", "--request", "--speed-time", "--speed-limit", "--time-cond",
		"--url", "--json", "--connect-timeout", "--retry", "--retry-delay", "--retry-max-time", "--cacert", "--capath",
		"--key", "--resolve", "--connect-to", "--unix-socket", "--abstract-unix-socket", "--interface", "--dns-servers",
		"--limit-rate", "--max-filesize", "--max-redirs", "--output-dir", "--proto", "--proto-default", "--proto-redir",
		"--socks5", "--socks5-hostname", "--socks4", "--socks4a", "--preproxy", "--proxy-header", "--mail-from",
		"--mail-rcpt", "--mail-auth", "--oauth2-bearer", "--aws-sigv4", "--ciphers", "--tls-max", "--create-file-mode",
		"--etag-save", "--etag-compare", "--trace", "--trace-ascii", "--stderr", "--netrc-file", "--pinnedpubkey",
		"--local-port", "--keepalive-time", "--expect100-timeout", "--happy-eyeballs-timeout-ms", "--krb", "--libcurl",
		"--login-options", "--noproxy", "--pass", "--pubkey", "--engine", "--delegation", "--doh-url", "--variable",
		"--rate", "--parallel-max", "--request-target", "--sasl-authzid", "--service-name", "--tlspassword", "--tlsuser",
		"--cert-type", "--key-type", "--crlfile", "--curves", "--ftp-account", "--ftp-method", "--hostpubmd5",
		"--hostpubsha256", "--tls13-ciphers", "--proxy-cacert", "--proxy-cert", "--proxy-key", "--upload-flags"),
}

// urlBase returns the file name a URL would be saved as by curl -O / wget.
func urlBase(u string) string {
	if i := strings.IndexAny(u, "?#"); i >= 0 {
		u = u[:i]
	}
	if i := strings.Index(u, "://"); i >= 0 {
		u = u[i+3:]
		j := strings.IndexByte(u, '/')
		if j < 0 {
			return "index.html"
		}
		u = u[j+1:]
	}
	b := baseName(u)
	if b == "" {
		return "index.html"
	}
	return b
}

// urlHasSubst reports a URL built with a command substitution: data is being
// carried out in the request line itself.
func urlHasSubst(p arg) bool {
	return p.dyn && (strings.Contains(p.s, "$(...)") || strings.Contains(p.s, "<(...)"))
}

func hCurl(a *analyzer, c *simple, in flow, out *flow) {
	o := parseOpts(c.rest(), curlSpec)
	var urls []string
	var hosts []string
	dataInURL := false
	addURL := func(p arg) {
		if p.s == "" {
			return
		}
		a.url(p.s)
		urls = append(urls, p.s)
		if h := urlHost(p.s); h != "" {
			hosts = append(hosts, h)
		}
		if urlHasSubst(p) {
			dataInURL = true
		}
		if strings.HasPrefix(strings.ToLower(p.s), "file://") {
			a.read(p.s[len("file://"):])
		}
	}
	for _, p := range o.pos {
		addURL(p)
	}
	for _, p := range o.all("--url") {
		addURL(p)
	}
	if len(urls) == 0 {
		return
	}
	a.f.Downloads = true

	// What leaves with the request.
	fileUp, hasData := false, false
	stdinData := false
	readAt := func(v string) {
		// @file reads a file, @- reads stdin.
		if v == "-" {
			stdinData = true
			return
		}
		a.read(v)
		fileUp = true
	}
	for _, d := range o.all("-d", "--data", "--data-ascii", "--data-binary", "--json") {
		hasData = true
		if v, ok := strings.CutPrefix(d.s, "@"); ok {
			readAt(v)
		}
	}
	for _, d := range o.all("--data-urlencode") {
		hasData = true
		if i := strings.IndexByte(d.s, '@'); i >= 0 && !strings.Contains(d.s[:i], "=") {
			readAt(d.s[i+1:])
		}
	}
	for _, d := range o.all("--data-raw") {
		_ = d
		hasData = true
	}
	for _, d := range o.all("-F", "--form") {
		hasData = true
		if i := strings.IndexByte(d.s, '='); i >= 0 && i+1 < len(d.s) && (d.s[i+1] == '@' || d.s[i+1] == '<') {
			v := d.s[i+2:]
			if j := strings.IndexByte(v, ';'); j >= 0 {
				v = v[:j]
			}
			readAt(v)
		}
	}
	for _, d := range o.all("--form-string") {
		_ = d
		hasData = true
	}
	for _, d := range o.all("-T", "--upload-file") {
		if d.s == "-" || d.s == "." {
			stdinData = true
		} else {
			a.read(d.s)
			fileUp = true
		}
	}
	if stdinData {
		hasData = true
	}
	for _, f := range o.all("-K", "--config", "--cert", "-E", "--key", "--netrc-file", "-b", "--cookie") {
		// -b takes a file name or a literal cookie string.
		if !strings.Contains(f.s, "=") {
			a.read(f.s)
		}
	}
	if o.has("-n", "--netrc", "--netrc-optional") {
		a.read("~/.netrc")
	}
	if dataInURL {
		hasData = true
	}
	if fileUp || hasData {
		a.netSend(hosts, urls, fileUp, hasData)
	} else {
		a.netSend(hosts, urls, false, false)
	}
	for _, u := range urls {
		l := strings.ToLower(u)
		if (strings.HasPrefix(l, "smtp://") || strings.HasPrefix(l, "smtps://")) && (o.has("--mail-rcpt") || fileUp) {
			a.exfil("email_send")
		}
	}
	if s, ok := o.get("--unix-socket"); ok && strings.Contains(s.s, "docker.sock") {
		a.priv("docker_socket_mount")
	}
	for _, p := range o.all("-x", "--proxy", "--socks5", "--socks5-hostname", "--socks4a", "--preproxy") {
		if strings.HasSuffix(p.s, ":9050") || strings.HasSuffix(p.s, ":9150") {
			a.nettool("tor")
		}
	}

	// Where the response goes.
	out.static = nil
	saved := false
	dir := ""
	if d, ok := o.get("--output-dir"); ok {
		dir = strings.TrimRight(d.s, "/") + "/"
	}
	for _, f := range o.all("-o", "--output") {
		if f.s == "-" {
			continue
		}
		saved = true
		a.write(dir + f.s)
		a.drop(dir+f.s, tDownload)
	}
	if o.has("-O", "--remote-name", "--remote-name-all", "-J", "--remote-header-name") {
		saved = true
		for _, u := range urls {
			name := urlBase(u)
			a.write(dir + name)
			a.drop(dir+name, tDownload)
		}
	}
	if saved || o.has("-I", "--head") {
		out.t = 0
		return
	}
	out.t = tDownload
}

var wgetSpec = &optSpec{
	short: "OoaPtTwQUeiBlDARIX",
	long: longSet("--header", "--post-data", "--post-file", "--user", "--password", "--output-document", "--output-file",
		"--append-output", "--directory-prefix", "--tries", "--timeout", "--wait", "--user-agent", "--referer",
		"--load-cookies", "--save-cookies", "--ca-certificate", "--certificate", "--private-key", "--method",
		"--body-data", "--body-file", "--limit-rate", "--bind-address", "--execute", "--input-file", "--base",
		"--level", "--domains", "--accept", "--reject", "--include-directories", "--exclude-directories",
		"--proxy-user", "--proxy-password", "--http-user", "--http-password", "--secure-protocol", "--dns-timeout",
		"--connect-timeout", "--read-timeout", "--waitretry", "--quota", "--cut-dirs", "--progress", "--config",
		"--ftp-user", "--ftp-password", "--warc-file", "--default-page", "--restrict-file-names"),
}

func hWget(a *analyzer, c *simple, in flow, out *flow) {
	o := parseOpts(c.rest(), wgetSpec)
	var urls, hosts []string
	dataInURL := false
	for _, p := range o.pos {
		a.url(p.s)
		urls = append(urls, p.s)
		if h := urlHost(p.s); h != "" {
			hosts = append(hosts, h)
		}
		if urlHasSubst(p) {
			dataInURL = true
		}
	}
	if f, ok := o.get("-i", "--input-file"); ok {
		a.read(f.s)
		a.f.Downloads = true
	}
	if len(urls) == 0 {
		return
	}
	a.f.Downloads = true
	fileUp, hasData := false, dataInURL
	for _, f := range o.all("--post-file", "--body-file") {
		a.read(f.s)
		fileUp = true
	}
	if o.has("--post-data", "--body-data") {
		hasData = true
	}
	a.netSend(hosts, urls, fileUp, hasData)
	for _, f := range o.all("--load-cookies", "--certificate", "--private-key", "--config") {
		a.read(f.s)
	}
	out.static = nil
	if f, ok := o.get("-O", "--output-document"); ok {
		if f.s == "-" || f.s == "/dev/stdout" {
			out.t = tDownload
			return
		}
		a.write(f.s)
		a.drop(f.s, tDownload)
		out.t = 0
		return
	}
	if o.has("--spider") {
		out.t = 0
		return
	}
	dir := ""
	if d, ok := o.get("-P", "--directory-prefix"); ok {
		dir = strings.TrimRight(d.s, "/") + "/"
	}
	for _, u := range urls {
		name := urlBase(u)
		a.write(dir + name)
		a.drop(dir+name, tDownload)
	}
	out.t = 0
}

// hFetchers covers the less common download tools.
func hFetchers(a *analyzer, c *simple, in flow, out *flow) {
	out.static = nil
	pos := c.positionals()
	any := false
	for _, p := range pos {
		if strings.Contains(p.s, "://") || c.name == "tftp" || c.name == "ftp" || c.name == "lftp" {
			if strings.Contains(p.s, "://") {
				a.url(p.s)
			} else {
				a.host(p.s)
			}
			any = true
		}
	}
	if !any {
		return
	}
	a.f.Downloads = true
	switch c.name {
	case "lynx", "w3m", "links", "elinks":
		// -source / -dump write the page to stdout.
		out.t = tDownload
	case "fetch", "aria2c", "axel", "lwp-download":
		o := parseOpts(c.rest(), &optSpec{short: "odn", long: longSet("--out", "--dir", "--output")})
		if f, ok := o.get("-o", "--out", "--output"); ok && f.s != "-" {
			a.write(f.s)
			a.drop(f.s, tDownload)
		} else if ok {
			out.t = tDownload
		} else {
			for _, p := range pos {
				if strings.Contains(p.s, "://") {
					a.drop(urlBase(p.s), tDownload)
					a.write(urlBase(p.s))
				}
			}
		}
	}
}

// hHTTPie covers "http [METHOD] URL [items]" (HTTPie, xh).
func hHTTPie(a *analyzer, c *simple, in flow, out *flow) {
	o := parseOpts(c.rest(), &optSpec{short: "oaAsp", long: longSet("--output", "--auth", "--auth-type", "--session", "--print", "--proxy", "--cert", "--cert-key", "--timeout", "--verify")})
	pos := o.pos
	method := ""
	if len(pos) > 0 {
		switch strings.ToUpper(pos[0].s) {
		case "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS":
			method = strings.ToUpper(pos[0].s)
			pos = pos[1:]
		}
	}
	if len(pos) == 0 {
		return
	}
	u := pos[0].s
	if !strings.Contains(u, "://") {
		// HTTPie defaults the scheme; ":3000/x" means localhost.
		if strings.HasPrefix(u, ":") {
			u = "localhost" + u
		}
	}
	a.url(u)
	a.f.Downloads = true
	host := urlHost(u)
	fileUp, hasData := false, false
	for _, it := range pos[1:] {
		switch {
		case strings.Contains(it.s, "@") && !strings.Contains(it.s, "=="):
			if i := strings.IndexByte(it.s, '@'); i >= 0 && i+1 < len(it.s) {
				a.read(it.s[i+1:])
				fileUp = true
			}
		case strings.Contains(it.s, "=") && !strings.Contains(it.s, "=="):
			hasData = true
		}
	}
	if in.piped || c.hasIn || c.stdin != nil {
		hasData = true
		if c.hasIn {
			fileUp = true
		}
	}
	if method == "POST" || method == "PUT" || method == "PATCH" || fileUp || hasData {
		a.netSend([]string{host}, []string{u}, fileUp, hasData || method != "")
	} else {
		a.netSend([]string{host}, []string{u}, false, false)
	}
	out.static = nil
	if f, ok := o.get("-o", "--output"); ok {
		a.write(f.s)
		a.drop(f.s, tDownload)
		out.t = 0
		return
	}
	if o.has("-d", "--download") {
		a.drop(urlBase(u), tDownload)
		out.t = 0
		return
	}
	out.t = tDownload
}

var ncSpec = &optSpec{short: "ecgGiIMmOopPqsTVwWxX", long: longSet("--exec", "--sh-exec", "--lua-exec", "--source", "--source-port",
	"--proxy", "--proxy-type", "--proxy-auth", "--wait", "--idle-timeout", "--max-conns", "--ssl-cert", "--ssl-key", "--allow", "--deny", "--output", "--hex-dump")}

func hNc(a *analyzer, c *simple, in flow, out *flow) {
	if c.name == "ncat" {
		a.nettool("ncat")
	} else {
		a.nettool("nc")
	}
	o := parseOpts(c.rest(), ncSpec)
	listen := o.has("-l", "--listen")
	var host string
	for _, p := range o.pos {
		if isDigits(p.s) || strings.Contains(p.s, "-") && isDigits(strings.ReplaceAll(p.s, "-", "")) {
			continue // port or port range
		}
		host = cleanHost(p.s)
		a.host(p.s)
		break
	}
	execArg, hasExec := o.get("-e", "-c", "--exec", "--sh-exec")
	if hasExec && execArg.s != "" {
		// nc -e /bin/sh host port: a shell bound to the socket.
		a.sub(execArg.s, Posix, OriginWrapper, c.depth+1, noFlow())
	}
	out.static = nil
	if listen {
		// A listener's output is whatever the peer sends.
		out.t = tDownload
		return
	}
	out.t = 0
	if host == "" || isLoopback(host) {
		return
	}
	sends := in.piped || c.hasIn || c.stdin != nil || hasExec
	if sends {
		a.exfil("netcat_out")
		if isPasteHost(host) {
			a.exfil("paste_post")
		}
	}
	if isSinkHost(host) {
		a.exfil("webhook_post")
	}
	// Reading from a remote socket into a pipe is a download.
	out.t = tDownload
}

func hSocat(a *analyzer, c *simple, in flow, out *flow) {
	a.nettool("socat")
	remote := false
	execs := false
	for _, p := range c.positionals() {
		addr := p.s
		l := strings.ToLower(addr)
		kind := l
		if i := strings.IndexByte(l, ':'); i > 0 {
			kind = l[:i]
		}
		switch kind {
		case "tcp", "tcp4", "tcp6", "tcp-connect", "udp", "udp4", "udp6", "udp-connect", "ssl", "openssl", "openssl-connect", "sctp", "socks4", "socks4a", "proxy":
			parts := strings.Split(addr, ":")
			if len(parts) >= 3 {
				h := cleanHost(parts[1])
				a.host(h)
				if !isLoopback(h) {
					remote = true
				}
			}
		case "exec", "system", "shell":
			execs = true
			if i := strings.IndexByte(addr, ':'); i > 0 {
				cmd := addr[i+1:]
				if j := strings.IndexByte(cmd, ','); j >= 0 {
					cmd = cmd[:j]
				}
				a.sub(strings.Trim(cmd, "'\""), Posix, OriginWrapper, c.depth+1, noFlow())
			}
		case "file", "open", "gopen":
			if i := strings.IndexByte(addr, ':'); i > 0 {
				f := addr[i+1:]
				if j := strings.IndexByte(f, ','); j >= 0 {
					f = f[:j]
				}
				a.read(f)
				execs = true
			}
		}
	}
	if remote && (execs || in.piped || c.hasIn || c.stdin != nil) {
		a.exfil("netcat_out")
	}
}

func hTelnet(a *analyzer, c *simple, in flow, out *flow) {
	pos := c.positionals()
	if len(pos) == 0 {
		return
	}
	a.host(pos[0].s)
	if (in.piped || c.hasIn || c.stdin != nil) && !isLoopback(cleanHost(pos[0].s)) {
		a.exfil("netcat_out")
	}
}

var scpSpec = &optSpec{short: "cFiJloPSDX"}

func hScp(a *analyzer, c *simple, in flow, out *flow) {
	o := parseOpts(c.rest(), scpSpec)
	for _, f := range o.all("-i", "-F") {
		a.read(f.s)
	}
	pos := o.pos
	if c.name == "sftp" {
		if len(pos) > 0 {
			h, ok := remoteSpec(pos[0].s)
			if !ok {
				h = sshTarget(pos[0].s)
			}
			a.host(h)
			// sftp host <<< "put file": batch commands on stdin.
			if static, _, has := c.input(a, in); has && static != nil {
				for _, line := range strings.Split(*static, "\n") {
					f := strings.Fields(line)
					if len(f) >= 2 && (f[0] == "put" || f[0] == "mput") {
						a.read(f[1])
						a.exfil("scp_out")
					}
					if len(f) >= 2 && (f[0] == "get" || f[0] == "mget") {
						a.f.Downloads = true
					}
				}
			}
		}
		return
	}
	if len(pos) < 2 {
		return
	}
	dest := pos[len(pos)-1]
	srcs := pos[:len(pos)-1]
	dh, destRemote := remoteSpec(dest.s)
	if destRemote {
		a.host(dh)
	}
	anyRemoteSrc := false
	for _, s := range srcs {
		if h, ok := remoteSpec(s.s); ok {
			a.host(h)
			anyRemoteSrc = true
			continue
		}
		a.read(s.s)
	}
	if destRemote && !anyRemoteSrc && !isLoopback(dh) {
		a.exfil("scp_out")
	}
	if !destRemote {
		a.write(dest.s)
		if anyRemoteSrc {
			a.f.Downloads = true
			a.drop(dest.s, tDownload)
		}
	}
}

var rsyncSpec = &optSpec{short: "eTBfM", long: longSet("--rsh", "--rsync-path", "--exclude", "--exclude-from", "--include", "--include-from",
	"--files-from", "--temp-dir", "--compare-dest", "--copy-dest", "--link-dest", "--password-file", "--port", "--log-file",
	"--bwlimit", "--max-size", "--min-size", "--timeout", "--chmod", "--chown", "--partial-dir", "--backup-dir", "--filter", "--out-format", "--info", "--debug")}

func hRsync(a *analyzer, c *simple, in flow, out *flow) {
	o := parseOpts(c.rest(), rsyncSpec)
	if e, ok := o.get("-e", "--rsh"); ok {
		// rsync -e 'ssh -o ...' runs that command.
		a.sub(e.s, Posix, OriginWrapper, c.depth+1, noFlow())
	}
	for _, f := range o.all("--password-file", "--files-from", "--exclude-from", "--include-from") {
		a.read(f.s)
	}
	pos := o.pos
	if len(pos) < 2 {
		return
	}
	dest := pos[len(pos)-1]
	dh, destRemote := remoteSpec(dest.s)
	if destRemote {
		a.host(dh)
	}
	anyRemoteSrc := false
	for _, s := range pos[:len(pos)-1] {
		if h, ok := remoteSpec(s.s); ok {
			a.host(h)
			anyRemoteSrc = true
			continue
		}
		a.read(s.s)
	}
	if destRemote && !anyRemoteSrc && !isLoopback(dh) {
		a.exfil("rsync_out")
	}
	if !destRemote {
		a.write(dest.s)
		if anyRemoteSrc {
			a.f.Downloads = true
			a.drop(dest.s, tDownload)
		}
		if o.has("--delete", "--delete-before", "--delete-after", "--delete-during", "--delete-excluded", "--del") {
			// rsync --delete into / or ~ removes whatever the source lacks.
			n := normPath(dest.s)
			if isRootLike(n) {
				a.destructive("rm_recursive_root")
			} else if isHomeRoot(n) {
				a.destructive("rm_recursive_home")
			}
		}
	}
}

// dnsExfilName reports a queried name that carries data: a substitution or
// variable used as a label of a longer name, or a long high-entropy label.
func dnsExfilName(p arg) bool {
	s := p.s
	if p.dyn {
		if strings.Contains(s, "$(...)") {
			return true
		}
		// "$VAR.example.com": variable as a label. A bare "$HOST" is not.
		if i := strings.IndexByte(s, '$'); i >= 0 {
			j := i + 1
			for j < len(s) && isIdentByte(s[j]) {
				j++
			}
			if j < len(s) && s[j] == '.' && strings.Count(s[j:], ".") >= 2 {
				return true
			}
			if i > 0 && s[i-1] == '.' {
				return false
			}
		}
		return false
	}
	for _, label := range strings.Split(s, ".") {
		if len(label) > 30 && labelEntropyHigh(label) {
			return true
		}
	}
	return false
}

// labelEntropyHigh is a cheap stand-in for an entropy estimate: many distinct
// characters and a mix of letters and digits.
func labelEntropyHigh(l string) bool {
	var seen [256]bool
	distinct, digits, letters := 0, 0, 0
	for i := 0; i < len(l); i++ {
		c := l[i]
		if !seen[c] {
			seen[c] = true
			distinct++
		}
		if c >= '0' && c <= '9' {
			digits++
		} else if isAlnum(c) {
			letters++
		}
	}
	return distinct >= 12 && digits >= 3 && letters >= 3
}

func hDNS(a *analyzer, c *simple, in flow, out *flow) {
	if c.dialect != Posix && c.name == "host" {
		return
	}
	for _, p := range c.positionals() {
		s := p.s
		if strings.HasPrefix(s, "+") || strings.HasPrefix(s, "@") {
			if strings.HasPrefix(s, "@") {
				a.host(s[1:])
			}
			continue
		}
		if isDigits(s) || len(s) <= 5 && strings.ToUpper(s) == s && !strings.Contains(s, ".") {
			continue // record type: A, TXT, MX
		}
		if s == "query" {
			continue
		}
		if dnsExfilName(p) {
			a.exfil("dns_tunnel")
		}
		if strings.Contains(s, ".") || p.dyn {
			a.host(s)
		}
	}
}

func hDNSTunnel(a *analyzer, c *simple, in flow, out *flow) {
	a.exfil("dns_tunnel")
	for _, p := range c.positionals() {
		if strings.Contains(p.s, ".") {
			a.host(p.s)
		}
	}
}

func hTunnel(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	sub := ""
	if len(rest) > 0 {
		sub = strings.ToLower(rest[0].s)
	}
	switch c.name {
	case "ngrok":
		if sub != "" && sub != "version" && sub != "help" && sub != "config" && sub != "update" && !strings.HasPrefix(sub, "-") {
			a.nettool("ngrok")
		}
	case "cloudflared":
		if sub == "tunnel" || sub == "access" || sub == "proxy-dns" {
			a.nettool("cloudflared")
		}
	case "tailscale":
		if sub == "funnel" {
			a.nettool("tailscale_funnel")
		}
	case "chisel":
		if sub == "client" || sub == "server" {
			a.nettool("chisel")
		}
	case "frpc", "frps":
		a.nettool("frp")
	case "bore":
		if sub == "local" || sub == "server" {
			a.nettool("bore")
		}
	case "lt", "localtunnel":
		if c.name == "localtunnel" || c.has("--port", "-p") {
			a.nettool("localtunnel")
		}
	case "tor":
		a.nettool("tor")
	}
}

func hMail(a *analyzer, c *simple, in flow, out *flow) {
	rest := c.rest()
	send := false
	for _, r := range rest {
		if strings.Contains(r.s, "@") && !strings.HasPrefix(r.s, "-") {
			send = true
		}
	}
	o := parseOpts(rest, &optSpec{short: "sabcrSAfFiHexto", long: longSet("--subject", "--attach", "--to", "--from", "--server", "--body", "--header", "--data", "--auth-user", "--auth-password")})
	for _, f := range o.all("-a", "-A", "--attach") {
		if !strings.Contains(f.s, ":") {
			a.read(f.s)
		}
		send = true
	}
	if o.has("-t", "--to", "--server") || c.name == "sendmail" && (in.piped || c.hasIn || c.stdin != nil) {
		send = true
	}
	if send {
		a.exfil("email_send")
	}
}

func hScanner(a *analyzer, c *simple, in flow, out *flow) {
	a.recon("nmap")
	for _, p := range c.positionals() {
		if strings.Contains(p.s, ".") && !strings.Contains(p.s, "/") || strings.Count(p.s, ".") == 3 {
			a.host(strings.SplitN(p.s, "/", 2)[0])
		}
	}
}
