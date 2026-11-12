package shellx

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// urlSchemes are the schemes extracted from arbitrary text. The list is
// closed so that "foo://" noise in arguments does not become a URL.
var urlSchemes = []string{
	"https://", "http://", "ftp://", "ftps://", "sftp://", "scp://", "ssh://", "git://",
	"ws://", "wss://", "smtp://", "smtps://", "tftp://", "ldap://", "ldaps://", "smb://",
	"s3://", "gs://", "rsync://", "telnet://", "gopher://", "dict://", "file://",
	"git+https://", "git+ssh://", "git+http://",
}

// findURLs returns every URL in s. It is a hand scanner rather than a regex
// because it runs on every argument of every command.
func findURLs(s string) []string {
	if !strings.Contains(s, "://") {
		return nil
	}
	var out []string
	for i := 0; i < len(s); {
		j := strings.Index(s[i:], "://")
		if j < 0 {
			break
		}
		j += i
		// Walk back over the scheme.
		st := j
		for st > 0 && (isAlnum(s[st-1]) || s[st-1] == '+' || s[st-1] == '-' || s[st-1] == '.') {
			st--
		}
		scheme := strings.ToLower(s[st : j+3])
		known := false
		for _, k := range urlSchemes {
			if strings.HasSuffix(scheme, k) {
				st = j + 3 - len(k)
				known = true
				break
			}
		}
		end := j + 3
		for end < len(s) && !urlStop(s[end]) {
			end++
		}
		if known && end > j+3 {
			u := strings.TrimRight(s[st:end], ".,;:!?)]}'\"")
			out = append(out, u)
			if len(out) >= 32 {
				break
			}
		}
		i = end
		if i <= j {
			i = j + 3
		}
	}
	return out
}

func urlStop(c byte) bool {
	switch c {
	case ' ', '\t', '\n', '\r', '"', '\'', '<', '>', '`', '|', '\\', '^', '{', '}', '(', ')', ';':
		return true
	}
	return c < 0x20 || c == 0x7f
}

// urlHost extracts the host of a URL or scheme-less host/path reference:
// userinfo stripped, port removed, lower-case, IPv6 brackets removed.
func urlHost(raw string) string {
	s := raw
	if i := strings.Index(s, "://"); i >= 0 {
		if strings.EqualFold(s[:i], "file") {
			return ""
		}
		s = s[i+3:]
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		s = s[i+1:]
	}
	return cleanHost(s)
}

func cleanHost(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "[") {
		if i := strings.IndexByte(s, ']'); i > 0 {
			return strings.ToLower(s[1:i])
		}
		return ""
	}
	// A single colon is host:port; more than one is a bare IPv6 address.
	if strings.Count(s, ":") == 1 {
		s = s[:strings.IndexByte(s, ':')]
	}
	s = strings.ToLower(strings.TrimRight(s, "."))
	if !validHost(s) {
		return ""
	}
	return s
}

// validHost accepts DNS names, IP literals and unresolved "$VAR" hosts. It
// rejects flags, paths and anything with characters a host cannot contain.
func validHost(s string) bool {
	if s == "" || len(s) > 255 || s[0] == '-' || s[0] == '.' {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if isAlnum(c) || c == '.' || c == '-' || c == '_' || c == ':' || c == '$' || c == '%' {
			continue
		}
		return false
	}
	return true
}

// userinfoKind is the marker kind package classify gives credentials in a
// URL's userinfo (classify.KindBasicAuthURL). shellx does not import
// classify; TestUserinfoMarkerMatchesClassify keeps the two in step.
const userinfoKind = "basic_auth_url"

// redactUserinfo replaces URL credentials with a redaction marker. Facts may
// be quoted in detection evidence, and "https://user:token@host" is the most
// common way a secret ends up inside an otherwise harmless fact.
//
// The marker is classify's, byte for byte: "[REDACTED:basic_auth_url:<fp>]"
// with fp the first 8 hex digits of an UNKEYED SHA-256 of the userinfo. That
// fingerprint is an offline guessing oracle for a short password, so it must
// not leave the endpoint as written; using classify's exact shape is what
// makes package privacy rewrite it on the way out (keyed with the tenant
// key, or removed when there is none), exactly as it does for classify's
// own markers. Any other shape would pass through privacy untouched.
func redactUserinfo(u string) string {
	i := strings.Index(u, "://")
	if i < 0 {
		return u
	}
	rest := u[i+3:]
	end := strings.IndexAny(rest, "/?#")
	if end < 0 {
		end = len(rest)
	}
	at := strings.LastIndexByte(rest[:end], '@')
	if at <= 0 {
		return u
	}
	info := rest[:at]
	// "git@" and other bare user names carry no secret.
	if !strings.Contains(info, ":") && len(info) < 20 {
		return u
	}
	sum := sha256.Sum256([]byte(info))
	return u[:i+3] + "[REDACTED:" + userinfoKind + ":" + hex.EncodeToString(sum[:4]) + "]" + rest[at:]
}

func (a *analyzer) url(u string) {
	u = strings.TrimSpace(u)
	if u == "" {
		return
	}
	if len(u) > 2048 {
		u = clip(u, 2048)
	}
	addUniq(&a.f.URLs, redactUserinfo(u))
	a.host(urlHost(u))
}

func (a *analyzer) host(h string) {
	h = cleanHost(h)
	if h == "" {
		return
	}
	addUniq(&a.f.Hosts, h)
}

// scanURLs records every URL found in free text (arguments, inline code).
func (a *analyzer) scanURLs(s string) {
	for _, u := range findURLs(s) {
		a.url(u)
	}
}

// devTCPHost recognises bash's /dev/tcp/host/port and /dev/udp/host/port.
func devTCPHost(p string) (string, bool) {
	var rest string
	switch {
	case strings.HasPrefix(p, "/dev/tcp/"):
		rest = p[len("/dev/tcp/"):]
	case strings.HasPrefix(p, "/dev/udp/"):
		rest = p[len("/dev/udp/"):]
	default:
		return "", false
	}
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	return rest, rest != ""
}

func isLoopback(h string) bool {
	switch h {
	case "localhost", "::1", "0.0.0.0", "ip6-localhost", "host.docker.internal":
		return true
	}
	return strings.HasPrefix(h, "127.") || strings.HasSuffix(h, ".localhost")
}

// allLoopback reports whether every destination is the local machine. Posting
// a file to a dev server on localhost is routine and is not exfiltration.
func allLoopback(hosts []string) bool {
	if len(hosts) == 0 {
		return false
	}
	for _, h := range hosts {
		if !isLoopback(h) {
			return false
		}
	}
	return true
}

func hostIn(h string, list []string) bool {
	for _, d := range list {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

// Paste and one-shot file drop services (threats.md EXFIL_HOSTS plus the
// usual suspects). A data-carrying request to one of them is paste_post.
var pasteHosts = []string{
	"pastebin.com", "paste.ee", "hastebin.com", "dpaste.com", "dpaste.org", "ix.io", "0x0.st",
	"transfer.sh", "termbin.com", "sprunge.us", "paste.rs", "file.io", "rentry.co", "bashupload.com",
	"temp.sh", "catbox.moe", "tmpfiles.org", "clbin.com", "privatebin.net", "paste.debian.net",
	"paste.ubuntu.com", "ghostbin.com", "controlc.com", "pastes.io", "oshi.at", "uguu.se", "p.ip.fi",
	"paste.c-net.org", "gofile.io", "anonfiles.com",
}

// Request-capture services: any request to them leaks whatever is in it.
var sinkHosts = []string{
	"webhook.site", "requestbin.com", "requestbin.net", "pipedream.net", "pipedream.com",
	"interact.sh", "oast.pro", "oast.live", "oast.site", "oast.online", "oast.fun", "oast.me",
	"oastify.com", "burpcollaborator.net", "requestcatcher.com", "beeceptor.com", "hookbin.com",
	"webhook.cool", "smee.io", "canarytokens.com", "ngrok.io", "ngrok-free.app", "ngrok.app",
	"trycloudflare.com", "dnslog.cn", "ceye.io",
}

// Chat and automation webhooks: a sink only when the request carries data.
var chatHookHosts = []string{
	"hooks.slack.com", "discord.com", "discordapp.com", "api.telegram.org", "webhook.office.com",
	"hooks.zapier.com", "maker.ifttt.com", "hook.integromat.com", "ntfy.sh", "api.pushover.net",
}

var metadataHosts = []string{
	"169.254.169.254", "169.254.170.2", "100.100.100.200", "metadata.google.internal",
	"metadata.goog", "fd00:ec2::254", "metadata.azure.internal",
}

func isPasteHost(h string) bool { return hostIn(h, pasteHosts) }
func isSinkHost(h string) bool  { return hostIn(h, sinkHosts) }
func isChatHook(h string) bool  { return hostIn(h, chatHookHosts) }

func isMetadataHost(h string) bool {
	for _, m := range metadataHosts {
		if h == m {
			return true
		}
	}
	return false
}

// netSend classifies a data-carrying request to the given destinations.
// fileUpload distinguishes "a file leaves" from "inline data leaves".
func (a *analyzer) netSend(hosts []string, urls []string, fileUpload, hasData bool) {
	if allLoopback(hosts) {
		return
	}
	if fileUpload {
		a.exfil("http_upload_file")
	} else if hasData {
		a.exfil("http_post_data")
	}
	for _, h := range hosts {
		if isPasteHost(h) && (fileUpload || hasData) {
			a.exfil("paste_post")
		}
		if isSinkHost(h) {
			a.exfil("webhook_post")
		}
		if isChatHook(h) && (fileUpload || hasData || chatSendURL(urls)) {
			a.exfil("webhook_post")
		}
	}
}

// chatSendURL spots bot API calls that send a message with data in the URL
// itself (Telegram sendMessage?text=...).
func chatSendURL(urls []string) bool {
	for _, u := range urls {
		l := strings.ToLower(u)
		if strings.Contains(l, "/sendmessage") || strings.Contains(l, "/senddocument") || strings.Contains(l, "/api/webhooks/") {
			return true
		}
	}
	return false
}

// remoteSpec parses scp/rsync style "[user@]host:path". Windows drive letters
// and URLs are not remote specs.
func remoteSpec(s string) (host string, ok bool) {
	if strings.Contains(s, "://") {
		switch {
		case hasPrefixFold(s, "scp://"), hasPrefixFold(s, "sftp://"), hasPrefixFold(s, "rsync://"), hasPrefixFold(s, "ssh://"):
			h := urlHost(s)
			return h, h != ""
		}
		return "", false
	}
	i := strings.IndexByte(s, ':')
	if i <= 1 {
		// "C:\x" or ":path".
		return "", false
	}
	if strings.ContainsAny(s[:i], "/\\") {
		return "", false
	}
	h := s[:i]
	if at := strings.LastIndexByte(h, '@'); at >= 0 {
		h = h[at+1:]
	}
	h = cleanHost(h)
	return h, h != ""
}

// sshTarget parses "[user@]host" or "ssh://[user@]host[:port]".
func sshTarget(s string) string {
	if strings.Contains(s, "://") {
		return urlHost(s)
	}
	if at := strings.LastIndexByte(s, '@'); at >= 0 {
		s = s[at+1:]
	}
	return cleanHost(s)
}
