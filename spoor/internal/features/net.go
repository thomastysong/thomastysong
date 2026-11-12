package features

import (
	"net/netip"
	"strings"

	"github.com/thomastysong/spoor/internal/classify"
)

const maxURLScan = 8 << 10

func (c *computer) network() {
	var hosts, urls []string
	if t := c.e.Target; t != nil {
		if t.URL != "" {
			uniq(&urls, t.URL)
		}
		uniq(&hosts, normHost(t.Host))
		for _, h := range t.Hosts {
			uniq(&hosts, normHost(h))
		}
	}
	for _, u := range c.urls {
		uniq(&urls, u)
	}
	for _, h := range c.hosts {
		uniq(&hosts, normHost(h))
	}
	var schemes []string
	hasSecret := false
	queryLen := 0
	for _, u := range urls {
		if len(u) > maxURLScan {
			u = u[:maxURLScan]
		}
		uniq(&hosts, classify.URLHost(u))
		if i := strings.Index(u, "://"); i > 0 && i <= 32 {
			uniq(&schemes, strings.ToLower(u[:i]))
		}
		if q := urlQuery(u); len(q) > queryLen {
			queryLen = len(q)
		}
		if !hasSecret && len(classify.FindSecrets(u)) > 0 {
			hasSecret = true
		}
	}
	if len(hosts) == 0 && len(urls) == 0 {
		return
	}
	c.setList("net.host", hosts)
	c.setList("net.host_classes", hostClasses(hosts))
	c.setList("net.scheme", schemes)
	isIP := false
	for _, h := range hosts {
		if isIPHost(h) {
			isIP = true
			break
		}
	}
	c.f["net.is_ip"] = isIP
	c.f["net.url_has_secret"] = hasSecret
	c.f["net.query_len"] = float64(queryLen)
}

func normHost(h string) string {
	h = strings.TrimSpace(strings.ToLower(h))
	h = strings.TrimSuffix(h, ".")
	if len(h) > 255 {
		return ""
	}
	return h
}

// urlQuery returns the query string of u (between '?' and '#').
func urlQuery(u string) string {
	i := strings.IndexByte(u, '?')
	if i < 0 {
		return ""
	}
	q := u[i+1:]
	if j := strings.IndexByte(q, '#'); j >= 0 {
		q = q[:j]
	}
	return q
}

func isIPHost(h string) bool {
	h = strings.Trim(h, "[]")
	if i := strings.IndexByte(h, '%'); i >= 0 {
		h = h[:i]
	}
	if _, err := netip.ParseAddr(h); err == nil {
		return true
	}
	for _, cl := range classify.HostClasses(h) {
		if cl == "raw_ip" {
			return true
		}
	}
	return false
}
