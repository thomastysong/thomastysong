package features

import (
	"net/netip"
	"strings"

	"github.com/thomastysong/spoor/internal/classify"
)

const maxURLScan = 8 << 10

// maxNetURLs bounds the URLs the network pass examines: the first and last
// half of them, the rest marking the network features incomplete.
const maxNetURLs = 4 * maxList

func (c *computer) network() {
	var hosts, urlSet uniqList
	if t := c.e.Target; t != nil {
		urlSet.add(t.URL)
		hosts.add(normHost(t.Host))
		for _, h := range t.Hosts {
			hosts.add(normHost(h))
		}
	}
	urlSet.addAll(c.urls)
	for _, h := range c.hosts {
		hosts.add(normHost(h))
	}
	urls, urlsCut := headTailCut(urlSet.list, maxNetURLs)
	var schemes uniqList
	hasSecret := false
	queryLen := 0
	for _, u := range urls {
		if len(u) > maxURLScan {
			u = u[:maxURLScan]
		}
		hosts.add(classify.URLHost(u))
		if i := strings.Index(u, "://"); i > 0 && i <= 32 {
			schemes.add(strings.ToLower(u[:i]))
		}
		if q := urlQuery(u); len(q) > queryLen {
			queryLen = len(q)
		}
		if !hasSecret && len(classify.FindSecrets(u)) > 0 {
			hasSecret = true
		}
	}
	if len(hosts.list) == 0 && len(urls) == 0 {
		return
	}
	cut := c.netCut || urlsCut
	kept := c.setList("net.host", hosts.list)
	cut = cut || c.cut["net.host"]
	if cut && kept != nil {
		c.markCut("net.host")
	}
	c.setDerived("net.host_classes", hostClasses(kept), cut)
	c.setDerived("net.scheme", schemes.list, cut)
	isIP := false
	for _, h := range hosts.list {
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
