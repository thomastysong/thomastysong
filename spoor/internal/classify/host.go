package classify

import (
	"net/netip"
	"strconv"
	"strings"
	"sync"
)

var (
	hostTableOnce sync.Once
	hostSuffix    map[string]hostBits // host and all of its subdomains
)

func hostTable() map[string]hostBits {
	hostTableOnce.Do(func() {
		m := make(map[string]hostBits, 1024)
		add := func(list []string, b hostBits) {
			for _, h := range list {
				m[h] |= b
			}
		}
		add(llmAPIHosts, hbLLM)
		add(pasteHosts, hbPaste)
		add(fileShareHosts, hbFileShare)
		add(tunnelHosts, hbTunnel)
		add(webhookSinkHosts, hbWebhookSink)
		add(chatWebhookHosts, hbChatWebhook)
		add(shortenerHosts, hbShortener)
		add(codeHosts, hbCodeHost)
		add(registryHosts, hbRegistry)
		add(metadataHosts, hbMetadata)
		add(dynDNSHosts, hbDynDNS)
		add(onionGateways, hbOnion)
		add(objectStorageHosts, hbObjectStorage)
		add(mailHosts, hbMail)
		add(freeHostingHosts, hbFreeHosting)
		add(loopbackHosts, hbLoopback)
		hostSuffix = m
	})
	return hostSuffix
}

// HostClasses returns the closed-vocabulary classes of a network host.
//
// The argument may be a bare host, host:port, a bracketed IPv6 literal or a
// whole URL. IPv4 addresses are recognised in every form the C resolver
// accepts (decimal 2852039166, hex 0xa9fea9fe, octal 0251.0376.0251.0376,
// short forms 127.1), IPv4-mapped and NAT64 IPv6 addresses are classified by
// the IPv4 address they carry, and wildcard-DNS names such as
// 169.254.169.254.nip.io are classified by the address they resolve to: these
// are the standard ways to walk a metadata or loopback address past a filter
// that compares strings. Unknown hosts return nil. HostClasses never panics
// and never resolves names.
func HostClasses(host string) (out []string) {
	defer func() {
		if recover() != nil {
			out = nil
		}
	}()
	var h string
	if strings.Contains(host, "/") || strings.Contains(host, "@") {
		h = URLHost(host)
	} else {
		if len(host) > maxURLParse {
			return nil
		}
		h = normalizeHost(host)
	}
	if h == "" {
		return nil
	}
	return hostBitsFor(h).names()
}

func hostBitsFor(h string) hostBits {
	if addr, ok := parseIPLoose(h); ok {
		return hbRawIP | ipBits(addr)
	}
	var b hostBits
	labels := strings.Split(h, ".")
	table := hostTable()
	// Walk suffixes from the full name down to the TLD.
	off := 0
	for i := range labels {
		b |= table[h[off:]]
		off += len(labels[i]) + 1
	}
	n := len(labels)
	tld := labels[n-1]
	if tld == "onion" {
		b |= hbOnion
	}
	if tld == "localhost" {
		b |= hbLoopback // RFC 6761: the whole .localhost zone is loopback
	}
	if n >= 2 && labels[n-2] == "oast" {
		b |= hbWebhookSink // interactsh public servers: oast.pro, oast.live, ...
	}
	if n >= 3 && mailLabels.has(labels[0]) {
		b |= hbMail
	}
	b |= cloudPatternBits(h, labels)
	if b&hbDynDNS != 0 {
		if addr, ok := embeddedIP(h, labels); ok {
			// Classified by what it resolves to, but it is still a name.
			b |= ipBits(addr)
		}
	}
	return b
}

// cloudPatternBits handles provider hostnames whose shape, not a fixed name,
// carries the service: regional and per-tenant endpoints.
func cloudPatternBits(h string, labels []string) hostBits {
	var b hostBits
	switch {
	case strings.HasSuffix(h, ".amazonaws.com") || strings.HasSuffix(h, ".amazonaws.com.cn"):
		for _, l := range labels {
			switch {
			case l == "s3" || strings.HasPrefix(l, "s3-") || strings.HasPrefix(l, "s3express"):
				b |= hbObjectStorage
			case strings.HasPrefix(l, "bedrock"):
				b |= hbLLM
			case l == "email" || strings.HasPrefix(l, "email-smtp"):
				b |= hbMail
			case l == "execute-api" || l == "lambda-url":
				b |= hbFreeHosting
			case l == "ecr" || strings.HasPrefix(l, "codeartifact"):
				b |= hbRegistry
			case strings.HasPrefix(l, "git-codecommit"):
				b |= hbCodeHost
			}
		}
	case strings.HasSuffix(h, ".aliyuncs.com"):
		for _, l := range labels {
			if strings.HasPrefix(l, "oss-") {
				b |= hbObjectStorage
			}
		}
	case strings.HasSuffix(h, ".googleapis.com"):
		// Regional Vertex AI endpoints: us-central1-aiplatform.googleapis.com.
		if strings.HasSuffix(labels[0], "-aiplatform") {
			b |= hbLLM
		}
	}
	return b
}

// metadataIPs are instance metadata and workload credential endpoints. They
// are parsed on first use (metadataAddrs), not by package init.
var metadataIPs = []string{
	"169.254.169.254", // AWS, GCP, Azure, DigitalOcean, OpenStack, Oracle
	"169.254.170.2",   // AWS ECS task credentials
	"169.254.170.23",  // AWS EKS Pod Identity
	"100.100.100.200", // Alibaba Cloud
	"192.0.0.192",     // Oracle Cloud (classic)
	"168.63.129.16",   // Azure WireServer
	"fd00:ec2::254",   // AWS IMDS over IPv6
	"fd00:ec2::23",    // AWS EKS Pod Identity over IPv6
	// UNVERIFIED: GCP documents an IPv6 metadata address for IPv6-only
	// instances; the value is from memory.
	"fd20:ce::254",
}

var (
	metadataOnce sync.Once
	metadataSet  map[netip.Addr]bool
)

func metadataAddrs() map[netip.Addr]bool {
	metadataOnce.Do(func() {
		m := make(map[netip.Addr]bool, len(metadataIPs))
		for _, s := range metadataIPs {
			m[netip.MustParseAddr(s)] = true
		}
		metadataSet = m
	})
	return metadataSet
}

// The special ranges below are tested on the address bytes: a
// netip.MustParsePrefix at package level would run in every process.

// inCGNAT reports 100.64.0.0/10 (carrier-grade NAT, RFC 6598).
func inCGNAT(a netip.Addr) bool {
	b := a.As4()
	return b[0] == 100 && b[1]&0xC0 == 64
}

// inNAT64 reports 64:ff9b::/96 (the well-known NAT64 prefix, RFC 6052).
func inNAT64(a netip.Addr) bool {
	b := a.As16()
	return b[0] == 0 && b[1] == 0x64 && b[2] == 0xff && b[3] == 0x9b &&
		b[4]|b[5]|b[6]|b[7]|b[8]|b[9]|b[10]|b[11] == 0
}

// inThisNet reports 0.0.0.0/8 ("this network", RFC 1122).
func inThisNet(a netip.Addr) bool { return a.As4()[0] == 0 }

// ipBits classifies an address. IPv4-mapped and NAT64 addresses are unwrapped
// first so the embedded IPv4 address decides.
func ipBits(a netip.Addr) hostBits {
	if a.Is4In6() {
		a = a.Unmap()
	} else if a.Is6() && inNAT64(a) {
		raw := a.As16()
		a = netip.AddrFrom4([4]byte{raw[12], raw[13], raw[14], raw[15]})
	}
	var b hostBits
	if metadataAddrs()[a] {
		b |= hbMetadata
	}
	switch {
	case a.IsLoopback(), a.IsUnspecified():
		b |= hbLoopback
	case a.Is4() && inThisNet(a):
		// 0.x.y.z is "this host" to most stacks; Linux routes 0.0.0.0 to
		// loopback, which makes it a classic localhost filter bypass.
		b |= hbLoopback
	case a.IsPrivate(), a.IsLinkLocalUnicast():
		b |= hbPrivateIP
	case a.Is4() && inCGNAT(a):
		b |= hbPrivateIP
	}
	return b
}

// parseIPLoose parses IPv6 literals and every IPv4 spelling inet_aton accepts.
func parseIPLoose(h string) (netip.Addr, bool) {
	if strings.Contains(h, ":") {
		a, err := netip.ParseAddr(h)
		if err != nil {
			return netip.Addr{}, false
		}
		return a.WithZone(""), true
	}
	parts := strings.Split(h, ".")
	if len(parts) > 4 {
		return netip.Addr{}, false
	}
	var vals [4]uint64
	for i, p := range parts {
		v, ok := parseIPPart(p)
		if !ok {
			return netip.Addr{}, false
		}
		vals[i] = v
	}
	n := len(parts)
	// All parts but the last are single bytes; the last fills what remains.
	var ip uint64
	for i := 0; i < n-1; i++ {
		if vals[i] > 0xff {
			return netip.Addr{}, false
		}
		ip |= vals[i] << (24 - 8*uint(i))
	}
	maxLast := uint64(1)<<(8*uint(5-n)) - 1
	if vals[n-1] > maxLast {
		return netip.Addr{}, false
	}
	ip |= vals[n-1]
	return netip.AddrFrom4([4]byte{byte(ip >> 24), byte(ip >> 16), byte(ip >> 8), byte(ip)}), true
}

// parseIPPart parses one inet_aton component: decimal, 0x hex or 0 octal.
func parseIPPart(p string) (uint64, bool) {
	if p == "" || len(p) > 12 {
		return 0, false
	}
	base := 10
	digits := p
	switch {
	case len(p) > 2 && (p[:2] == "0x" || p[:2] == "0X"):
		base, digits = 16, p[2:]
	case len(p) > 1 && p[0] == '0':
		base, digits = 8, p[1:]
	}
	v, err := strconv.ParseUint(digits, base, 64)
	if err != nil || v > 0xffffffff {
		return 0, false
	}
	return v, true
}

// embeddedIP extracts the address a wildcard-DNS name resolves to:
// 10.0.0.1.nip.io, 10-0-0-1.nip.io, app.10.0.0.1.sslip.io, a9fea9fe.nip.io.
func embeddedIP(h string, labels []string) (netip.Addr, bool) {
	var suffix string
	for _, w := range wildcardDNS {
		if strings.HasSuffix(h, "."+w) {
			suffix = w
			break
		}
	}
	if suffix == "" {
		return netip.Addr{}, false
	}
	if suffix == "localtest.me" || suffix == "lvh.me" {
		return netip.AddrFrom4([4]byte{127, 0, 0, 1}), true
	}
	rest := labels[:len(labels)-strings.Count(suffix, ".")-1]
	// Dotted quad in the last four labels.
	if n := len(rest); n >= 4 {
		if a, err := netip.ParseAddr(strings.Join(rest[n-4:], ".")); err == nil {
			return a, true
		}
	}
	if len(rest) == 0 {
		return netip.Addr{}, false
	}
	last := rest[len(rest)-1]
	// Dashed quad, possibly after a name: app-10-0-0-1.
	if segs := strings.Split(last, "-"); len(segs) >= 4 {
		if a, err := netip.ParseAddr(strings.Join(segs[len(segs)-4:], ".")); err == nil {
			return a, true
		}
	}
	// Eight hex digits.
	if len(last) == 8 {
		if v, err := strconv.ParseUint(last, 16, 32); err == nil {
			return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)}), true
		}
	}
	return netip.Addr{}, false
}
