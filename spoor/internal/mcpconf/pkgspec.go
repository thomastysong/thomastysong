package mcpconf

import (
	"regexp"
	"strings"
)

// pkgSpec is what a launcher was told to run: a registry package, a
// container image, a git/URL source or a local path.
type pkgSpec struct {
	name    string // registry name, image repository, or the remote source as written
	version string // as declared: exact version, range, dist-tag, image tag, digest or git ref
	pinned  bool   // version identifies immutable content
	local   bool   // a path on this machine: nothing is fetched
	remote  bool   // git or URL source instead of a registry name
}

var (
	// An exact npm version is a full MAJOR.MINOR.PATCH. "1" and "1.2" are
	// x-ranges and "latest"/"next" are dist-tags: all three move.
	reSemverExact = regexp.MustCompile(`^[v=]?\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?(?:\+[0-9A-Za-z.\-]+)?$`)
	// PEP 440 public version with optional local label. No wildcard, no
	// operator, no comma: those make it a range.
	rePEP440Exact = regexp.MustCompile(`(?i)^v?(?:\d+!)?\d+(?:\.\d+)*(?:[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?\d*)?(?:[-_.]?(?:post|rev|r)[-_.]?\d*|-\d+)?(?:[-_.]?dev[-_.]?\d*)?(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$`)
	// A full commit id names content; abbreviated ids, tags and branches do not.
	reCommitID = regexp.MustCompile(`^(?:[0-9a-f]{40}|[0-9a-f]{64})$`)
	reDigest   = regexp.MustCompile(`^sha(?:256:[0-9a-f]{64}|512:[0-9a-f]{128})$`)
	reGoExact  = regexp.MustCompile(`^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.\-]+)?(?:\+incompatible)?$`)
	rePyName   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._\-]*`)
	rePySep    = regexp.MustCompile(`[-_.]+`)
)

// isLocalSpec reports whether a package operand is a filesystem path.
func isLocalSpec(s string) bool {
	if s == "" {
		return false
	}
	if s == "." || s == ".." || isAbsPath(s) || homeRelative(s) {
		return true
	}
	ls := strings.ToLower(s)
	for _, p := range []string{"./", "../", `.\`, `..\`, "~", "file:"} {
		if strings.HasPrefix(ls, p) {
			return true
		}
	}
	return false
}

// remoteSpec splits "source<sep>ref". The ref pins only when it is a full
// commit id.
func remoteSpec(s, sep string) pkgSpec {
	name, ref := s, ""
	if i := strings.LastIndex(s, sep); i >= 0 {
		name, ref = s[:i], s[i+len(sep):]
	}
	return pkgSpec{name: name, version: ref, remote: true, pinned: reCommitID.MatchString(strings.ToLower(ref))}
}

// parseNpmSpec reads an npm package argument: name, name@version,
// @scope/name@version, git and URL sources, GitHub shorthand, local paths.
func parseNpmSpec(s string) pkgSpec {
	s = strings.TrimSpace(s)
	if isLocalSpec(s) {
		return pkgSpec{name: s, local: true}
	}
	ls := strings.ToLower(s)
	for _, p := range []string{"git+", "git://", "github:", "gitlab:", "bitbucket:", "gist:", "http://", "https://", "ssh://"} {
		if strings.HasPrefix(ls, p) {
			return remoteSpec(s, "#")
		}
	}
	name, ver := s, ""
	if at := strings.LastIndex(s, "@"); at > 0 {
		name, ver = s[:at], s[at+1:]
	}
	if !strings.HasPrefix(name, "@") && strings.Contains(name, "/") {
		return remoteSpec(s, "#") // user/repo is npm's GitHub shorthand
	}
	return pkgSpec{name: name, version: ver, pinned: reSemverExact.MatchString(ver)}
}

// parsePySpec reads a requirement as given to uvx, uv --with, pipx or pip:
// name, name[extra], name==1.2.3, name>=1, name@1.2.3 (uvx), name @ URL,
// VCS and archive URLs, local paths.
func parsePySpec(s string) pkgSpec {
	s = strings.TrimSpace(s)
	if i := strings.IndexByte(s, ';'); i >= 0 {
		s = strings.TrimSpace(s[:i]) // environment marker
	}
	ls := strings.ToLower(s)
	if pyRemotePrefix(ls) {
		return pyRemote(s)
	}
	if isLocalSpec(s) || strings.HasSuffix(ls, ".py") {
		return pkgSpec{name: s, local: true}
	}
	name := rePyName.FindString(s)
	if name == "" {
		return pkgSpec{name: s}
	}
	rest := strings.TrimSpace(s[len(name):])
	if strings.HasPrefix(rest, "[") {
		if j := strings.IndexByte(rest, ']'); j >= 0 {
			rest = strings.TrimSpace(rest[j+1:])
		}
	}
	sp := pkgSpec{name: rePySep.ReplaceAllString(strings.ToLower(name), "-")}
	switch {
	case rest == "":
	case strings.HasPrefix(rest, "==="):
		sp.version = strings.TrimSpace(rest[3:])
		sp.pinned = rePEP440Exact.MatchString(sp.version)
	case strings.HasPrefix(rest, "=="):
		sp.version = strings.TrimSpace(rest[2:])
		sp.pinned = rePEP440Exact.MatchString(sp.version)
	case strings.HasPrefix(rest, "@"):
		v := strings.TrimSpace(rest[1:])
		if pyRemotePrefix(strings.ToLower(v)) || isLocalSpec(v) {
			// PEP 508 direct reference: the name is a label, the URL decides.
			direct := pyRemote(v)
			sp.remote, sp.version, sp.pinned = true, direct.version, direct.pinned
			break
		}
		sp.version = v
		sp.pinned = rePEP440Exact.MatchString(v)
	default:
		sp.version = rest // a range such as ">=1.0" or "~=1.2"
	}
	return sp
}

func pyRemotePrefix(ls string) bool {
	for _, p := range []string{"git+", "hg+", "svn+", "bzr+", "http://", "https://"} {
		if strings.HasPrefix(ls, p) {
			return true
		}
	}
	return false
}

// pyRemote reads a VCS or archive URL: git+https://host/org/repo@ref#egg=x.
func pyRemote(s string) pkgSpec {
	body := s
	if i := strings.IndexByte(body, '#'); i >= 0 {
		body = body[:i]
	}
	ref := ""
	if i := strings.Index(body, "://"); i >= 0 {
		rest := body[i+3:]
		// Only an "@" after the first "/" is a ref; before it, it is userinfo.
		if slash := strings.IndexByte(rest, '/'); slash >= 0 {
			if at := strings.LastIndexByte(rest[slash:], '@'); at >= 0 {
				ref = rest[slash+at+1:]
				body = body[:i+3+slash+at]
			}
		}
	}
	return pkgSpec{name: body, version: ref, remote: true, pinned: reCommitID.MatchString(strings.ToLower(ref))}
}

// parseImageRef reads [registry[:port]/]repository[:tag][@digest].
func parseImageRef(ref string) pkgSpec {
	ref = strings.TrimSpace(ref)
	digest := ""
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		ref, digest = ref[:i], ref[i+1:]
	}
	tag := ""
	if i := strings.LastIndexByte(ref, ':'); i > strings.LastIndexByte(ref, '/') {
		ref, tag = ref[:i], ref[i+1:]
	}
	sp := pkgSpec{name: ref, version: tag}
	if digest != "" {
		sp.version = digest
		sp.pinned = reDigest.MatchString(strings.ToLower(digest))
	}
	return sp
}

// parseGoSpec reads the operand of "go run": module/path@version or a local
// package.
func parseGoSpec(s string) pkgSpec {
	if at := strings.LastIndex(s, "@"); at > 0 && !isLocalSpec(s) {
		ver := s[at+1:]
		return pkgSpec{name: s[:at], version: ver, pinned: reGoExact.MatchString(ver)}
	}
	return pkgSpec{name: s, local: true}
}
