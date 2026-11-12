package discovery

import (
	"errors"
	"fmt"
	"io/fs"
	"strings"

	"github.com/thomastysong/spoor/internal/event"
)

// The owner rule for files inside an account's home (the home itself and
// projects below it). An agent reads its configuration from there and acts
// on it as the account, so a file the account did not write is a way for
// someone else to give the agent instructions, MCP servers or hooks. Such
// a file is read only when
//
//   - the account or root owns it (an administrator may provision a
//     read-only configuration into a home), and
//   - nobody else can write it: not world-writable, and group-writable only
//     when the group is private to the owner (the user-private-group scheme
//     with umask 002, Debian and Ubuntu's default for login users, where
//     only the owner is in the group),
//   - and, for a root-owned file in another account's home, it has a
//     single link: on kernels or mounts without protected_hardlinks an
//     account can hard-link a root file it cannot read (a container's
//     /etc/shadow) into its home, and a capable sensor would read it for
//     the account.
//
// Anything else is refused on the open descriptor before a byte is read,
// counted as denied, and reported as posture: the risk flag
// untrusted_owner on the agent whose file it is, or a project_config asset
// for a project file. This holds whether or not the scan is privileged:
// the node sensor runs as an ordinary uid with read capabilities. Files a
// scan reads for an account outside its home (a project elsewhere, a
// relocated state directory) keep the older rule: when privileged, the
// account must own them. Windows ACLs are not read (no owner is known).

// flagUntrustedOwner is the posture flag for such a refusal.
const flagUntrustedOwner = "untrusted_owner"

// checkFile applies the ownership rules to a file opened for an account
// (owner is its uid, "" for system files, which have no such rule).
func (g *gate) checkFile(l loc, m fmeta, owner string) error {
	if owner == "" || !m.hasOwner {
		return nil
	}
	if !l.inHome {
		return g.checkOwner(l, m, owner)
	}
	why := g.untrustedWhy(m, owner)
	if why == "" {
		return nil
	}
	if g.untrusted != nil {
		g.untrusted(l, m, why)
	}
	return fmt.Errorf("%w: %s", errUntrusted, why)
}

// untrustedWhy says why a file in the home of account (a uid) is not
// trusted, or "".
func (g *gate) untrustedWhy(m fmeta, account string) string {
	admin := g.adminUID
	if admin == "" {
		admin = "0"
	}
	mode := fmt.Sprintf("mode %04o", uint32(m.perm&fs.ModePerm))
	switch {
	case m.owner != account && m.owner != admin:
		return "owned by uid " + m.owner + ", neither the account (uid " + account + ") nor root"
	case m.owner == admin && account != admin && m.nlink > 1:
		return fmt.Sprintf("owned by root with %d links: possibly a hard link to a file the account cannot read", m.nlink)
	case m.perm&0o002 != 0:
		return "writable by every account (" + mode + ")"
	case m.perm&0o020 != 0 && !g.privateGroup(m.group, m.owner):
		return "writable by group " + m.group + ", which is not private to the owner (" + mode + ")"
	}
	return ""
}

// acctDB is what the owner rule needs from the account database of the
// scanned root.
type acctDB struct {
	primary map[string][]string // gid -> uids whose primary group it is
	name    map[string]string   // uid -> account name
	members map[string][]string // gid -> supplementary member names
}

// privateGroup reports whether only owner is in group gid: the owner's
// primary group, nobody else's, and no other account listed as a member.
// Without a readable account database no group is private.
func (g *gate) privateGroup(gid, owner string) bool {
	g.acctOnce.Do(func() { g.acct = g.loadAccounts() })
	db := g.acct
	if db == nil || gid == "" {
		return false
	}
	if us := db.primary[gid]; len(us) != 1 || us[0] != owner {
		return false
	}
	name := db.name[owner]
	for _, m := range db.members[gid] {
		if m != name {
			return false
		}
	}
	return true
}

// loadAccounts reads /etc/passwd and /etc/group of the scanned root
// (inside HostRoot when set) through the gate.
func (g *gate) loadAccounts() *acctDB {
	pw, _, err := g.readFile(systemLoc("/etc/passwd"), "", 4<<20)
	if err != nil {
		return nil
	}
	db := &acctDB{primary: map[string][]string{}, name: map[string]string{}, members: map[string][]string{}}
	for _, line := range strings.Split(string(pw), "\n") {
		f := strings.Split(strings.TrimSuffix(line, "\r"), ":")
		if len(f) < 4 || f[0] == "" || strings.HasPrefix(f[0], "#") || !numeric(f[2]) || !numeric(f[3]) {
			continue
		}
		if _, dup := db.name[f[2]]; !dup {
			db.name[f[2]] = f[0]
		}
		db.primary[f[3]] = append(db.primary[f[3]], f[2])
	}
	gr, _, err := g.readFile(systemLoc("/etc/group"), "", 4<<20)
	switch {
	case err == nil:
		for _, line := range strings.Split(string(gr), "\n") {
			f := strings.Split(strings.TrimSuffix(line, "\r"), ":")
			if len(f) < 4 || !numeric(f[2]) || strings.TrimSpace(f[3]) == "" {
				continue
			}
			for _, m := range strings.Split(f[3], ",") {
				if m = strings.TrimSpace(m); m != "" {
					db.members[f[2]] = append(db.members[f[2]], m)
				}
			}
		}
	case errors.Is(err, fs.ErrNotExist):
		// No group file: nobody has a supplementary group.
	default:
		// Members unknown: no group can be shown to be private.
		return nil
	}
	return db
}

func numeric(s string) bool {
	if s == "" || len(s) > 10 {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// untrustedFile is a file checkFile refused, kept for the posture report.
type untrustedFile struct {
	uid, path, why string
}

// maxUntrusted bounds the refusals kept per scan: a hostile home can plant
// one in every catalogued location.
const maxUntrusted = 256

// recordUntrusted is the gate's untrusted callback.
func (s *scanner) recordUntrusted(l loc, _ fmeta, why string) {
	p := l.String()
	s.untrustedMu.Lock()
	defer s.untrustedMu.Unlock()
	if s.untrustedSeen[p] || len(s.untrusted) >= maxUntrusted {
		return
	}
	s.untrustedSeen[p] = true
	s.untrusted = append(s.untrusted, untrustedFile{uid: l.uid, path: p, why: why})
}

// productHomeBases lists the static prefixes of every home location the
// catalog gives product i, expanded for uc.
func (s *scanner) productHomeBases(i int, uc *userCtx) []string {
	p := &s.products[i]
	pats := append([]string(nil), p.StateDirs.For(s.goos)...)
	for _, m := range p.MCP {
		pats = append(pats, m.Paths.For(s.goos)...)
	}
	if p.Hooks != nil {
		pats = append(pats, p.Hooks.UserPaths.For(s.goos)...)
	}
	for _, st := range p.Settings {
		pats = append(pats, st.File.For(s.goos)...)
	}
	for _, l := range [][]string{p.Skills, p.Rules, p.Plugins, p.Subagents, p.Commands} {
		pats = append(pats, l...)
	}
	if p.Transcript != nil {
		pats = append(pats, p.Transcript.Globs.For(s.goos)...)
	}
	bases := []string{}
	for _, pat := range pats {
		if !isHomePath(pat) {
			continue
		}
		if e, ok := s.expand(pat, uc); ok {
			if b := staticPrefix(e); b != "" && b != uc.home && withinLogical(uc.home, b, s.goos) {
				bases = append(bases, b)
			}
		}
	}
	return bases
}

// inScannedProject reports whether p lies in a project scanned for uc.
func (s *scanner) inScannedProject(uc *userCtx, p string) bool {
	for _, d := range s.projDirs[uc.u.UID] {
		if withinLogical(d, p, s.goos) {
			return true
		}
	}
	return false
}

// reportUntrusted records the refused files below dir (a project, or the
// home when project is false) that are not reported yet, one
// project_config asset each, flagged untrusted_owner. Their content was not
// read, so they carry no hash. A home file names as Parent the agent whose
// catalogued location holds it: the agent asset itself may not exist (a
// state directory several products share identifies none of them).
func (s *scanner) reportUntrusted(uc *userCtx, dir string, project bool) {
	s.untrustedMu.Lock()
	var files []untrustedFile
	for _, f := range s.untrusted {
		if !s.untrustedDone[f.path] && f.uid == uidOf(uc) && withinLogical(dir, f.path, s.goos) {
			files = append(files, f)
			s.untrustedDone[f.path] = true
		}
	}
	s.untrustedMu.Unlock()
	for _, f := range files {
		if !project && s.inScannedProject(uc, f.path) {
			continue
		}
		rel, ok := relLogical(dir, f.path, s.goos)
		if !ok || rel == "" {
			continue
		}
		a := &event.Asset{
			Kind:      event.AssetProjectConfig,
			Name:      safeText(rel, 256),
			Path:      safeText(f.path, 1024),
			Scope:     event.ScopeUser,
			RiskFlags: []string{flagUntrustedOwner},
			Detail:    map[string]string{flagUntrustedOwner: safeText(f.why, 300)},
		}
		if project {
			a.Scope = event.ScopeProject
			a.Detail["project"] = safeText(dir, 1024)
		} else {
			a.Parent = s.ownerProduct(uc, f.path)
		}
		if uc != nil {
			a.Owner = uc.u.Name
		}
		s.add(&record{a: a, uc: uc})
	}
}

// ownerProduct is the catalog id of the product (agents first) whose home
// locations hold p, or "".
func (s *scanner) ownerProduct(uc *userCtx, p string) string {
	best, rank := "", 2
	for i := range s.products {
		r := 1
		if s.products[i].Kind == string(event.AssetAgent) {
			r = 0
		}
		if r >= rank {
			continue
		}
		for _, b := range s.productHomeBases(i, uc) {
			if withinLogical(b, p, s.goos) {
				best, rank = s.products[i].ID, r
				break
			}
		}
	}
	return best
}
