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
//     when nobody but the owner, the account and root is in the group (the
//     user-private-group scheme with umask 002, Debian and Ubuntu's default
//     for login users, or a root file in the account's own group),
//   - and, for a root-owned file in another account's home, it has a
//     single link: on kernels or mounts without protected_hardlinks an
//     account can hard-link a root file it cannot read (a container's
//     /etc/shadow) into its home, and a capable sensor would read it for
//     the account.
//
// Anything else is refused on the open descriptor before a byte is read,
// counted as denied, and reported as posture: a project_config asset with
// the risk flag untrusted_owner (Parent the agent whose location holds it)
// and a failing posture check SPR-SCAN-001 on it. This holds whether or not the scan is privileged:
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
	admin := adminOr(g.adminUID)
	mode := fmt.Sprintf("mode %04o", uint32(m.perm&fs.ModePerm))
	switch {
	case m.owner != account && m.owner != admin:
		return "owned by uid " + m.owner + ", neither the account (uid " + account + ") nor root"
	case rootLinked(m, account, admin):
		return fmt.Sprintf("owned by root with %d links: possibly a hard link to a file the account cannot read", m.nlink)
	case m.perm&0o002 != 0:
		return "writable by every account (" + mode + ")"
	case m.perm&0o020 != 0 && !g.groupWithin(m.group, m.owner, account, admin):
		return "writable by group " + m.group + ", which holds accounts other than the owner, the account and root (" + mode + ")"
	}
	return ""
}

func adminOr(uid string) string {
	if uid == "" {
		return "0"
	}
	return uid
}

func rootLinked(m fmeta, account, admin string) bool {
	return m.owner == admin && account != admin && m.nlink > 1
}

// foreignWrite reports a refusal whose file someone other than the
// account and root wrote, or may be a link to a file the account cannot
// read: a planted file, not merely loose permissions on the account's own.
func foreignWrite(m fmeta, account, admin string) bool {
	return m.owner != account && m.owner != admin || rootLinked(m, account, admin)
}

// acctDB is what the owner rule needs from the account database of the
// scanned root.
type acctDB struct {
	primary map[string][]string // gid -> uids whose primary group it is
	name    map[string]string   // uid -> account name
	members map[string][]string // gid -> supplementary member names
}

// groupWithin reports whether every account in group gid is the file's
// owner, the account whose home holds it, or root: the gid is the primary
// group of at least one of them and of nobody else, and no other account
// is listed as a member. That covers the user-private-group scheme (umask
// 002: the account's own group on its own file) and a root-provisioned
// file the account may edit (root:account 0664), both writable by nobody
// but the account and root. Without a readable account database no group
// qualifies.
func (g *gate) groupWithin(gid string, uids ...string) bool {
	g.acctOnce.Do(func() { g.acct = g.loadAccounts() })
	db := g.acct
	if db == nil || gid == "" {
		return false
	}
	allowed := func(uid string) bool {
		for _, u := range uids {
			if u != "" && u == uid {
				return true
			}
		}
		return false
	}
	us := db.primary[gid]
	if len(us) == 0 {
		return false
	}
	for _, u := range us {
		if !allowed(u) {
			return false
		}
	}
	for _, m := range db.members[gid] {
		ok := false
		for _, u := range uids {
			if n, known := db.name[u]; known && n == m {
				ok = true
				break
			}
		}
		if !ok {
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
	foreign        bool // someone else wrote it (see foreignWrite)
}

// untrustedSet is the refusals kept for one directory reported as a unit:
// a home, or a project.
type untrustedSet struct {
	files []untrustedFile
	// dropped counts the distinct refused files over the caps, and
	// droppedForeign those of them someone else wrote.
	dropped, droppedForeign int
}

// The refusals kept are bounded per directory and per account, never per
// scan: a hostile home can plant one in every catalogued location and
// multiply skills at will, and a scan-wide cap would let one account fill
// it from its own home and hide a file planted in the home of an account
// scanned after it. Within a directory a file someone else wrote displaces
// one that only has loose permissions, so the account's own world-writable
// files cannot hide a planted one either. What is dropped is still counted
// as denied and reported as one summary check per directory.
const (
	maxUntrustedPerDir     = 64
	maxUntrustedPerAccount = 256
)

// untrustedKey identifies the set a refused file at l belongs to.
func (s *scanner) untrustedKey(uid, root string) string {
	k := uid + "\x00" + cleanLogical(root)
	if foldCase(s.goos) {
		k = strings.ToLower(k)
	}
	return k
}

// recordUntrusted is the gate's untrusted callback.
func (s *scanner) recordUntrusted(l loc, m fmeta, why string) {
	p := l.String()
	f := untrustedFile{uid: l.uid, path: p, why: why, foreign: foreignWrite(m, l.uid, adminOr(s.adminUID))}
	s.untrustedMu.Lock()
	defer s.untrustedMu.Unlock()
	if s.untrustedSeen[p] {
		return
	}
	s.untrustedSeen[p] = true
	k := s.untrustedKey(l.uid, l.root)
	set := s.untrusted[k]
	if set == nil {
		set = &untrustedSet{}
		s.untrusted[k] = set
	}
	if len(set.files) < maxUntrustedPerDir && s.untrustedKept[l.uid] < maxUntrustedPerAccount {
		set.files = append(set.files, f)
		s.untrustedKept[l.uid]++
		return
	}
	if f.foreign {
		// Displace the last file of this directory that nobody else wrote.
		for i := len(set.files) - 1; i >= 0; i-- {
			if !set.files[i].foreign {
				set.files[i], f = f, set.files[i]
				break
			}
		}
	}
	set.dropped++
	if f.foreign {
		set.droppedForeign++
	}
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

// reportUntrusted reports the refused files of dir (a project, or the home
// when project is false) that are not reported yet: one project_config
// asset each, flagged untrusted_owner, and a failing posture check on it
// (untrustedCheck). Their content was not read, so they carry no hash. A
// home file names as Parent the agent whose catalogued location holds it:
// the agent asset itself may not exist (a state directory several products
// share identifies none of them). Files over the caps are reported as one
// summary check for dir.
func (s *scanner) reportUntrusted(uc *userCtx, dir string, project bool) {
	s.untrustedMu.Lock()
	k := s.untrustedKey(uidOf(uc), dir)
	set := s.untrusted[k]
	delete(s.untrusted, k)
	s.untrustedMu.Unlock()
	if set == nil {
		return
	}
	for _, f := range set.files {
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
		s.add(&record{a: a, uc: uc, check: untrustedCheck(a, f.foreign)})
	}
	if set.dropped > 0 {
		s.led.note(fmt.Sprintf("%d more files refused by the owner rule in %s are not listed (limits: %d per directory, %d per account)",
			set.dropped, dir, maxUntrustedPerDir, maxUntrustedPerAccount))
		c := &event.Check{
			ID:       checkUntrustedOwner,
			Title:    "More agent configuration files written or writable by other accounts",
			Status:   "fail",
			Severity: event.SevMedium,
			Scope:    event.ScopeUser,
			Subject:  safeText(dir, 1024),
			Expected: untrustedExpected,
			Actual: fmt.Sprintf("%d more refused files are not listed (%d written by another account); limits %d per directory, %d per account",
				set.dropped, set.droppedForeign, maxUntrustedPerDir, maxUntrustedPerAccount),
			Remedy: untrustedRemedy,
		}
		if set.droppedForeign > 0 {
			c.Severity = event.SevHigh
		}
		if project {
			c.Scope = event.ScopeProject
		}
		if uc != nil {
			c.Owner = uc.u.Name
		}
		s.checks = append(s.checks, &checkRec{c: c, uc: uc})
	}
}

// checkUntrustedOwner is the id of the posture check for a refused file.
// The scanner itself emits it, not a rule pack: the refusal is the
// scanner's decision about a file it did not read, and it is reported
// whatever rule set or bundle is loaded. The SCAN area keeps it apart from
// the pack rule ids (SPR-POST-*).
const checkUntrustedOwner = "SPR-SCAN-001"

const (
	untrustedExpected = "owned by the account or root and writable by nobody else"
	untrustedRemedy   = "Find out who wrote the file. If the account did not, remove it and treat the account as targeted; " +
		"if it did, give the file to the account (chown) and remove group and world write (chmod go-w). " +
		"spoor does not read the file until then."
)

// untrustedCheck is the failing posture check reported with the asset of a
// refused file: high when someone else wrote it (a planted file), medium
// when only its permissions let others write it.
func untrustedCheck(a *event.Asset, foreign bool) *event.Check {
	c := &event.Check{
		ID:       checkUntrustedOwner,
		Title:    "Agent configuration file written or writable by another account",
		Status:   "fail",
		Severity: event.SevMedium,
		AgentID:  a.Parent,
		Scope:    a.Scope,
		Subject:  a.Path,
		Expected: untrustedExpected,
		Actual:   a.Detail[flagUntrustedOwner],
		Owner:    a.Owner,
		Remedy:   untrustedRemedy,
	}
	if foreign {
		c.Severity = event.SevHigh
	}
	return c
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
