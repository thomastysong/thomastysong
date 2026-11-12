package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/config"
	"github.com/thomastysong/thomastysong/hawkbell/internal/engine"
	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
	"github.com/thomastysong/thomastysong/hawkbell/internal/platform"
	"github.com/thomastysong/thomastysong/hawkbell/internal/privacy"
	"github.com/thomastysong/thomastysong/hawkbell/internal/sink"
	"github.com/thomastysong/thomastysong/hawkbell/internal/state"
)

func (a *app) cmdPrivacy(args []string) int {
	return a.dispatch("privacy", []subcommand{
		{"show", "what is collected, in which profile, where it goes and how long it is kept", a.privacyShow},
		{"tail", "show the records written about your own sessions", a.privacyTail},
		{"purge", "erase a user's records from the state database, the local ring and the hook spool", a.privacyPurge},
	}, args)
}

// describePolicy builds the policy for Describe. When a key file is
// configured but this account cannot read it (it is root-only), a
// stand-in key of the right length makes Describe tell the truth ("a key
// is configured"); it is never used to compute anything.
func describePolicy(cfg *config.Config) (*privacy.Policy, string) {
	p, err := engine.PolicyFromConfig(cfg)
	if err == nil {
		return p, ""
	}
	note := ""
	p = &privacy.Policy{
		Profile: privacy.Profile(cfg.Privacy.Profile), KeyID: cfg.Privacy.KeyID,
		PseudonymizeUsers: cfg.Privacy.PseudonymizeUsers, MaxLine: cfg.Output.MaxLine,
		Exclude: privacy.Exclusions{Paths: cfg.Privacy.Exclude.Paths, Repos: cfg.Privacy.Exclude.Repos, Users: cfg.Privacy.Exclude.Users},
	}
	if cfg.Privacy.HMACKeyFile != "" {
		p.Key = make([]byte, privacy.MinKeyLen)
		note = fmt.Sprintf("the tenant key file could not be read by this account (%v); the sensor reads it as root", err)
	}
	return p, note
}

type privacyView struct {
	Profile      string            `json:"profile"`
	Statements   []string          `json:"statements"`
	Note         string            `json:"note,omitempty"`
	Destinations []string          `json:"destinations"`
	Retention    map[string]string `json:"retention"`
	Exclusions   config.Exclude    `json:"exclusions"`
	Context      int               `json:"context_events"`
	KillSwitch   bool              `json:"kill_switch"`
}

func (a *app) privacyShow(args []string) int {
	fs := a.newFlags("privacy show", "privacy show [--json]", "Explains, for the person whose machine this is, what hawkbell collects here, what leaves the machine, where it goes and how long it is kept.")
	var cf cfgFlags
	cf.register(fs)
	asJSON := fs.Bool("json", false, "print JSON")
	if pos, code, done := a.parse(fs, args); done {
		return code
	} else if len(pos) > 0 {
		return a.usageErr("privacy show", "unexpected argument %q", pos[0])
	}
	cfg, _, err := loadConfig(cf)
	if err != nil {
		return a.fail("privacy show", err)
	}
	pol, note := describePolicy(cfg)
	v := privacyView{
		Profile: cfg.Privacy.Profile, Statements: pol.Describe(), Note: note,
		Destinations: destinations(cfg), Exclusions: cfg.Privacy.Exclude, Context: cfg.Privacy.ContextEvents,
		KillSwitch: platform.Disabled(),
		Retention: map[string]string{
			"outbox":       fmt.Sprintf("%s or %s, whichever is reached first", cfg.Retention.Outbox.D(), bytesStr(cfg.Retention.OutboxBytes)),
			"local_ring":   fmt.Sprintf("%s or %s", cfg.Retention.Local.D(), bytesStr(cfg.Retention.LocalBytes)),
			"hook_spool":   cfg.Retention.Spool.D().String() + " after the last write (system spool: once the daemon has also read it; elsewhere: at the first hook call an hour or more after the previous scan of that spool, and never while no hook runs or the hook is switched off)",
			"state_detect": cfg.Retention.Detections.D().String(),
			"state_sess":   cfg.Retention.Sessions.D().String(),
		},
	}
	if *asJSON {
		return a.printJSON(v)
	}
	for _, s := range v.Statements {
		fmt.Fprintf(a.stdout, "%s\n\n", s)
	}
	if note != "" {
		fmt.Fprintf(a.stdout, "Note: %s.\n\n", note)
	}
	fmt.Fprintln(a.stdout, "Where shipped records go:")
	for _, d := range v.Destinations {
		fmt.Fprintf(a.stdout, "  - %s\n", d)
	}
	fmt.Fprintln(a.stdout, "\nHow long local copies are kept:")
	fmt.Fprintf(a.stdout, "  - outbox (shipped records): %s\n", v.Retention["outbox"])
	fmt.Fprintf(a.stdout, "  - local ring (activity that is not shipped): %s\n", v.Retention["local_ring"])
	fmt.Fprintf(a.stdout, "  - hook spool: %s\n", v.Retention["hook_spool"])
	fmt.Fprintf(a.stdout, "  - state database (read by osquery/Fleet): detections %s, sessions %s\n", v.Retention["state_detect"], v.Retention["state_sess"])
	fmt.Fprintln(a.stdout, "\nYour own records: `hawkbell privacy tail` (the records are readable by root, and the shipped ones by output.group, so run it with administrator rights). Erasure: `hawkbell privacy purge --user <name>` (administrator).")
	if v.KillSwitch {
		fmt.Fprintln(a.stdout, "\nThe kill switch is on: nothing is being collected on this machine right now.")
	}
	return exitOK
}

func destinations(cfg *config.Config) []string {
	out := []string{fmt.Sprintf("the outbox %s, which a log shipper on this machine (normally Fluent Bit) forwards to the organisation's log store; hawkbell does not choose that destination", cfg.OutboxDir())}
	if cfg.Output.Stdout {
		out = append(out, "standard output of the sensor (container log collection)")
	}
	if f := cfg.Output.Forward; f != nil && f.Addr != "" {
		out = append(out, "Fluent Forward to "+endpointHost(f.Addr))
	}
	if o := cfg.Output.OTLP; o != nil && o.Endpoint != "" {
		out = append(out, "OTLP/HTTP to "+endpointHost(o.Endpoint))
	}
	if len(cfg.Output.Streams) > 0 {
		out = append(out, "shipped streams restricted to: "+strings.Join(cfg.Output.Streams, ", "))
	}
	return out
}

// endpointHost shows scheme and host of an endpoint, never credentials,
// paths or query strings.
func endpointHost(s string) string {
	u, err := url.Parse(s)
	if err != nil || u.Host == "" {
		if i := strings.LastIndexByte(s, '@'); i >= 0 {
			s = s[i+1:]
		}
		return clip(s, 80)
	}
	return u.Scheme + "://" + u.Host
}

func bytesStr(n int64) string {
	switch {
	case n <= 0:
		return "no size limit"
	case n >= 1<<30 && n%(1<<30) == 0:
		return fmt.Sprintf("%d GiB", n>>30)
	case n >= 1<<20:
		return fmt.Sprintf("%d MiB", n>>20)
	}
	return fmt.Sprintf("%d bytes", n)
}

// recordUser reads the user of one native or OCSF record line, or of a
// hook spool line ({"v":1,"event":{...},"content":{...}}).
func recordUser(line []byte) (name, id string) {
	type nativeUser struct {
		Name string `json:"name"`
		ID   string `json:"id"`
	}
	var r struct {
		User  *nativeUser `json:"user"`
		Actor *struct {
			User *struct {
				Name string `json:"name"`
				UID  string `json:"uid"`
			} `json:"user"`
		} `json:"actor"`
		Event *struct {
			User *nativeUser `json:"user"`
		} `json:"event"`
	}
	if json.Unmarshal(line, &r) != nil {
		return "", ""
	}
	switch {
	case r.User != nil:
		return r.User.Name, r.User.ID
	case r.Actor != nil && r.Actor.User != nil:
		return r.Actor.User.Name, r.Actor.User.UID
	case r.Event != nil && r.Event.User != nil:
		return r.Event.User.Name, r.Event.User.ID
	}
	return "", ""
}

// userMatcher decides whether a record belongs to one account: by name, by
// id, or by the keyed pseudonym the policy ships instead of either.
type userMatcher struct {
	names map[string]bool
	// all matches every line: an account's own spool directory, where the
	// file owner, not the line, says whose activity it is.
	all bool
	// pseudo is set when users are pseudonymized; keyErr says why the
	// pseudonyms could not be computed (the tenant key is unreadable or
	// unusable), in which case records carrying them are not matched.
	pseudo bool
	keyErr error
}

func newUserMatcher(cfg *config.Config, name, uid string) userMatcher {
	m := userMatcher{names: map[string]bool{}, pseudo: cfg.Privacy.PseudonymizeUsers}
	for _, v := range []string{name, uid} {
		if v != "" {
			m.names[v] = true
		}
	}
	if m.pseudo {
		pol, err := engine.PolicyFromConfig(cfg)
		if err != nil {
			m.keyErr = err
			return m
		}
		for _, v := range []string{name, uid} {
			if v == "" {
				continue
			}
			p := pol.Pseudonym(v)
			if p == "" {
				m.keyErr = errors.New("no usable tenant key")
				continue
			}
			m.names[p] = true
		}
	}
	return m
}

func (m userMatcher) match(line []byte) bool {
	if m.all {
		return true
	}
	n, id := recordUser(line)
	return (n != "" && m.names[n]) || (id != "" && m.names[id])
}

// values is every name, id and pseudonym the account's rows may carry, in
// a stable order.
func (m userMatcher) values() []string { return sortedKeys(m.names) }

const privacyTailAbout = `Shows the records hawkbell wrote about your own sessions: what was shipped
(outbox) and what stayed on this machine (local ring).

Both are written by the sensor running as root: the local ring is readable
by root only, and the outbox by root and the members of output.group. An
ordinary account therefore sees its own records only with administrator
rights (sudo hawkbell privacy tail --user <your name>), or, for the shipped
records alone, as a member of output.group. When neither can be read the
command says so and exits 1; it never reports "nothing" for records it could
not read. Another account's records need administrator rights (--user). With
pseudonymized users the match needs the tenant key, which only the
administrator can read.`

func (a *app) privacyTail(args []string) int {
	fs := a.newFlags("privacy tail", "privacy tail [--user name] [-n 20] [--follow] [--json]", privacyTailAbout)
	var cf cfgFlags
	cf.register(fs)
	user := fs.String("user", "", "account name (default: you; another account needs privilege)")
	n := fs.Int("n", 20, "records to show before following (0: only new ones)")
	follow := fs.Bool("follow", false, "keep printing new records until interrupted")
	interval := fs.Duration("interval", time.Second, "poll interval with --follow")
	asJSON := fs.Bool("json", false, "print the records as NDJSON")
	if pos, code, done := a.parse(fs, args); done {
		return code
	} else if len(pos) > 0 {
		return a.usageErr("privacy tail", "unexpected argument %q", pos[0])
	}
	if *n < 0 {
		return a.usageErr("privacy tail", "-n %d: want 0 or more", *n)
	}
	if *interval <= 0 {
		return a.usageErr("privacy tail", "--interval %s: want a positive duration", *interval)
	}
	cfg, _, err := loadConfig(cf)
	if err != nil {
		return a.fail("privacy tail", err)
	}
	me := currentUser()
	name, uid := me.Name, me.UID
	if *user != "" && *user != me.Name {
		if !platform.IsPrivileged() {
			return a.fail("privacy tail", fmt.Errorf("showing records of %q needs administrator rights", *user))
		}
		name, uid = *user, lookupUID(*user)
	}
	m := newUserMatcher(cfg, name, uid)
	if m.pseudo && m.keyErr != nil {
		a.warn("privacy tail", "users are pseudonymized and the tenant key cannot be used here (%v): records carrying the pseudonym are not shown", m.keyErr)
	}
	t := newTailer(cfg)
	recs, problems := t.poll(m)
	for _, p := range problems {
		a.warn("privacy tail", "%s", p)
	}
	if t.denied > 0 && t.read == 0 {
		return a.fail("privacy tail", fmt.Errorf("this account cannot read the records hawkbell keeps (%s): they are readable by root only%s; run `sudo hawkbell privacy tail --user %s`, or ask the administrator", strings.Join(t.deniedDirs, ", "), groupClause(cfg), firstNonEmpty(name, uid, "<your name>")))
	}
	if len(recs) > *n {
		recs = recs[len(recs)-*n:]
	}
	a.printTail(recs, *asJSON)
	if !*follow {
		return exitOK
	}
	ctx, stop := signal.NotifyContext(a.ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	tick := time.NewTicker(*interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return exitOK
		case <-tick.C:
			recs, _ := t.poll(m)
			a.printTail(recs, *asJSON)
		}
	}
}

// groupClause names output.group for the access messages.
func groupClause(cfg *config.Config) string {
	if cfg.Output.Group == "" {
		return ""
	}
	return fmt.Sprintf(" (the outbox also by members of %q)", cfg.Output.Group)
}

// tailRecord is one matched line and where it was found.
type tailRecord struct {
	where string // outbox | local
	line  []byte
}

// tailDir is one directory tail reads and who may read it.
type tailDir struct {
	path, where, label, access string
}

// tailer reads new complete lines of segment files, remembering offsets.
type tailer struct {
	dirs    []tailDir
	offsets map[string]int64
	// Of the last poll: directories read, and refused for lack of access.
	read, denied int
	deniedDirs   []string
}

func newTailer(cfg *config.Config) *tailer {
	outboxAccess := "readable by root only"
	if cfg.Output.Group != "" {
		outboxAccess = fmt.Sprintf("readable by root and the members of %q", cfg.Output.Group)
	}
	return &tailer{
		dirs: []tailDir{
			{cfg.OutboxDir(), "outbox", "outbox", outboxAccess},
			{cfg.LocalDir(), "local", "local ring", "readable by root only"},
		},
		offsets: map[string]int64{},
	}
}

func (t *tailer) poll(m userMatcher) ([]tailRecord, []string) {
	var out []tailRecord
	var problems []string
	t.read, t.denied, t.deniedDirs = 0, 0, nil
	for _, d := range t.dirs {
		ents, err := os.ReadDir(d.path)
		if err != nil {
			switch {
			case errors.Is(err, fs.ErrPermission):
				t.denied++
				t.deniedDirs = append(t.deniedDirs, d.path)
				problems = append(problems, fmt.Sprintf("%s: permission denied (the %s is %s)", d.path, d.label, d.access))
			case errors.Is(err, fs.ErrNotExist):
				t.read++ // nothing written yet: nothing hidden either
			default:
				problems = append(problems, err.Error())
			}
			continue
		}
		t.read++
		var names []string
		for _, e := range ents {
			if _, ok := sink.ParseSegmentName(e.Name()); ok && e.Type().IsRegular() {
				names = append(names, e.Name())
			}
		}
		sort.Slice(names, func(i, j int) bool { return segmentOrder(names[i]) < segmentOrder(names[j]) })
		for _, nm := range names {
			p := filepath.Join(d.path, nm)
			lines, off, err := readNewLines(p, t.offsets[p])
			if err != nil {
				problems = append(problems, err.Error())
				continue
			}
			t.offsets[p] = off
			for _, l := range lines {
				if m.match(l) {
					out = append(out, tailRecord{where: d.where, line: l})
				}
			}
		}
	}
	return out, problems
}

// readNewLines returns the complete lines after off, opened without
// following links. A file that shrank (replaced) is read from the start.
func readNewLines(path string, off int64) ([][]byte, int64, error) {
	f, err := platform.OpenNoFollow(path)
	if err != nil {
		return nil, off, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, off, err
	}
	if fi.Size() < off {
		off = 0
	}
	if _, err := f.Seek(off, io.SeekStart); err != nil {
		return nil, off, err
	}
	br := bufio.NewReaderSize(f, 64<<10)
	var lines [][]byte
	for {
		l, err := br.ReadBytes('\n')
		if err != nil {
			// An incomplete last line is left for the next poll.
			return lines, off, nil
		}
		off += int64(len(l))
		if len(l) <= maxInputLine {
			lines = append(lines, bytes.TrimRight(l, "\r\n"))
		}
	}
}

func (a *app) printTail(recs []tailRecord, asJSON bool) {
	for _, r := range recs {
		if asJSON {
			fmt.Fprintf(a.stdout, "%s\n", r.line)
			continue
		}
		var e event.Event
		if json.Unmarshal(r.line, &e) != nil || e.Kind == "" {
			fmt.Fprintf(a.stdout, "%-6s %s\n", r.where, clip(string(r.line), 200))
			continue
		}
		fmt.Fprintf(a.stdout, "%-6s %s %-9s %-20s %s\n", r.where, e.TS.Time.UTC().Format(time.RFC3339), term(string(e.Kind)), clip(e.Type, 20), clip(oneLine(&e), 140))
	}
}

// oneLine summarizes a record for the tail view.
func oneLine(e *event.Event) string {
	var parts []string
	if e.Agent != nil {
		parts = append(parts, e.Agent.ID)
	}
	switch {
	case e.Detection != nil:
		parts = append(parts, e.Detection.RuleID, e.Detection.Title)
	case e.Target != nil && e.Target.Command != "":
		parts = append(parts, e.Target.Command)
	case e.Target != nil && e.Target.URL != "":
		parts = append(parts, e.Target.URL)
	case e.Target != nil && e.Target.Path != "":
		parts = append(parts, e.Target.Path)
	case e.Tool != nil:
		parts = append(parts, e.Tool.Name)
	case e.Asset != nil:
		parts = append(parts, string(e.Asset.Kind), e.Asset.Name)
	case e.Summary != nil:
		parts = append(parts, fmt.Sprintf("%d events", e.Summary.Events))
	}
	return strings.Join(parts, " ")
}

type purgeResult struct {
	User        string   `json:"user"`
	DryRun      bool     `json:"dry_run"`
	StateRows   int      `json:"state_rows"`
	LocalLines  int      `json:"local_lines"`
	LocalFiles  int      `json:"local_files"`
	SpoolLines  int      `json:"spool_lines"`
	SpoolFiles  int      `json:"spool_files"`
	SpoolState  int      `json:"spool_state_files"`
	OutboxLines int      `json:"outbox_lines_not_erased"`
	Notes       []string `json:"notes,omitempty"`
}

const privacyPurgeAbout = `Erases one account's records from this machine:
  - every row of the state database that carries the account's name, id or
    (with pseudonymized users) keyed pseudonym (secure delete; the
    write-ahead log is truncated);
  - every line of the local ring that belongs to the account;
  - the hook spool, which holds the account's activity WITH local content
    (prompt text, tool input and output) for retention.spool after its last
    write and until it is deleted (by the daemon once it has read a file in
    <data>/spool/<uid>/, by a later hook of the account elsewhere; not while
    no hook runs or the hook is switched off): every line of the account's
    own spool directories (<data>/spool/<uid>/ and the fallback spool in its
    home) is overwritten in place, its guard-mode session state is deleted,
    and lines naming the account in any other spool directory are
    overwritten too.
Records already shipped must be erased in the log store; outbox segments are
append-only and leave by retention (their count is reported). For a
guaranteed purge stop the daemon and the account's agents first: a line
appended while a file is being purged can be missed (retention removes it
later). --uid names the account's numeric id (or SID) when it no longer
exists on this machine.`

func (a *app) privacyPurge(args []string) int {
	fs := a.newFlags("privacy purge", "privacy purge --user name [--uid id] [--dry-run] [--json]", privacyPurgeAbout)
	var cf cfgFlags
	cf.register(fs)
	user := fs.String("user", "", "account name or id to erase (required)")
	uidFlag := fs.String("uid", "", "the account's numeric id or SID (default: looked up from --user)")
	dry := fs.Bool("dry-run", false, "count what would be erased, change nothing")
	asJSON := fs.Bool("json", false, "print JSON")
	if pos, code, done := a.parse(fs, args); done {
		return code
	} else if len(pos) > 0 {
		return a.usageErr("privacy purge", "unexpected argument %q", pos[0])
	}
	if strings.TrimSpace(*user) == "" {
		return a.usageErr("privacy purge", "--user is required")
	}
	cfg, _, err := loadConfig(cf)
	if err != nil {
		return a.fail("privacy purge", err)
	}
	res := purgeResult{User: *user, DryRun: *dry}
	uid := *uidFlag
	if uid == "" {
		uid = lookupUID(*user)
	}
	if uid == "" && !looksLikeUID(*user) {
		res.Notes = append(res.Notes, fmt.Sprintf("no local account %q: records are matched by name; pass --uid to also erase records and the spool directory kept under the account's id", *user))
	} else if uid == "" {
		uid = *user
	}
	m := newUserMatcher(cfg, *user, uid)
	if m.pseudo && m.keyErr != nil {
		res.Notes = append(res.Notes, fmt.Sprintf("users are pseudonymized and the tenant key could not be used (%v): state rows, local and spool lines carrying the pseudonym were not matched; run purge where the key is readable (as root)", m.keyErr))
	}
	if *dry {
		res.StateRows = -1
	} else if _, err := os.Stat(cfg.StateDB()); err == nil {
		n, err := purgeStateRows(cfg.StateDB(), m.values())
		if err != nil {
			return a.fail("privacy purge", err)
		}
		res.StateRows = n
	}
	lines, files, err := purgeSegments(cfg.LocalDir(), m, *dry)
	if err != nil {
		return a.fail("privacy purge", err)
	}
	res.LocalLines, res.LocalFiles = lines, files
	sp, err := purgeSpool(cfg, m, *user, uid, *dry)
	res.SpoolLines, res.SpoolFiles, res.SpoolState = sp.lines, sp.files, sp.state
	res.Notes = append(res.Notes, sp.notes...)
	if err != nil {
		return a.fail("privacy purge", err)
	}
	res.OutboxLines, _, _ = purgeSegments(cfg.OutboxDir(), m, true)
	if *asJSON {
		return a.printJSON(res)
	}
	verb := "erased"
	if *dry {
		verb = "would erase"
	}
	if res.StateRows >= 0 {
		fmt.Fprintf(a.stdout, "state database: %s %d row(s)\n", verb, res.StateRows)
	}
	fmt.Fprintf(a.stdout, "local ring: %s %d line(s) in %d segment(s)\n", verb, res.LocalLines, res.LocalFiles)
	fmt.Fprintf(a.stdout, "hook spool: %s %d line(s) in %d file(s) and %d session state file(s)\n", verb, res.SpoolLines, res.SpoolFiles, res.SpoolState)
	fmt.Fprintf(a.stdout, "outbox: %d line(s) of this user remain (append-only, shipped already; erase them in the log store, retention removes the local copy)\n", res.OutboxLines)
	for _, n := range res.Notes {
		fmt.Fprintf(a.stdout, "note: %s\n", sanitize(n))
	}
	return exitOK
}

// looksLikeUID reports whether s is an account id rather than a name: a
// POSIX uid or a Windows SID.
func looksLikeUID(s string) bool {
	if strings.HasPrefix(s, "S-1-") {
		return true
	}
	if s == "" || len(s) > 10 {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// purgeStateRows deletes the account's rows under every value they can
// carry. With pseudonymize_users the pipeline stores the redacted record,
// so the rows hold the keyed pseudonym of the name (or of the id when
// there is no name), not the name itself.
func purgeStateRows(path string, values []string) (int, error) {
	st, err := state.Open(path)
	if err != nil {
		return 0, fmt.Errorf("state database: %w", err)
	}
	total := 0
	var perr error
	for _, v := range values {
		if strings.TrimSpace(v) == "" {
			continue
		}
		n, err := st.PurgeUser(v)
		if err != nil {
			perr = err
			break
		}
		total += n
	}
	if cerr := st.Close(); perr == nil {
		perr = cerr
	}
	return total, perr
}

type spoolPurge struct {
	lines, files, state int
	notes               []string
}

// purgeSpool erases the account's hook spool lines. In the account's own
// directories every line is the account's (the daemon attributes a spool
// line by its file's owner, never by what the line says); elsewhere only
// lines that name the account are touched. Lines are overwritten in place
// with newlines instead of being removed, so the file keeps its identity
// and length: the daemon's spool reader keeps byte offsets per file, and a
// shorter replacement file would make it read the remaining lines again.
// An empty line is skipped by the reader without a complaint.
//
// Spool directories are writable by the accounts they belong to, so every
// directory is opened as an os.Root: a symbolic link planted inside one
// (a "state" that points at /etc, a home spool path that leads to the local
// ring) cannot take an administrator's purge outside it.
func purgeSpool(cfg *config.Config, m userMatcher, name, uid string, dry bool) (spoolPurge, error) {
	var res spoolPurge
	type root struct {
		r   *os.Root
		own bool // the account's own directory
	}
	var roots []root
	defer func() {
		for _, r := range roots {
			r.r.Close()
		}
	}()
	ents, err := os.ReadDir(cfg.SpoolDir())
	switch {
	case err == nil:
		for _, e := range ents {
			// Only per-account directories (named by uid or SID), never
			// through a link.
			if !e.IsDir() || !looksLikeUID(e.Name()) {
				continue
			}
			r, err := openDirRoot(filepath.Join(cfg.SpoolDir(), e.Name()))
			if err != nil {
				res.notes = append(res.notes, fmt.Sprintf("%s: %v (not purged)", filepath.Join(cfg.SpoolDir(), e.Name()), err))
				continue
			}
			roots = append(roots, root{r: r, own: uid != "" && e.Name() == uid})
		}
	case errors.Is(err, fs.ErrNotExist):
	case errors.Is(err, fs.ErrPermission):
		res.notes = append(res.notes, fmt.Sprintf("%s: permission denied: the hook spool was not purged (run as root)", cfg.SpoolDir()))
	default:
		return res, err
	}
	// The fallback spool in the account's home, used when the system spool
	// directory did not exist for it. Resolved inside the home only.
	if home := accountHome(name, uid); home != "" {
		if r, ok := homeSpoolRoot(home); ok {
			roots = append(roots, root{r: r, own: true})
		}
	}
	for _, r := range roots {
		mm := m
		mm.all = r.own
		lines, files, err := blankSpoolDir(r.r, mm, dry)
		res.lines += lines
		res.files += files
		if err != nil {
			return res, err
		}
		if r.own {
			n, err := purgeSpoolState(r.r, dry)
			res.state += n
			if err != nil {
				return res, err
			}
		}
	}
	return res, nil
}

// openDirRoot opens dir, which must be a real directory and not a link, as
// an os.Root.
func openDirRoot(dir string) (*os.Root, error) {
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, err
	}
	if !fi.IsDir() {
		return nil, errNotOurs
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		return nil, err
	}
	if got, err := r.Stat("."); err != nil || !os.SameFile(fi, got) {
		r.Close()
		return nil, errNotOurs
	}
	return r, nil
}

// homeSpoolRoot opens the fallback spool directory of a home, resolved
// within the home.
func homeSpoolRoot(home string) (*os.Root, bool) {
	rel, err := filepath.Rel(home, platform.UserDirs(home).Spool)
	if err != nil || rel == "." || strings.HasPrefix(rel, "..") {
		return nil, false
	}
	hr, err := os.OpenRoot(home)
	if err != nil {
		return nil, false
	}
	defer hr.Close()
	r, err := hr.OpenRoot(rel)
	if err != nil {
		return nil, false
	}
	return r, true
}

// accountHome finds the home directory of the account named name (or with
// id uid) among the accounts this process can see.
func accountHome(name, uid string) string {
	users, _ := platform.Users()
	for _, u := range users {
		if (name != "" && u.Name == name) || (uid != "" && u.UID == uid) {
			return u.Home
		}
	}
	return ""
}

// errNotOurs refuses a file or directory purge must not write: a link,
// something other than a regular file (or directory), or a file with
// several names.
var errNotOurs = errors.New("not a regular single-link file or a real directory")

// openForRewrite opens name in r read-write for an in-place rewrite. It
// must be a regular file (not a link, not a FIFO or device) with exactly
// one name: with one name, the bytes written are reachable only through
// the spool file being purged, never through a hard link the account made
// to a file it cannot write itself.
func openForRewrite(r *os.Root, name string) (*os.File, error) {
	fi, err := r.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !fi.Mode().IsRegular() {
		return nil, errNotOurs
	}
	f, err := r.OpenFile(name, os.O_RDWR|rewriteFlags, 0)
	if err != nil {
		return nil, err
	}
	got, err := f.Stat()
	if err != nil || !got.Mode().IsRegular() || !os.SameFile(fi, got) || linkCount(got) != 1 {
		f.Close()
		return nil, errNotOurs
	}
	return f, nil
}

// blankSpoolDir overwrites the matching complete lines of every spool file
// (*.ndjson) in r.
func blankSpoolDir(r *os.Root, m userMatcher, dry bool) (lines, files int, err error) {
	d, err := r.Open(".")
	if err != nil {
		return 0, 0, err
	}
	ents, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		return 0, 0, err
	}
	for _, e := range ents {
		nm := e.Name()
		if !strings.HasSuffix(nm, ".ndjson") || strings.HasPrefix(nm, ".") || !e.Type().IsRegular() {
			continue
		}
		n, err := blankLines(r, nm, m, dry)
		if err != nil {
			return lines, files, err
		}
		if n > 0 {
			lines += n
			files++
		}
	}
	return lines, files, nil
}

// blankLines overwrites each matching complete line of name with as many
// newlines as it had bytes, in place.
func blankLines(r *os.Root, name string, m userMatcher, dry bool) (int, error) {
	f, err := openForRewrite(r, name)
	if err != nil {
		if errors.Is(err, errNotOurs) || errors.Is(err, fs.ErrNotExist) {
			return 0, nil // a link or a device (the daemon's reader refuses it too), or gone
		}
		return 0, fmt.Errorf("%s: %w", name, err)
	}
	defer f.Close()
	type span struct{ off, n int64 }
	var hits []span
	br := bufio.NewReaderSize(f, 64<<10)
	var off int64
	for {
		l, rerr := br.ReadBytes('\n')
		if len(l) > 0 && l[len(l)-1] == '\n' {
			body := bytes.TrimRight(l, "\r\n")
			if len(body) > 0 && m.match(body) {
				hits = append(hits, span{off, int64(len(l))})
			}
		}
		off += int64(len(l))
		if rerr != nil {
			break
		}
	}
	if dry || len(hits) == 0 {
		return len(hits), nil
	}
	for _, h := range hits {
		if _, err := f.WriteAt(bytes.Repeat([]byte{'\n'}, int(h.n)), h.off); err != nil {
			return 0, fmt.Errorf("%s: %w", f.Name(), err)
		}
	}
	return len(hits), f.Sync()
}

// purgeSpoolState deletes the guard-mode session state files of the
// account's spool (derived from its activity). "state" is opened inside r,
// so a link the account put there cannot lead the removal elsewhere.
func purgeSpoolState(r *os.Root, dry bool) (int, error) {
	sub, err := r.OpenRoot("state")
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, nil
		}
		return 0, nil // a link out of the directory, or not a directory: nothing of ours
	}
	defer sub.Close()
	d, err := sub.Open(".")
	if err != nil {
		return 0, err
	}
	ents, err := d.ReadDir(-1)
	d.Close()
	if err != nil {
		return 0, err
	}
	n := 0
	for _, e := range ents {
		if !e.Type().IsRegular() {
			continue
		}
		n++
		if dry {
			continue
		}
		// Remove unlinks this name only; it never follows a link.
		if err := sub.Remove(e.Name()); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return n, err
		}
	}
	return n, nil
}

// purgeSegments removes matching lines from every segment in dir (or only
// counts them when dry). A segment is rewritten through a temporary file and
// renamed over the original with the original's mode; lines appended while
// it was being filtered are carried over until the size is stable.
func purgeSegments(dir string, m userMatcher, dry bool) (lines, files int, err error) {
	ents, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return 0, 0, nil
	}
	if err != nil {
		return 0, 0, err
	}
	for _, e := range ents {
		if _, ok := sink.ParseSegmentName(e.Name()); !ok || !e.Type().IsRegular() {
			continue
		}
		n, err := purgeSegment(filepath.Join(dir, e.Name()), m, dry)
		if err != nil {
			return lines, files, err
		}
		if n > 0 {
			lines += n
			files++
		}
	}
	return lines, files, nil
}

func purgeSegment(path string, m userMatcher, dry bool) (int, error) {
	f, err := platform.OpenNoFollow(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return 0, err
	}
	var kept bytes.Buffer
	removed := 0
	var off int64
	filter := func() error {
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			return err
		}
		br := bufio.NewReaderSize(f, 64<<10)
		for {
			l, err := br.ReadBytes('\n')
			if len(l) > 0 && l[len(l)-1] == '\n' {
				off += int64(len(l))
				if m.match(bytes.TrimRight(l, "\r\n")) {
					removed++
				} else {
					kept.Write(l)
				}
			} else if len(l) > 0 {
				// A torn last line (writers append whole lines in one
				// write, so only a crash leaves one): kept as it is.
				off += int64(len(l))
				kept.Write(l)
				return nil
			}
			if err != nil {
				return nil
			}
		}
	}
	if err := filter(); err != nil {
		return 0, err
	}
	if dry || removed == 0 {
		return removed, nil
	}
	for i := 0; i < 5; i++ {
		cur, err := os.Lstat(path)
		if err != nil {
			return 0, err
		}
		if cur.Size() == off {
			break
		}
		if err := filter(); err != nil {
			return 0, err
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".purge-*")
	if err != nil {
		return 0, err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if _, err := tmp.Write(kept.Bytes()); err != nil {
		tmp.Close()
		return 0, err
	}
	if err := tmp.Chmod(fi.Mode().Perm()); err != nil {
		tmp.Close()
		return 0, err
	}
	if uid, gid, ok := fileOwner(fi); ok {
		_ = tmp.Chown(uid, gid)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return 0, err
	}
	if err := tmp.Close(); err != nil {
		return 0, err
	}
	return removed, os.Rename(name, path)
}
