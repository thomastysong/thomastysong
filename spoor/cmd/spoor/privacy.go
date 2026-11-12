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

	"github.com/thomastysong/spoor/internal/config"
	"github.com/thomastysong/spoor/internal/engine"
	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/platform"
	"github.com/thomastysong/spoor/internal/privacy"
	"github.com/thomastysong/spoor/internal/sink"
	"github.com/thomastysong/spoor/internal/state"
)

func (a *app) cmdPrivacy(args []string) int {
	return a.dispatch("privacy", []subcommand{
		{"show", "what is collected, in which profile, where it goes and how long it is kept", a.privacyShow},
		{"tail", "show the records written about your own sessions", a.privacyTail},
		{"purge", "erase a user's rows from the state database and the local ring", a.privacyPurge},
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
	fs := a.newFlags("privacy show", "privacy show [--json]", "Explains, for the person whose machine this is, what spoor collects here, what leaves the machine, where it goes and how long it is kept.")
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
			"hook_spool":   cfg.Retention.Spool.D().String() + " after it was read",
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
	fmt.Fprintln(a.stdout, "\nYour own records: `spoor privacy tail`. Erasure: `spoor privacy purge --user <name>` (administrator).")
	if v.KillSwitch {
		fmt.Fprintln(a.stdout, "\nThe kill switch is on: nothing is being collected on this machine right now.")
	}
	return exitOK
}

func destinations(cfg *config.Config) []string {
	out := []string{fmt.Sprintf("the outbox %s, which a log shipper on this machine (normally Fluent Bit) forwards to the organisation's log store; spoor does not choose that destination", cfg.OutboxDir())}
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

// recordUser reads the user of one native or OCSF record line.
func recordUser(line []byte) (name, id string) {
	var r struct {
		User *struct {
			Name string `json:"name"`
			ID   string `json:"id"`
		} `json:"user"`
		Actor *struct {
			User *struct {
				Name string `json:"name"`
				UID  string `json:"uid"`
			} `json:"user"`
		} `json:"actor"`
	}
	if json.Unmarshal(line, &r) != nil {
		return "", ""
	}
	if r.User != nil {
		return r.User.Name, r.User.ID
	}
	if r.Actor != nil && r.Actor.User != nil {
		return r.Actor.User.Name, r.Actor.User.UID
	}
	return "", ""
}

// userMatcher decides whether a record belongs to one account: by name, by
// id, or by the keyed pseudonym the policy ships instead of either.
type userMatcher struct {
	names map[string]bool
}

func newUserMatcher(cfg *config.Config, name, uid string) userMatcher {
	m := userMatcher{names: map[string]bool{}}
	for _, v := range []string{name, uid} {
		if v != "" {
			m.names[v] = true
		}
	}
	if cfg.Privacy.PseudonymizeUsers {
		if pol, err := engine.PolicyFromConfig(cfg); err == nil {
			for _, v := range []string{name, uid} {
				if v != "" {
					m.names[pol.Pseudonym(v)] = true
				}
			}
		}
	}
	return m
}

func (m userMatcher) match(line []byte) bool {
	n, id := recordUser(line)
	return (n != "" && m.names[n]) || (id != "" && m.names[id])
}

func (a *app) privacyTail(args []string) int {
	fs := a.newFlags("privacy tail", "privacy tail [--user name] [-n 20] [--follow] [--json]",
		`Shows the records spoor wrote about your own sessions: what was shipped
(outbox) and what stayed on this machine (local ring). Another account's
records need administrator rights (--user). With pseudonymized users the
match needs the tenant key, which only the administrator can read.`)
	var cf cfgFlags
	cf.register(fs)
	user := fs.String("user", "", "account name (default: you; another account needs privilege)")
	n := fs.Int("n", 20, "records to show before following")
	follow := fs.Bool("follow", false, "keep printing new records until interrupted")
	interval := fs.Duration("interval", time.Second, "poll interval with --follow")
	asJSON := fs.Bool("json", false, "print the records as NDJSON")
	if pos, code, done := a.parse(fs, args); done {
		return code
	} else if len(pos) > 0 {
		return a.usageErr("privacy tail", "unexpected argument %q", pos[0])
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
	t := &tailer{dirs: []string{cfg.OutboxDir(), cfg.LocalDir()}, offsets: map[string]int64{}}
	recs, problems := t.poll(m)
	for _, p := range problems {
		a.warn("privacy tail", "%s", p)
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

// tailRecord is one matched line and where it was found.
type tailRecord struct {
	where string // outbox | local
	line  []byte
}

// tailer reads new complete lines of segment files, remembering offsets.
type tailer struct {
	dirs    []string
	offsets map[string]int64
}

func (t *tailer) poll(m userMatcher) ([]tailRecord, []string) {
	var out []tailRecord
	var problems []string
	for i, dir := range t.dirs {
		where := "outbox"
		if i > 0 {
			where = "local"
		}
		ents, err := os.ReadDir(dir)
		if err != nil {
			if errors.Is(err, fs.ErrPermission) {
				problems = append(problems, fmt.Sprintf("%s: permission denied (readable by root and the output group)", dir))
			} else if !errors.Is(err, fs.ErrNotExist) {
				problems = append(problems, err.Error())
			}
			continue
		}
		var names []string
		for _, e := range ents {
			if _, ok := sink.ParseSegmentName(e.Name()); ok && e.Type().IsRegular() {
				names = append(names, e.Name())
			}
		}
		sort.Slice(names, func(i, j int) bool { return segmentOrder(names[i]) < segmentOrder(names[j]) })
		for _, nm := range names {
			p := filepath.Join(dir, nm)
			lines, off, err := readNewLines(p, t.offsets[p])
			if err != nil {
				problems = append(problems, err.Error())
				continue
			}
			t.offsets[p] = off
			for _, l := range lines {
				if m.match(l) {
					out = append(out, tailRecord{where: where, line: l})
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
		fmt.Fprintf(a.stdout, "%-6s %s %-9s %-20s %s\n", r.where, e.TS.Time.UTC().Format(time.RFC3339), e.Kind, clip(e.Type, 20), clip(oneLine(&e), 140))
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
	OutboxLines int      `json:"outbox_lines_not_erased"`
	Notes       []string `json:"notes,omitempty"`
}

func (a *app) privacyPurge(args []string) int {
	fs := a.newFlags("privacy purge", "privacy purge --user name [--dry-run] [--json]",
		`Erases one account's records from this machine: every row of the state
database (secure delete, the write-ahead log is truncated) and every line of
the local ring. Records already shipped must be erased in the log store;
outbox segments are append-only and leave by retention. For a guaranteed
purge of the local ring stop the daemon first: a line it appends while a
segment is rewritten can be missed (it is then removed by retention).`)
	var cf cfgFlags
	cf.register(fs)
	user := fs.String("user", "", "account name or id to erase (required)")
	dry := fs.Bool("dry-run", false, "count what would be erased, change nothing")
	asJSON := fs.Bool("json", false, "print JSON")
	if pos, code, done := a.parse(fs, args); done {
		return code
	} else if len(pos) > 0 {
		return a.usageErr("privacy purge", "unexpected argument %q", pos[0])
	}
	if *user == "" {
		return a.usageErr("privacy purge", "--user is required")
	}
	cfg, _, err := loadConfig(cf)
	if err != nil {
		return a.fail("privacy purge", err)
	}
	res := purgeResult{User: *user, DryRun: *dry}
	m := newUserMatcher(cfg, *user, lookupUID(*user))
	if cfg.Privacy.PseudonymizeUsers && len(m.names) <= 2 {
		res.Notes = append(res.Notes, "users are pseudonymized and the tenant key could not be read: shipped and local records carrying the pseudonym were not matched")
	}
	if *dry {
		res.StateRows = -1
	} else if _, err := os.Stat(cfg.StateDB()); err == nil {
		st, err := state.Open(cfg.StateDB())
		if err != nil {
			return a.fail("privacy purge", fmt.Errorf("state database: %w", err))
		}
		n, perr := st.PurgeUser(*user)
		cerr := st.Close()
		if perr != nil {
			return a.fail("privacy purge", perr)
		}
		if cerr != nil {
			return a.fail("privacy purge", cerr)
		}
		res.StateRows = n
	}
	lines, files, err := purgeSegments(cfg.LocalDir(), m, *dry)
	if err != nil {
		return a.fail("privacy purge", err)
	}
	res.LocalLines, res.LocalFiles = lines, files
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
	fmt.Fprintf(a.stdout, "outbox: %d line(s) of this user remain (append-only, shipped already; erase them in the log store, retention removes the local copy)\n", res.OutboxLines)
	for _, n := range res.Notes {
		fmt.Fprintf(a.stdout, "note: %s\n", n)
	}
	return exitOK
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
				// A partial line being written: keep it for the next pass.
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
