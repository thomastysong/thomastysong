package state

import (
	"database/sql"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// AgentProcess is one agent root process as the process monitor sees it.
// Nothing from the command line is stored except Flags, the catalog's
// closed list of risky switches.
type AgentProcess struct {
	PID       int
	StartTime time.Time // with PID, the identity of the process
	AgentID   string
	User      string // account name shown in the table
	UserID    string // uid or SID; keys session_ref, never shown
	Exe       string
	Flags     []string
	// SessionID is the agent's own session id when known. Only SessionRef of
	// it is stored.
	SessionID   string
	ContainerID string
}

// refreshEvery is how often an unchanged process or coverage set is written
// anyway, to move last_seen and updated forward.
const refreshEvery = time.Minute

// SetAgentProcesses replaces the set of running agent processes. Processes
// that were running and are not in p stay in the table with running = 0 and
// their last_seen frozen, until Prune removes them after
// Retention.Processes: Fleet looks at a host about once an hour, and a table
// of only the processes alive at that instant could not attribute what ran
// in between.
//
// Calling it with an unchanged set is cheap: the database is written at most
// once a minute in that case.
func (s *Store) SetAgentProcesses(p []AgentProcess) (err error) {
	defer guard(&err)
	t := mustTable("agent_processes")
	now := s.now()
	procs := make([]AgentProcess, 0, len(p))
	for _, ap := range p {
		if ap.PID > 0 {
			procs = append(procs, ap)
		}
	}
	// More live processes than the table may hold: keep the newest.
	sort.SliceStable(procs, func(i, j int) bool { return procs[i].StartTime.After(procs[j].StartTime) })
	if len(procs) > t.rowCap {
		procs = procs[:t.rowCap]
	}

	type rec struct {
		pid                                         int
		start, agent, user, userID, exe, flags, ref string
		container                                   string
	}
	recs := make([]rec, 0, len(procs))
	var sig strings.Builder
	for _, ap := range procs {
		user, userID := clip(ap.User, maxName), clip(ap.UserID, maxName)
		if user == "" {
			user = userID
		}
		if userID == "" {
			userID = user
		}
		agent := clip(ap.AgentID, maxID)
		r := rec{
			pid: ap.PID, start: FormatTime(ap.StartTime), agent: agent, user: user, userID: userID,
			exe: clip(ap.Exe, maxPath), flags: joinList(ap.Flags),
			ref: SessionRef(userID, agent, ap.SessionID), container: clip(ap.ContainerID, maxID),
		}
		recs = append(recs, r)
		sig.WriteString(fingerprint(r.pid, r.start, r.agent, r.user, r.userID, r.exe, r.flags, r.ref, r.container))
	}

	s.mu.Lock()
	unchanged := sig.String() == s.procSig && !s.procAt.IsZero() && now.Sub(s.procAt) < refreshEvery && !now.Before(s.procAt)
	s.mu.Unlock()
	if unchanged {
		return nil
	}

	ctx, cancel := opContext()
	defer cancel()
	at := FormatTime(now)
	err = s.write(ctx, func(tx *sql.Tx) error {
		b := newBatch(ctx, tx, s)
		defer b.close()
		if _, err := b.exec(`UPDATE agent_processes SET running = 0 WHERE running != 0`); err != nil {
			return err
		}
		for _, r := range recs {
			first := at
			st, err := b.stmt(`SELECT first_seen FROM agent_processes WHERE pid = ? AND start_time = ?`)
			if err != nil {
				return err
			}
			var prev string
			switch err := st.QueryRowContext(ctx, r.pid, r.start).Scan(&prev); {
			case errors.Is(err, sql.ErrNoRows):
			case err != nil:
				return err
			case prev != "" && prev < first:
				first = prev
			}
			row := &row{}
			row.set("pid", r.pid)
			row.set("start_time", r.start)
			row.set("agent_id", r.agent)
			row.set("user", r.user)
			row.set("exe", r.exe)
			row.set("flags", r.flags)
			row.set("session_ref", r.ref)
			row.set("container_id", r.container)
			row.set("first_seen", first)
			row.set("last_seen", at)
			row.set("running", 1)
			row.set("user_id", r.userID)
			if err := b.upsert(t, row); err != nil {
				return err
			}
		}
		return b.enforceCap(t)
	})
	if err == nil {
		s.mu.Lock()
		s.procSig, s.procAt = sig.String(), now
		s.mu.Unlock()
	}
	return err
}

// SetCoverage replaces the coverage table with c, the complete per-agent,
// per-user visibility statement. Like SetAgentProcesses, an unchanged set is
// rewritten at most once a minute.
func (s *Store) SetCoverage(c []event.Coverage) (err error) {
	defer guard(&err)
	t := mustTable("coverage")
	now := s.now()
	type key struct{ agent, user string }
	index := map[key]int{}
	var rows []*row
	var sigParts []string
	for _, cv := range c {
		agent, user := clip(cv.AgentID, maxID), clip(cv.User, maxName)
		if agent == "" {
			continue
		}
		r := &row{}
		r.set("agent_id", agent)
		r.set("user", user)
		r.set("hooks", clip(cv.Hooks, maxID))
		r.set("transcript", clip(cv.Transcript, maxID))
		r.set("processes", max(cv.Processes, 0))
		r.set("state", clip(cv.State, maxID))
		// Two statements for one agent and user: the later one stands.
		if i, ok := index[key{agent, user}]; ok {
			rows[i] = r
			sigParts[i] = fingerprint(r.vals...)
			continue
		}
		index[key{agent, user}] = len(rows)
		rows = append(rows, r)
		sigParts = append(sigParts, fingerprint(r.vals...))
	}
	if len(rows) > t.rowCap {
		rows, sigParts = rows[:t.rowCap], sigParts[:t.rowCap]
	}
	sig := strings.Join(sigParts, "")

	s.mu.Lock()
	unchanged := sig == s.covSig && !s.covAt.IsZero() && now.Sub(s.covAt) < refreshEvery && !now.Before(s.covAt)
	s.mu.Unlock()
	if unchanged {
		return nil
	}

	ctx, cancel := opContext()
	defer cancel()
	at := FormatTime(now)
	err = s.write(ctx, func(tx *sql.Tx) error {
		b := newBatch(ctx, tx, s)
		defer b.close()
		if _, err := b.exec(`DELETE FROM coverage`); err != nil {
			return err
		}
		for _, r := range rows {
			r.set("updated", at)
			if err := b.upsert(t, r); err != nil {
				return err
			}
		}
		return nil
	})
	if err == nil {
		s.mu.Lock()
		s.covSig, s.covAt = sig, now
		s.mu.Unlock()
	}
	return err
}
