package state

import (
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/thomastysong/spoor/internal/event"
)

// applyCheck keeps the posture table equal to "checks that currently fail":
// fail upserts, pass deletes, anything else (unknown) leaves the row as it
// was so an unreadable file does not clear a finding.
func (b *batch) applyCheck(e *event.Event, now time.Time, scanSeq int64) (bool, error) {
	c := e.Check
	id := clip(c.ID, maxID)
	if id == "" {
		return false, nil
	}
	owner := clip(c.Owner, maxName)
	ownerID := ""
	if e.User != nil {
		name, uid := userOf(e.User)
		if owner == "" {
			owner = name
		}
		if owner == name {
			ownerID = uid
		}
	}
	keyVals := []any{
		id, clip(c.AgentID, maxID), clip(c.AssetID, maxID), clip(string(c.Scope), maxID),
		clip(c.Subject, maxPath), owner,
	}
	const where = ` WHERE check_id = ? AND agent_id = ? AND asset_id = ? AND scope = ? AND subject = ? AND owner = ?`
	switch c.Status {
	case "pass":
		_, err := b.exec(`DELETE FROM posture`+where, keyVals...)
		return true, err
	case "fail":
	default:
		return true, nil
	}
	seen := stamp(e.TS.Time, now)
	first, last := seen, seen
	st, err := b.stmt(`SELECT first_seen, last_seen FROM posture` + where)
	if err != nil {
		return false, err
	}
	var pf, pl string
	switch err := st.QueryRowContext(b.ctx, keyVals...).Scan(&pf, &pl); {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return false, err
	default:
		if pf != "" && pf < first {
			first = pf
		}
		if pl > last {
			last = pl
		}
	}
	r := &row{}
	for i, k := range mustTable("posture").key {
		r.set(k, keyVals[i])
	}
	r.set("title", clip(c.Title, maxName))
	r.set("severity", clip(c.Severity, maxID))
	r.set("actual", clip(c.Actual, maxName))
	r.set("remedy", clip(c.Remedy, maxText))
	r.set("first_seen", first)
	r.set("last_seen", last)
	r.set("owner_id", ownerID)
	// Checks applied now belong to the scan in progress, which becomes
	// scanSeq+1 when MarkScan completes it.
	r.set("seen_scan", scanSeq+1)
	return true, b.upsert(mustTable("posture"), r)
}

// applyDetection stores one finding. Rows are aggregated so a noisy rule
// cannot fill the capped table:
//
//   - the same event id again (an at-least-once replay) rewrites its row and
//     never lowers the count;
//   - a different event with the same dedup key, rule and user folds into the
//     existing row: counts add up and the row moves to the newer event.
//
// The fold is scoped by user so one account's findings are never merged
// into, or erased with, another's.
func (b *batch) applyDetection(e *event.Event, now time.Time) (bool, error) {
	d := e.Detection
	eventID, rule := clip(e.ID, maxID), clip(d.RuleID, maxID)
	if eventID == "" || rule == "" {
		return false, nil
	}
	user, userID := userOf(e.User)
	agent := ""
	if e.Agent != nil {
		agent = clip(e.Agent.ID, maxID)
	}
	ref := ""
	if e.Session != nil {
		ref = SessionRef(userID, agent, e.Session.ID)
	}
	ts := stamp(e.TS.Time, now)
	count := max(d.Count, 1)
	dedup := clip(d.DedupKey, maxName)
	t := mustTable("detections")

	fresh := &row{}
	fresh.set("event_id", eventID)
	fresh.set("ts", ts)
	fresh.set("rule_id", rule)
	fresh.set("title", clip(d.Title, maxName))
	fresh.set("severity", clip(d.Severity, maxID))
	fresh.set("confidence", clip(d.Confidence, maxID))
	fresh.set("maturity", clip(d.Maturity, maxID))
	fresh.set("category", clip(d.Category, maxID))
	fresh.set("tags", joinList(d.Tags))
	fresh.set("agent_id", agent)
	fresh.set("user", user)
	fresh.set("session_ref", ref)
	fresh.set("integrity", clip(string(e.Integrity), maxID))
	fresh.set("response", clip(d.Response, maxID))
	fresh.set("enforced", boolInt(d.Enforced))
	fresh.set("dedup_key", dedup)
	fresh.set("user_id", userID)

	// Replay of an event already stored.
	st, err := b.stmt(`SELECT "count" FROM detections WHERE event_id = ?`)
	if err != nil {
		return false, err
	}
	var have int
	switch err := st.QueryRowContext(b.ctx, eventID).Scan(&have); {
	case err == nil:
		fresh.set("count", max(have, count))
		return true, b.upsert(t, fresh)
	case !errors.Is(err, sql.ErrNoRows):
		return false, err
	}

	if dedup != "" {
		st, err := b.stmt(`SELECT rowid, ts, "count" FROM detections
			WHERE dedup_key = ? AND rule_id = ? AND user = ? ORDER BY ts DESC LIMIT 1`)
		if err != nil {
			return false, err
		}
		var rowid int64
		var prevTS string
		switch err := st.QueryRowContext(b.ctx, dedup, rule, user).Scan(&rowid, &prevTS, &have); {
		case err == nil:
			if prevTS > ts {
				// An older occurrence arriving late adds to the count but
				// must not drag the row back in time.
				_, err := b.exec(`UPDATE detections SET "count" = "count" + ? WHERE rowid = ?`, count, rowid)
				return true, err
			}
			fresh.set("count", have+count)
			sets := make([]string, len(fresh.cols))
			for i, c := range fresh.cols {
				sets[i] = quoteIdent(c) + " = ?"
			}
			_, err := b.exec("UPDATE detections SET "+strings.Join(sets, ", ")+" WHERE rowid = ?",
				append(append([]any{}, fresh.vals...), rowid)...)
			return true, err
		case !errors.Is(err, sql.ErrNoRows):
			return false, err
		}
	}
	fresh.set("count", count)
	return true, b.upsert(t, fresh)
}

// applySummary upserts the session row from a session summary. Summaries
// are cumulative and may arrive more than once or out of order, so counts
// and severity only ever move up and the time window only ever widens.
func (b *batch) applySummary(e *event.Event, now time.Time) (bool, error) {
	if e.Session == nil || e.Session.ID == "" {
		return false, nil
	}
	sum := e.Summary
	user, userID := userOf(e.User)
	agent := ""
	if e.Agent != nil {
		agent = clip(e.Agent.ID, maxID)
	}
	ref := SessionRef(userID, agent, e.Session.ID)
	at := stamp(e.TS.Time, now)
	started := optStamp(sum.Started.Time, now)
	if started == "" {
		started = at
	}
	last := optStamp(sum.Ended.Time, now)
	if last == "" {
		last = at
	}
	calls := 0
	for _, n := range sum.ToolCalls {
		if n > 0 {
			calls += n
		}
	}
	dets := len(sum.Detections)
	severity := clip(sum.MaxSeverity, maxID)
	mode := clip(e.Session.PermissionMode, maxID)
	coverage := clip(sum.Coverage, maxID)
	var sources []string
	for _, s := range sum.Surfaces {
		sources = append(sources, string(s))
	}
	if len(sources) == 0 {
		for _, s := range e.Sources {
			sources = append(sources, string(s))
		}
	}

	st, err := b.stmt(`SELECT started, last_event, permission_mode, tool_calls, detections, max_severity, sources, coverage
		FROM sessions WHERE session_ref = ?`)
	if err != nil {
		return false, err
	}
	var ps, pl, pm, psev, psrc, pcov string
	var pcalls, pdets int
	switch err := st.QueryRowContext(b.ctx, ref).Scan(&ps, &pl, &pm, &pcalls, &pdets, &psev, &psrc, &pcov); {
	case errors.Is(err, sql.ErrNoRows):
	case err != nil:
		return false, err
	default:
		if ps != "" && ps < started {
			started = ps
		}
		newer := last >= pl
		if pl > last {
			last = pl
		}
		calls, dets = max(calls, pcalls), max(dets, pdets)
		if event.SeverityRank(psev) > event.SeverityRank(severity) {
			severity = psev
		}
		// Mode and coverage are states, not totals: the newer record wins,
		// and an empty value never erases a known one.
		if mode == "" || !newer {
			mode = firstNonEmpty(pm, mode)
		}
		if coverage == "" || !newer {
			coverage = firstNonEmpty(pcov, coverage)
		}
		if psrc != "" {
			sources = append(strings.Split(psrc, ","), sources...)
		}
	}

	r := &row{}
	r.set("session_ref", ref)
	r.set("agent_id", agent)
	r.set("user", user)
	r.set("started", started)
	r.set("last_event", last)
	r.set("permission_mode", mode)
	r.set("tool_calls", calls)
	r.set("detections", dets)
	r.set("max_severity", severity)
	r.set("sources", joinList(unique(sources)))
	r.set("coverage", coverage)
	r.set("user_id", userID)
	return true, b.upsert(mustTable("sessions"), r)
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// unique drops repeats, keeping first-seen order.
func unique(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := in[:0:0]
	for _, v := range in {
		if v == "" || v == "..." || seen[v] {
			continue
		}
		seen[v] = true
		out = append(out, v)
	}
	return out
}
