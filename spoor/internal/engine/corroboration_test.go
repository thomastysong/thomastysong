package engine

import (
	"reflect"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/event"
)

// TestFinalSummaryWaitsForTranscript is the regression test for the
// real-agent run: the SessionEnd hook record ended the session and its
// final summary was written at once; the transcript tailer delivered the
// session's records 0.2 s later, so the shipped summary said surfaces
// [hook], coverage partial, while the coverage table said covered. The
// final summary now waits for the correlation hold window after the end.
func TestFinalSummaryWaitsForTranscript(t *testing.T) {
	h := newHarness(t, nil)
	h.ingest(
		hook(event.TypeSessionStart, "rt"),
		hook(event.TypePromptSubmit, "rt", prompt("install the helper tool")),
		hook(event.TypeToolPre, "rt", shell("toolu_01", "curl -fsS http://127.0.0.1:47802/i.sh | sh")),
		hook(event.TypeToolPost, "rt", shell("toolu_01", "curl -fsS http://127.0.0.1:47802/i.sh | sh"), output("ran")),
		hook(event.TypeTurnEnd, "rt"),
		hook(event.TypeSessionEnd, "rt"),
	)
	h.tick()
	if n := len(h.out.ofType(event.TypeSessionSummary)); n != 0 {
		t.Fatalf("final summary written when SessionEnd was processed (%d), before the transcript could arrive", n)
	}
	h.advance(200 * time.Millisecond)
	h.ingest(
		transcript(event.TypeToolPre, "rt", shell("toolu_01", "curl -fsS http://127.0.0.1:47802/i.sh | sh")),
		transcript(event.TypeToolPost, "rt", shell("toolu_01", "curl -fsS http://127.0.0.1:47802/i.sh | sh"), output("ran")),
	)
	h.tick()
	if n := len(h.out.ofType(event.TypeSessionSummary)); n != 0 {
		t.Fatalf("final summary written inside the hold window (%d)", n)
	}
	h.advance(HoldFor)
	h.tick()
	sums := h.out.ofType(event.TypeSessionSummary)
	if len(sums) != 1 {
		t.Fatalf("want one final summary after the hold window, got %d:\n%s", len(sums), dump(h.out.all()))
	}
	s := sums[0]
	if !s.Summary.Final || s.Labels["end_reason"] != "session_end" {
		t.Errorf("summary final %v labels %v", s.Summary.Final, s.Labels)
	}
	if !reflect.DeepEqual(s.Summary.Surfaces, []event.Source{event.SourceHook, event.SourceTranscript}) || s.Summary.Coverage != "covered" {
		t.Errorf("summary surfaces %v coverage %q, want [hook transcript] covered", s.Summary.Surfaces, s.Summary.Coverage)
	}
	if s.Summary.ToolCalls["shell"] != 1 {
		t.Errorf("tool calls %v: the transcript twins must not count again", s.Summary.ToolCalls)
	}
	// Nothing supersedes it later: the twins were in time.
	h.advance(SessionIdle + time.Minute)
	h.tick()
	if n := len(h.out.ofType(event.TypeSessionSummary)); n != 1 {
		t.Errorf("a second summary followed (%d): the transcript twins were taken for late records", n)
	}
}

// Closing (a daemon stop, the end of detect or hook mode) does not wait:
// an ended session's final summary is written with reason session_end.
func TestFinalSummaryOnCloseDuringWindow(t *testing.T) {
	h := newHarness(t, nil)
	h.ingest(hook(event.TypeToolPre, "cw", shell("a", "ls")), hook(event.TypeSessionEnd, "cw"))
	h.tick()
	if err := h.p.Close(); err != nil {
		t.Fatal(err)
	}
	sums := h.out.ofType(event.TypeSessionSummary)
	if len(sums) != 1 || !sums[0].Summary.Final || sums[0].Labels["end_reason"] != "session_end" {
		t.Errorf("close during the window: %d summaries %+v", len(sums), sums)
	}
}

func activityOf(h *harness, typ string) []*event.Event {
	return append(h.out.ofType(typ), h.local.ofType(typ)...)
}

// TestCorroborationOnRecords: a twin from another surface collapsed into an
// activity record is in the Sources of the record written when that record
// is still to be written (transcript first and held, or both in one
// processing round), and counted when the record was already written
// (hook first, the transcript a poll later): heartbeat
// correlate.corroborated_after_write and the summary label.
func TestCorroborationOnRecords(t *testing.T) {
	both := []event.Source{event.SourceHook, event.SourceTranscript}

	t.Run("transcript then hook", func(t *testing.T) {
		h := newHarness(t, nil)
		h.ingest(transcript(event.TypeToolPre, "c1", shell("u1", "make")))
		h.advance(time.Second)
		h.tick()
		h.ingest(hook(event.TypeToolPre, "c1", shell("u1", "make")))
		h.tick()
		pre := activityOf(h, event.TypeToolPre)
		if len(pre) != 1 || pre[0].Source != event.SourceHook || !reflect.DeepEqual(pre[0].Sources, both) {
			t.Fatalf("written:\n%s", dump(pre))
		}
		st := h.stats()
		if st["correlate.corroborated"] != 1 || st["correlate.corroborated_after_write"] != 0 {
			t.Errorf("counters corroborated %d after_write %d", st["correlate.corroborated"], st["correlate.corroborated_after_write"])
		}
	})

	t.Run("hook then transcript, already written", func(t *testing.T) {
		h := newHarness(t, nil)
		h.ingest(hook(event.TypeToolPre, "c2", shell("u2", "make")))
		h.tick() // written
		h.advance(200 * time.Millisecond)
		h.ingest(transcript(event.TypeToolPre, "c2", shell("u2", "make")))
		h.ingest(transcript(event.TypeToolPre, "c2", shell("u2", "make"))) // a replay counts once
		h.tick()
		pre := activityOf(h, event.TypeToolPre)
		if len(pre) != 1 || pre[0].Source != event.SourceHook || len(pre[0].Sources) != 0 {
			t.Fatalf("written:\n%s", dump(pre))
		}
		st := h.stats()
		if st["correlate.corroborated"] != 1 || st["correlate.corroborated_after_write"] != 1 {
			t.Errorf("counters corroborated %d after_write %d", st["correlate.corroborated"], st["correlate.corroborated_after_write"])
		}
		h.ingest(hook(event.TypeSessionEnd, "c2"))
		h.endWindow()
		h.tick()
		sums := h.out.ofType(event.TypeSessionSummary)
		if len(sums) != 1 || sums[0].Labels["corroborated"] != "1" || sums[0].Labels["corroborated_after_write"] != "1" {
			t.Errorf("summary labels %v", sums)
		}
	})

	t.Run("hook then transcript, same round", func(t *testing.T) {
		h := newHarness(t, nil)
		h.ingest(
			hook(event.TypeToolPre, "c3", shell("u3", "make")),
			transcript(event.TypeToolPre, "c3", shell("u3", "make")),
		)
		h.tick()
		pre := activityOf(h, event.TypeToolPre)
		if len(pre) != 1 || pre[0].Source != event.SourceHook || !reflect.DeepEqual(pre[0].Sources, both) {
			t.Fatalf("written:\n%s", dump(pre))
		}
		if st := h.stats(); st["correlate.corroborated"] != 1 || st["correlate.corroborated_after_write"] != 0 {
			t.Errorf("counters %d %d", st["correlate.corroborated"], st["correlate.corroborated_after_write"])
		}
	})

	t.Run("late hook after the transcript was released", func(t *testing.T) {
		h := newHarness(t, nil)
		h.ingest(transcript(event.TypeToolPre, "c4", shell("u4", "make")))
		h.advance(HoldFor + time.Second)
		h.tick() // released and written as the transcript's record
		h.ingest(hook(event.TypeToolPre, "c4", shell("u4", "make")))
		h.tick()
		pre := activityOf(h, event.TypeToolPre)
		if len(pre) != 1 || pre[0].Source != event.SourceTranscript {
			t.Fatalf("written:\n%s", dump(pre))
		}
		if st := h.stats(); st["correlate.late_hook"] != 1 || st["correlate.corroborated_after_write"] != 1 {
			t.Errorf("late hook %d after_write %d", st["correlate.late_hook"], st["correlate.corroborated_after_write"])
		}
	})

	t.Run("synthesized start is not corroborated", func(t *testing.T) {
		h := newHarness(t, nil)
		h.ingest(transcript(event.TypeTurnEnd, "c5"))
		h.tick()
		h.ingest(hook(event.TypeSessionStart, "c5"))
		h.tick()
		if st := h.stats(); st["correlate.corroborated"] != 0 {
			t.Errorf("a synthesized session start counted as corroborated: %d", st["correlate.corroborated"])
		}
	})
}
