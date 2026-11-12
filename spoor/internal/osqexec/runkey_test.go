package osqexec

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/thomastysong/spoor/internal/event"
)

// unkeyedRowKey is what the key of an eid-less row used to be: a plain
// hash of row content, recomputable by anyone who reads the event.
func unkeyedRowKey(r map[string]string) string {
	h := sha256.New()
	for _, f := range []string{r["time"], r["pid"], r["path"], r["cmdline"]} {
		h.Write([]byte(f))
		h.Write([]byte{0})
	}
	return "h" + hex.EncodeToString(h.Sum(nil)[:12])
}

func TestRunKeyDrawnOnce(t *testing.T) {
	k := runKey()
	if len(k) != 32 || bytes.Equal(k, make([]byte, 32)) {
		t.Fatalf("run key is %d bytes or zero", len(k))
	}
	if !bytes.Equal(runKey(), k) {
		t.Fatal("run key changed within one process")
	}
}

// A row without a usable eid is keyed by a digest the log cannot recompute:
// time, pid and path ship in the same record, so a plain hash would let a
// reader confirm a guessed command line (and the password on it).
func TestEIDLessRowKeyed(t *testing.T) {
	secret := "Winter" + "2026!"
	noEID := func(pid int, cmdline string) map[string]string {
		r := auditRow(0, t0-3, pid, 100, "/usr/bin/mysql", cmdline)
		r["eid"] = ""
		return r
	}
	rows := []map[string]string{
		noEID(210, "mysql -uroot -p"+secret+" prod"),
		noEID(211, "mysql -uroot -p"+"Summer"+"2026! prod"),
		auditRow(9, t0-3, 212, 100, "/usr/bin/true", "true"),
	}
	spec := linuxAudit
	a, b := parseRows(&spec, rows), parseRows(&spec, rows)
	if len(a) != 3 {
		t.Fatalf("parsed %d rows", len(a))
	}
	byPID := map[int]rec{}
	for i := range a {
		if a[i].key != b[i].key {
			t.Fatalf("pid %d: key changed within one process", a[i].pid)
		}
		byPID[a[i].pid] = a[i]
	}
	if byPID[212].key != "9" {
		t.Errorf("a row with an eid is keyed by it: %q", byPID[212].key)
	}
	k210, k211 := byPID[210].key, byPID[211].key
	if !strings.HasPrefix(k210, "h") || k210 == k211 {
		t.Fatalf("eid-less keys %q / %q", k210, k211)
	}
	if k210 == unkeyedRowKey(rows[0]) {
		t.Fatal("the eid-less key is still a plain hash of the row")
	}

	f := newFake()
	f.add("process_events", rows...)
	s, _ := newTestSource(t, "linux", f, agentTree)
	evs, err := s.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 3 {
		t.Fatalf("got %d events: %v", len(evs), names(evs))
	}
	for _, ev := range evs {
		if ev.Process.PID != 210 {
			continue
		}
		ts := time.Unix(t0-3, 0).UTC()
		old := event.StableID(ts, event.TypeProcessExec, "osquery", "process_events", unkeyedRowKey(rows[0]), "210")
		if ev.ID == old {
			t.Fatal("the shipped id is still derived from a plain hash of the command line")
		}
		line, err := ev.MarshalLine()
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(line, []byte(secret)) {
			t.Fatalf("the secret reached the event: %s", line)
		}
		sum := sha256.Sum256([]byte(rows[0]["cmdline"]))
		if bytes.Contains(line, []byte(hex.EncodeToString(sum[:4]))) || bytes.Contains(line, []byte(unkeyedRowKey(rows[0])[1:9])) {
			t.Fatalf("an unkeyed digest of the row reached the event: %s", line)
		}
	}

	// The seen set still recognises a replayed eid-less row.
	again, err := s.Poll(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range again {
		if p := ev.Process.PID; p == 210 || p == 211 {
			t.Errorf("pid %d was emitted twice", p)
		}
	}
}

func TestContentRowKeySeparatesFields(t *testing.T) {
	// Field boundaries are part of the key: ("ab","c") and ("a","bc")
	// differ.
	if contentRowKey("ab", "c") == contentRowKey("a", "bc") {
		t.Fatal("field boundaries are not keyed")
	}
	if got := contentRowKey("1", "2", "/x", "y"); len(got) != 25 || got[0] != 'h' {
		t.Fatalf("key %q", got)
	}
	if _, err := strconv.ParseUint(contentRowKey("1")[1:9], 16, 64); err != nil {
		t.Fatalf("key is not hex: %v", err)
	}
}
