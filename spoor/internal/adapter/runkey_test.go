package adapter

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
)

// sha256Heads returns the hex heads (4 bytes and up) of the unkeyed SHA-256
// of each value: any of them in an emitted record is a guessing oracle.
func sha256Heads(values ...string) []string {
	var out []string
	for _, v := range values {
		sum := sha256.Sum256([]byte(v))
		out = append(out, hex.EncodeToString(sum[:4]))
	}
	return out
}

func encoded(t *testing.T, evs ...*event.Event) string {
	t.Helper()
	var b bytes.Buffer
	for _, e := range evs {
		line, err := json.Marshal(e)
		if err != nil {
			t.Fatal(err)
		}
		b.Write(line)
	}
	return strings.ToLower(b.String())
}

func assertNoOracle(t *testing.T, out string, values ...string) {
	t.Helper()
	for _, h := range sha256Heads(values...) {
		if strings.Contains(out, h) {
			t.Errorf("the output carries %s, the head of an unkeyed SHA-256 of record content", h)
		}
	}
}

func TestRunKeyDrawnOnce(t *testing.T) {
	k := runKey()
	if len(k) != 32 || bytes.Equal(k, make([]byte, 32)) {
		t.Fatalf("run key is %d bytes or zero", len(k))
	}
	if !bytes.Equal(runKey(), k) {
		t.Fatal("run key changed within one process")
	}
	if runDigest(domLine, []byte("x")) == runDigest(domProjectPath, []byte("x")) {
		t.Fatal("digest domains do not separate")
	}
}

// A record without an id of its own gets an id that is stable within the
// process and is not a function of its content alone.
func TestIDLessRecordsKeyed(t *testing.T) {
	cases := map[string]map[string]any{
		"event": eventRecord("prompt.user", map[string]any{"event_id": nil, "content_preview": "deploy the staging build now"}),
		"finding": func() map[string]any {
			f := fixtureMap(t, "numbat_finding_sequence.json")
			delete(f, "finding_id")
			return f
		}(),
		"enforcement": func() map[string]any {
			e := fixtureMap(t, "numbat_enforcement_deny.json")
			delete(e, "decision_id")
			return e
		}(),
	}
	for name, rec := range cases {
		t.Run(name, func(t *testing.T) {
			b := line(t, rec)
			e := one(t, b)
			again := one(t, b)
			if again.ID != e.ID {
				t.Fatal("the id of an id-less record changed within one process")
			}
			// What the id used to be: a pure function of the line.
			sum := sha256.Sum256(b)
			old := event.StableID(e.TS.Time, "numbat", "line", hex.EncodeToString(sum[:16]))
			if e.ID == old {
				t.Fatal("the id is still the unkeyed hash of the line")
			}
			if want := event.StableID(e.TS.Time, "numbat", "line", runDigest(domLine, b)); e.ID != want {
				t.Fatalf("id %s, want the keyed line digest %s", e.ID, want)
			}
			// A different line gets a different id.
			rec2 := map[string]any{}
			for k, v := range rec {
				rec2[k] = v
			}
			rec2["session_id"] = "another-session"
			if other := one(t, line(t, rec2)); other.ID == e.ID {
				t.Fatal("two different id-less records share an id")
			}
			assertNoOracle(t, encoded(t, e), string(b))
		})
	}
}

func TestOversizeStandInKeyed(t *testing.T) {
	r := eventRecord("command.exec", map[string]any{"tool_name": "Bash", "command": "echo " + strings.Repeat("B", MaxNumbatLine)})
	b := line(t, r)
	evs, err := Numbat(b)
	if !errors.Is(err, ErrTooLarge) || len(evs) != 1 {
		t.Fatalf("got %d events, %v", len(evs), err)
	}
	e := evs[0]
	if _, ok := e.Labels["line_sha256"]; ok {
		t.Fatal("the stand-in still carries line_sha256")
	}
	if e.Labels["line_bytes"] != itoa(int64(len(b))) {
		t.Fatalf("line_bytes = %q, want %d", e.Labels["line_bytes"], len(b))
	}
	again, _ := Numbat(b)
	if len(again) != 1 || again[0].ID != e.ID {
		t.Fatal("the stand-in id changed within one process")
	}
	sum := sha256.Sum256(b)
	if e.ID == event.StableID(e.TS.Time, "numbat", "oversize", hex.EncodeToString(sum[:16])) {
		t.Fatal("the stand-in id is still the unkeyed hash of the line")
	}
	assertNoOracle(t, encoded(t, e), string(b))
}

func TestDiffDigestNotRelayed(t *testing.T) {
	diff := "-replicas: 2\n+replicas: 5\n"
	sum := sha256.Sum256([]byte(diff))
	r := eventRecord("file.write", map[string]any{
		"tool_name": "Write", "file_path": "/srv/app/config.yaml",
		"diff_sha256": hex.EncodeToString(sum[:]), "diff_bytes": len(diff),
	})
	e := one(t, line(t, r))
	if _, ok := e.Labels["diff_sha256"]; ok {
		t.Fatal("numbat's unkeyed diff digest was relayed")
	}
	if e.Labels["diff_bytes"] != itoa(int64(len(diff))) {
		t.Fatalf("diff_bytes = %q", e.Labels["diff_bytes"])
	}
	assertNoOracle(t, encoded(t, e), diff)
}

// numbat's project_path_hash is relayed keyed: it joins a finding to the
// indicators of the same project, but is not numbat's lookup key.
func TestProjectPathHashKeyed(t *testing.T) {
	fnd := fixtureMap(t, "numbat_finding_sequence.json")
	ind := fixtureMap(t, "numbat_indicator_url.json")
	raw := fnd["project_path_hash"].(string)
	if ind["sample_project_path_hash"] != raw {
		t.Fatal("fixtures no longer share a project")
	}
	f, i := one(t, line(t, fnd)), one(t, line(t, ind))
	got := f.Labels["project_path_hash"]
	if got == "" || got != i.Labels["project_path_hash"] {
		t.Fatalf("finding %q and indicator %q do not join", got, i.Labels["project_path_hash"])
	}
	hexPart := strings.TrimPrefix(raw, "sha256:")
	out := encoded(t, f, i)
	if strings.Contains(out, hexPart[:8]) {
		t.Fatal("numbat's unsalted project path hash reached the output")
	}
	// A different project keys differently; junk is dropped.
	fnd["project_path_hash"] = "sha256:" + strings.Repeat("ab", 32)
	if other := one(t, line(t, fnd)); other.Labels["project_path_hash"] == got || other.Labels["project_path_hash"] == "" {
		t.Fatalf("other project: %q", other.Labels["project_path_hash"])
	}
	for _, junk := range []string{"/home/alice/src/secret-project", "sha256:xyz", "sha256:" + strings.Repeat("a", 63), strings.Repeat("sha256:", 40)} {
		fnd["project_path_hash"] = junk
		if v := one(t, line(t, fnd)).Labels["project_path_hash"]; v != "" {
			t.Errorf("%q relayed as %q", junk, v)
		}
	}
}

// An indicator's id and Dedupe must not give back the parts of its value
// that are deliberately not shipped (an e-mail's local part, a URL query).
func TestIndicatorIDsKeyed(t *testing.T) {
	ind := func(typ, value string) map[string]any {
		r := fixtureMap(t, "numbat_indicator_url.json")
		r["type"], r["value"] = typ, value
		return r
	}
	// hidden is what this adapter itself leaves out. A URL keeps its query
	// here (events are pre-redaction) and loses it in the privacy stage,
	// so for a URL only the ids are checked.
	for _, c := range []struct{ typ, value, hidden string }{
		{"email", "alice.example@corp.example", "alice.example"},
		{"url", "https://search.example/q?term=layoff+plans+2027", ""},
	} {
		e := one(t, line(t, ind(c.typ, c.value)))
		again := one(t, line(t, ind(c.typ, c.value)))
		if again.ID != e.ID || again.Dedupe != e.Dedupe || e.Dedupe == "" {
			t.Fatalf("%s: indicator ids are not stable within one process", c.typ)
		}
		oldID := numbatID("indicator", "run-example-01\x00"+c.typ+"\x00"+c.value)
		oldDedupe := event.DedupeKey("numbat-indicator", "run-example-01", c.typ, c.value)
		if e.ID == oldID || e.Dedupe == oldDedupe {
			t.Fatalf("%s: id or dedupe is still an unkeyed hash of the value", c.typ)
		}
		out := encoded(t, e)
		if c.hidden != "" && strings.Contains(out, c.hidden) {
			t.Fatalf("%s: %q shipped in clear: %s", c.typ, c.hidden, out)
		}
		assertNoOracle(t, out, c.value, c.typ+"\x00"+c.value)
		other := one(t, line(t, ind(c.typ, c.value+"x")))
		if other.ID == e.ID || other.Dedupe == e.Dedupe {
			t.Fatalf("%s: two values share an id", c.typ)
		}
	}
}
