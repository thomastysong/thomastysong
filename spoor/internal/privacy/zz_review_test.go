package privacy

// Adversarial review tests. Every test in this file FAILS against the
// current implementation and demonstrates one defect; delete a test once
// its defect is fixed.

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/hookio"
)

// reviewEmitAll emits e under every profile, with and without a key, and
// returns the encoded lines by variant name.
func reviewEmitAll(t *testing.T, e *event.Event) map[string]string {
	t.Helper()
	res := map[string]string{}
	for _, prof := range Profiles {
		for _, key := range [][]byte{nil, testKey} {
			out, _, ok := (&Policy{Profile: prof, Key: key}).Emit(e)
			if !ok {
				continue
			}
			res[string(prof)+map[bool]string{true: "/key", false: "/nokey"}[key != nil]] = line(t, out)
		}
	}
	return res
}

func reviewDetection(session string) *event.Event {
	d := activity(event.TypeDetectionFinding)
	d.Kind = event.KindDetection
	d.Session.ID = session
	d.Detection = &event.Detection{RuleID: "R1", Title: "t", Severity: "high"}
	return d
}

// Defect: the command lexer stops at maxTokens (65536) and render() copies
// the rest of the source verbatim; shellx records at most 2048 commands and
// the syntax-blind view is skipped above 64 KiB, so a secret after the
// token cap is seen by no structural view. MaxField keeps the TAIL of a
// command, so it is emitted - in every profile, in the minimal-profile
// context record and in a minimal-profile detection record (both ship).
func TestReviewTokenCapLeak(t *testing.T) {
	const pw = "SommerZQ2026x"
	cmd := strings.Repeat("true\n", 32768) + "mysql -u root -p" + pw + " -h db prod"
	for name, l := range reviewEmitAll(t, shellEvent(cmd)) {
		if strings.Contains(l, pw) {
			t.Errorf("Emit %s: secret after the token cap leaked", name)
		}
	}
	e := shellEvent(cmd)
	for _, c := range (&Policy{}).Context([]*event.Event{e, reviewDetection(e.Session.ID)}, 5) {
		if strings.Contains(line(t, c), pw) {
			t.Errorf("minimal Context (shipped): secret after the token cap leaked")
		}
	}
	d := reviewDetection(e.Session.ID)
	d.Target = &event.Target{Command: cmd}
	out, ship, _ := (&Policy{}).Emit(d)
	if l := line(t, out); ship && strings.Contains(l, pw) {
		t.Errorf("minimal detection record (shipped): secret after the token cap leaked")
	}
}

// Defect: the stdin-credential rule (specials.go readsSecretFromStdin)
// misses the most common consumers: sudo -S/--stdin, passwd without
// --stdin, kinit, openssl -pass stdin, vault login -.
func TestReviewStdinConsumersLeak(t *testing.T) {
	const pw = "Sommer2026!x"
	for _, c := range []string{
		"echo '" + pw + "' | sudo -S apt-get install -y jq",
		"echo " + pw + " | sudo --stdin systemctl restart nginx",
		"sudo -S <<< '" + pw + "' whoami",
		"printf '%s\\n' " + pw + " | sudo -S -k ls /root",
		"echo -e '" + pw + "\\n" + pw + "' | passwd bob",
		"echo '" + pw + "' | kinit bob@CORP.EXAMPLE",
		"echo " + pw + " | openssl enc -d -pass stdin -in f.enc",
		"echo " + pw + " | vault login -",
	} {
		for name, l := range reviewEmitAll(t, shellEvent(c)) {
			if strings.Contains(l, pw) {
				t.Errorf("%s: %q leaks the password fed on stdin", name, c)
				break
			}
		}
	}
}

// Defect: common secret-bearing flags and positional forms are not
// redacted (classify.RedactArgs tables plus privacy's PowerShell rules),
// so the structural pass the spec requires leaks them.
func TestReviewSecretFlagGaps(t *testing.T) {
	const pw = "Sommer2026x"
	for _, c := range []string{
		"sshpass -p" + pw + " ssh deploy@h",
		"keytool -genkeypair -storepass " + pw + " -keypass " + pw + " -alias a",
		"jarsigner -storepass " + pw + " app.jar alias",
		"sqlcmd -S db -U sa -P " + pw + " -Q 'select 1'",
		"ssh-keygen -t ed25519 -N '" + pw + "' -f id",
		"lftp -u bob," + pw + " sftp://h",
		"smbclient -U 'bob%" + pw + "' //h/share",
		"schtasks /create /tn t /tr x.exe /ru bob /rp " + pw,
		"Set-Item env:API_KEY '" + pw + "'",
		"[Environment]::SetEnvironmentVariable('API_TOKEN','" + pw + "','User')",
	} {
		for name, l := range reviewEmitAll(t, shellEvent(c)) {
			if strings.Contains(l, pw) {
				t.Errorf("%s: %q leaks", name, c)
				break
			}
		}
	}
}

// Defect: credentials written into credential files by the shell (heredoc
// or echo redirection into ~/.netrc, ~/.pgpass, printf format) ship in
// target.command in standard. The write target is a secret-class path, so
// structure is available; Describe also claims "file contents being
// written" never leave in standard.
func TestReviewCredentialFileWriteLeak(t *testing.T) {
	const pw = "Sommer2026x"
	for _, c := range []string{
		"cat > ~/.netrc <<EOF\nmachine git.internal login bob password " + pw + "\nEOF",
		"cat > ~/.pgpass <<'EOF'\ndb.internal:5432:app:app:" + pw + "\nEOF\nchmod 600 ~/.pgpass",
		"echo 'machine h login u password " + pw + "' >> ~/.netrc",
		"echo 'db:5432:app:app:" + pw + "' > ~/.pgpass",
		"printf 'user=app\\npassword=%s\\n' " + pw + " > db.conf",
	} {
		out, _, _ := (&Policy{Profile: ProfileStandard, Key: testKey}).Emit(shellEvent(c))
		if l := line(t, out); strings.Contains(l, pw) {
			t.Errorf("standard: %q leaks the written credential", c)
		}
	}
}

// Defect: producers summarise tool errors as "tool error fp:<8 hex>" (an
// UNKEYED SHA-256 prefix of the error text: hookio failure(), hookio
// denied reasons, otelrecv setError). Emit passes it through in every
// profile, with and without a key, and the minimal-profile context ships
// it, contrary to "content-derived digests are HMAC-SHA-256 with a tenant
// key or are not emitted".
func TestReviewUnkeyedErrorFingerprint(t *testing.T) {
	d, ok := hookio.Get("claude")
	if !ok {
		t.Skip("no claude dialect")
	}
	errText := "Error: permission denied for secret store"
	payload := `{"hook_event_name":"PostToolUseFailure","session_id":"s1","cwd":"/home/bob/w","tool_name":"Read","tool_input":{"file_path":"/home/bob/w/a"},"tool_use_id":"tu1","error":"` + errText + `"}`
	evs, _, err := d.Parse([]byte(payload), nil)
	if err != nil || len(evs) == 0 {
		t.Fatalf("parse: %v %d", err, len(evs))
	}
	sum := sha256.Sum256([]byte(errText))
	fp := hex.EncodeToString(sum[:])[:8]
	for name, l := range reviewEmitAll(t, evs[0]) {
		if strings.Contains(l, fp) {
			t.Errorf("%s: unkeyed fingerprint of tool error text emitted (%s)", name, fp)
		}
	}
	for _, c := range (&Policy{}).Context([]*event.Event{evs[0], reviewDetection(evs[0].Session.ID)}, 3) {
		if strings.Contains(line(t, c), fp) {
			t.Errorf("minimal Context (shipped): unkeyed fingerprint %s", fp)
		}
	}
}

// Defect: sanitizeEvidence passes any non-allowlisted value that parses as
// a float, so numeric content (an OTP in a prompt, a card number in tool
// output, numeric file content) ships as evidence in minimal and standard,
// contrary to the evidence allowlist.
func TestReviewEvidenceNumericContentBypass(t *testing.T) {
	d := reviewDetection("s")
	d.Detection.Evidence = map[string]string{
		"tool.output": "4111111111111111", "prompt.text": "829104", "content.file_content": "31415926535",
	}
	for _, prof := range []Profile{ProfileMinimal, ProfileStandard} {
		out, _, _ := (&Policy{Profile: prof}).Emit(d)
		for k, v := range out.Detection.Evidence {
			if v != Withheld {
				t.Errorf("%s: content evidence %s=%q shipped", prof, k, v)
			}
		}
	}
}

// Defect: render copies the input's Truncated names into r.trunc before
// the safety pass, and finish() writes r.trunc back afterwards, so those
// strings bypass redaction (capped at 64 bytes, which fits a GitHub PAT).
func TestReviewTruncatedBypassesSafetyPass(t *testing.T) {
	tok := "ghp_" + rnd(7, 36)
	e := shellEvent("ls")
	e.Truncated = []string{tok}
	for name, l := range reviewEmitAll(t, e) {
		if strings.Contains(l, tok) {
			t.Errorf("%s: token in the input truncated list emitted verbatim", name)
		}
	}
}

// Defect: fitLine falls back to the skeleton without checking that the
// skeleton itself fits; skeleton fields are capped at 128 raw bytes, which
// encode to 768, so with an allowed MaxLine (MinMaxLine..~13 KiB) the
// returned line exceeds MaxLine.
func TestReviewLineCapSkeletonOverBudget(t *testing.T) {
	lt := strings.Repeat("<", 4000)
	e := activity(event.TypeToolPre)
	e.Kind = event.KindDetection
	e.ID, e.Type, e.Writer, e.Dedupe = lt, lt, lt, lt
	e.Source, e.Fidelity, e.Integrity = event.Source(lt), event.Fidelity(lt), event.Integrity(lt)
	e.Session.ID = lt
	e.Host.ID, e.Host.OS, e.Host.Arch = lt, lt, lt
	e.Agent.ID = lt
	e.Detection = &event.Detection{RuleID: lt, Title: lt, Class: lt, Severity: lt}
	for _, ml := range []int{MinMaxLine, 4096} {
		p := &Policy{Profile: ProfileStandard, MaxLine: ml}
		out, _, _ := p.Emit(e)
		if l := line(t, out); len(l) > ml-LineHeadroom {
			t.Errorf("MaxLine=%d: encoded line is %d bytes", ml, len(l))
		}
	}
}

// Defect: a database URL in a structured value (label, check.actual) comes
// out with a marker nested inside a marker
// ("[REDACTED:database_url_with_password:[REDACTED:password...]") although
// the package and its canary test promise no nested markers.
func TestReviewNestedMarkerInValues(t *testing.T) {
	v := "postgres://app:Sommer2026x@db/x"
	for _, k := range [][]byte{nil, testKey} {
		e := shellEvent("ls")
		e.Labels = map[string]string{"db": v}
		e.Check = &event.Check{ID: "c", Status: "fail", Actual: v}
		out, _, _ := (&Policy{Profile: ProfileStandard, Key: k}).Emit(e)
		if l := line(t, out); nestedMarkerRe.MatchString(l) {
			t.Errorf("key=%v: nested marker emitted: label=%q actual=%q", k != nil, out.Labels["db"], out.Check.Actual)
		}
	}
}

// Defect (API): the spec's Context(prev, n) is what the engine calls with
// its per-session ring (BUILD-C C2 item 9); without the detection appended
// to prev, no record carries labels.context_for, so the shipped context
// cannot be joined to its finding.
func TestReviewContextWithoutDetectionUnlabelled(t *testing.T) {
	ring := []*event.Event{shellEvent("ls"), shellEvent("cat a")}
	for _, c := range (&Policy{}).Context(ring, 5) {
		if c.Labels[LabelContextFor] == "" {
			t.Errorf("context record %s has no %s label", c.ID, LabelContextFor)
		}
	}
}
