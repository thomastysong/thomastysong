package privacy

import (
	"fmt"
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/rules"
)

// packVersions builds a rules.Set.Version-shaped string for n packs
// (17 to 18 bytes per pack: 40 packs are 749 bytes, 60 are over 1 KiB).
func packVersions(n int) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = fmt.Sprintf("pack-%02d@2026.11.%d", i, i)
	}
	return strings.Join(parts, ",")
}

// versionOfLen builds a valid version string of exactly n bytes (n >= 3).
func versionOfLen(n int) string {
	var b strings.Builder
	for i := 0; ; i++ {
		entry := fmt.Sprintf("p%d@1", i)
		if b.Len() > 0 {
			entry = "," + entry
		}
		if rest := n - b.Len(); rest < len(entry)+6 {
			// Pad the last version to land exactly on n.
			if b.Len() > 0 {
				b.WriteString(",")
				rest--
			}
			b.WriteString("z@")
			b.WriteString(strings.Repeat("9", rest-2))
			return b.String()
		}
		b.WriteString(entry)
	}
}

func TestValidRulesVersion(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"a@1", true},
		{"agent-integrity@2026.11.0,coverage@2026.11.0", true},
		{"my_pack.v2@1.0.0-rc.1+build.5", true},
		{"p@V1", true},
		{packVersions(13), true},
		{packVersions(40), true}, // under 1 KiB
		{versionOfLen(maxVersionLabel), true},
		{versionOfLen(maxVersionLabel + 1), false},
		{strings.Repeat("a", 64) + "@" + strings.Repeat("1", 64), true},
		{"", false},
		{"a", false},
		{"a@", false},
		{"@1", false},
		{"A@1", false},      // pack names are lower-case
		{"a@1,", false},     // trailing separator
		{",a@1", false},     // empty entry
		{"a@1,,b@2", false}, // empty entry
		{"a@1 b@2", false},
		{"a@1;rm -rf /", false},
		{"a@b@c", false},
		{"a@1\n", false},
		{"a@1,b", false},
		{"pack@1.0/../x", false},
		{"pack@1:2", false},
		{"pàck@1", false},
		{"a@1\x00", false},
		{strings.Repeat("a", 65) + "@1", false},
		{"a@" + strings.Repeat("1", 65), false},
		{packVersions(60), false}, // over 1 KiB
	}
	for _, n := range []int{3, 100, maxVersionLabel, maxVersionLabel + 1} {
		if got := len(versionOfLen(n)); got != n {
			t.Fatalf("versionOfLen(%d) has %d bytes", n, got)
		}
	}
	for _, c := range cases {
		if got := validRulesVersion(c.in); got != c.want {
			t.Errorf("validRulesVersion(%q) = %v, want %v", short(c.in), got, c.want)
		}
	}
	for in, want := range map[string]bool{
		"0123456789ab": true, strings.Repeat("f", 128): true,
		"": false, "0123456789AB": false, "xyz": false, strings.Repeat("f", 129): false, "01 23": false,
	} {
		if got := validHexLabel(in); got != want {
			t.Errorf("validHexLabel(%q) = %v, want %v", in, got, want)
		}
	}
	if _, ok := versionLabelCap("bundle_version", "a@1"); ok {
		t.Error("only rules_version and rules_hash are exempt")
	}
}

func detectionWithLabels(labels map[string]string) *event.Event {
	d := event.New(event.KindDetection, event.TypeDetectionFinding, event.SourceSensor)
	d.Host = &event.Host{ID: "host-1", OS: "linux"}
	d.User = &event.User{Name: "bob", ID: "1000"}
	d.Detection = &event.Detection{RuleID: "SPR-X-001", Title: "t", Severity: "high"}
	d.Labels = labels
	return d
}

func hasTrunc(e *event.Event, name string) bool {
	for _, t := range e.Truncated {
		if t == name {
			return true
		}
	}
	return false
}

// TestVersionLabelSurvivesEmit: a version string of any realistic pack
// count leaves intact, in every profile, on findings and on heartbeats,
// whenever the operator's field cap allows it (the default 4 KiB always
// does); under a smaller MaxField it is cut to that cap and named in
// "truncated". Other labels keep the 256-byte cap.
func TestVersionLabelSurvivesEmit(t *testing.T) {
	set, err := rules.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	real := set.Version()
	t.Logf("embedded rules_version: %d packs, %d bytes", strings.Count(real, ",")+1, len(real))
	versions := []string{real, packVersions(1), packVersions(12), packVersions(13), packVersions(20), packVersions(40), versionOfLen(maxVersionLabel)}
	long := strings.Repeat("x", 600)
	for _, prof := range Profiles {
		for _, mf := range []int{0, MinMaxField, 512, maxVersionLabel} {
			for _, kind := range []event.Kind{event.KindDetection, event.KindHealth} {
				for _, v := range versions {
					p := &Policy{Profile: prof, Key: testKey, KeyID: "k1", PseudonymizeUsers: true, MaxField: mf}
					fieldCap := p.settings().maxField
					e := detectionWithLabels(map[string]string{
						labelRulesVersion: v, labelRulesHash: "0123456789ab", "other": long,
					})
					e.Kind = kind
					out, _, ok := p.Emit(e)
					if !ok {
						t.Fatalf("%s: dropped", prof)
					}
					got := out.Labels[labelRulesVersion]
					if len(v) <= fieldCap {
						if got != v {
							t.Errorf("%s maxField %d %s, %d bytes: rules_version became %q", prof, mf, kind, len(v), short(got))
						}
						if hasTrunc(out, "labels."+labelRulesVersion) {
							t.Errorf("%s: rules_version listed as truncated", prof)
						}
					} else {
						if len(got) > fieldCap || !hasTrunc(out, "labels."+labelRulesVersion) {
							t.Errorf("%s maxField %d %s: %d-byte rules_version kept %d bytes, truncated %v", prof, mf, kind, len(v), len(got), out.Truncated)
						}
						if head := got[:strings.Index(got, truncOpen)]; len(head) < fieldCap/3 || !strings.HasPrefix(v, head) {
							t.Errorf("%s maxField %d: cut rules_version lost its head: %q", prof, mf, short(got))
						}
					}
					if out.Labels[labelRulesHash] != "0123456789ab" {
						t.Errorf("%s: rules_hash became %q", prof, out.Labels[labelRulesHash])
					}
					if n := len(out.Labels["other"]); n > maxNameLen || !hasTrunc(out, "labels.other") {
						t.Errorf("%s: free-text label kept %d bytes", prof, n)
					}
				}
			}
		}
	}
	if len(real) <= maxNameLen {
		t.Logf("note: embedded rules_version is under the free-text cap today")
	}
	if len(real) > DefaultMaxField/4 {
		t.Errorf("embedded rules_version is %d bytes, close to the default field cap", len(real))
	}
}

// TestVersionLabelWithinMaxField: no string of the record, the version
// labels included, exceeds the operator's MaxField.
func TestVersionLabelWithinMaxField(t *testing.T) {
	for _, mf := range []int{MinMaxField, 300, 512, maxVersionLabel - 1} {
		for _, prof := range Profiles {
			p := &Policy{Profile: prof, MaxField: mf}
			out, _, ok := p.Emit(detectionWithLabels(map[string]string{
				labelRulesVersion: versionOfLen(maxVersionLabel), labelRulesHash: strings.Repeat("f", maxHashLabel),
			}))
			if !ok {
				t.Fatal("dropped")
			}
			for _, sl := range collectSlots(out) {
				if n := len(sl.get()); n > mf {
					t.Errorf("%s MaxField %d: %s is %d bytes", prof, mf, sl.name, n)
				}
			}
			if !hasTrunc(out, "labels."+labelRulesVersion) {
				t.Errorf("%s MaxField %d: cut not named in truncated %v", prof, mf, out.Truncated)
			}
		}
	}
}

// TestVersionLabelOutsideVocabulary: anything that is not a version string
// under these keys is free text with the free-text cap, and the larger
// bound is not a way around redaction.
func TestVersionLabelOutsideVocabulary(t *testing.T) {
	// An access-key-shaped value, built at run time.
	akid := "AK" + "IA" + strings.ToUpper(rnd(41, 16))
	pw := "VerPw" + "1"
	cases := map[string]struct {
		key, value string
		gone       string // must not appear in the output
	}{
		"prose":            {labelRulesVersion, "packs: " + strings.Repeat("see the wiki page for details ", 20), ""},
		"over bound":       {labelRulesVersion, packVersions(60), ""},
		"other key":        {"bundle_version", packVersions(30), ""},
		"credential":       {labelRulesVersion, packVersions(20) + ",aws@" + akid, akid},
		"hash not hex":     {labelRulesHash, strings.Repeat("g", 600), ""},
		"url in version":   {labelRulesVersion, "p@1,https://" + "user:" + pw + "@h.example/x?token=" + rnd(42, 30), pw},
		"newline injected": {labelRulesVersion, packVersions(5) + "\n" + strings.Repeat("z", 400), ""},
	}
	for name, c := range cases {
		for _, prof := range Profiles {
			p := &Policy{Profile: prof, Key: testKey}
			out, _, ok := p.Emit(detectionWithLabels(map[string]string{c.key: c.value}))
			if !ok {
				t.Fatalf("%s: dropped", name)
			}
			got := out.Labels[c.key]
			if len(got) > maxNameLen {
				t.Errorf("%s %s: %d bytes kept, free-text cap is %d", name, prof, len(got), maxNameLen)
			}
			if c.gone != "" && strings.Contains(line(t, out), c.gone) {
				t.Errorf("%s %s: secret survived: %q", name, prof, got)
			}
			if len(c.value) > maxNameLen && !hasTrunc(out, "labels."+c.key) {
				t.Errorf("%s %s: cut not named in truncated %v", name, prof, out.Truncated)
			}
		}
	}
}

// TestVersionLabelLineCap: the exemption raises a field cap, not the line
// cap: a record at the smallest line size still fits.
func TestVersionLabelLineCap(t *testing.T) {
	v := versionOfLen(maxVersionLabel)
	e := detectionWithLabels(map[string]string{labelRulesVersion: v})
	e.Target = &event.Target{Command: strings.Repeat("echo hello; ", 400), Paths: []string{strings.Repeat("/srv/x", 200)}}
	e.Detection.Evidence = map[string]string{"target.command": strings.Repeat("ls ", 500)}
	p := &Policy{Profile: ProfileStandard, MaxLine: MinMaxLine}
	out, _, ok := p.Emit(e)
	if !ok {
		t.Fatal("dropped")
	}
	if l := line(t, out); len(l) > MinMaxLine-LineHeadroom {
		t.Fatalf("line %d bytes over cap %d", len(l), MinMaxLine-LineHeadroom)
	}
	// A lone version label fits a minimal line whole.
	out, _, _ = p.Emit(detectionWithLabels(map[string]string{labelRulesVersion: v}))
	if out.Labels[labelRulesVersion] != v {
		t.Errorf("lone version label cut at the smallest line: %d bytes", len(out.Labels[labelRulesVersion]))
	}
}
