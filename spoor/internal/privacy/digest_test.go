package privacy

import (
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
)

func TestPseudonymStableAndKeyed(t *testing.T) {
	k1 := &Policy{Key: testKey, PseudonymizeUsers: true}
	k1b := &Policy{Key: append([]byte(nil), testKey...), PseudonymizeUsers: true}
	k2 := &Policy{Key: []byte("another-tenant-key-0123456789"), PseudonymizeUsers: true}
	a, b := k1.Pseudonym("bob"), k1b.Pseudonym("bob")
	if a == "" || a != b {
		t.Fatalf("pseudonym not stable: %q %q", a, b)
	}
	if !strings.HasPrefix(a, "u_") || len(a) != 18 {
		t.Errorf("pseudonym format %q", a)
	}
	if k2.Pseudonym("bob") == a {
		t.Error("pseudonyms must differ across keys")
	}
	if k1.Pseudonym("alice") == a {
		t.Error("pseudonyms must differ across names")
	}
	if (&Policy{}).Pseudonym("bob") != "" {
		t.Error("no key, no pseudonym")
	}
	if (&Policy{Key: []byte("short")}).Pseudonym("bob") != "" {
		t.Error("a key below MinKeyLen must be ignored")
	}

	e := activity(event.TypeToolPre)
	e.Process = &event.Process{User: "bob", Args: []string{"cat", "/home/carol/notes.txt", "/home/bob/x"}}
	out, _, _ := (&Policy{Profile: ProfileStandard, Key: testKey, KeyID: "k1", PseudonymizeUsers: true}).Emit(e)
	l := line(t, out)
	if strings.Contains(l, `"bob"`) || strings.Contains(l, "carol") {
		t.Errorf("names survived pseudonymization:\n%s", l)
	}
	if out.User.Name != a || out.User.ID != a || out.Process.User != a {
		t.Errorf("identity fields not pseudonymized consistently: %+v %+v", out.User, out.Process)
	}
	if !strings.Contains(l, "~/x") || !strings.Contains(l, "~"+k1.Pseudonym("carol")+"/notes.txt") {
		t.Errorf("home paths not rewritten:\n%s", l)
	}
	if out.Labels["key_id"] != "k1" {
		t.Errorf("key_id label missing: %v", out.Labels)
	}

	// Pseudonyms requested without a key: names are removed, never hashed
	// without a key.
	out, _, _ = (&Policy{Profile: ProfileStandard, PseudonymizeUsers: true}).Emit(activity(event.TypeToolPre))
	if out.User.Name != "" || out.User.ID != "" {
		t.Errorf("names must be removed without a key: %+v", out.User)
	}
}

func TestContentDigests(t *testing.T) {
	long := strings.Repeat("make the tests pass please ", 3)
	mk := func(text string) *event.Event {
		e := activity(event.TypePromptSubmit)
		e.Prompt = &event.Prompt{Len: len(text), SHA256: sha256Hex(text)}
		e.Content = &event.Content{PromptText: text}
		return e
	}
	nokey := &Policy{Profile: ProfileStandard}
	keyed := &Policy{Profile: ProfileStandard, Key: testKey, KeyID: "k1"}
	other := &Policy{Profile: ProfileStandard, Key: []byte("another-tenant-key-0123456789")}

	out, _, _ := nokey.Emit(mk(long))
	if out.Prompt.SHA256 != "" {
		t.Errorf("no key: digest must not be emitted, got %q", out.Prompt.SHA256)
	}
	o1, _, _ := keyed.Emit(mk(long))
	o2, _, _ := keyed.Emit(mk(long))
	o3, _, _ := other.Emit(mk(long))
	if o1.Prompt.SHA256 == "" || o1.Prompt.SHA256 != o2.Prompt.SHA256 {
		t.Errorf("keyed digest not stable: %q %q", o1.Prompt.SHA256, o2.Prompt.SHA256)
	}
	if o1.Prompt.SHA256 == o3.Prompt.SHA256 {
		t.Error("digests must differ across keys")
	}
	if o1.Prompt.SHA256 == sha256Hex(long) || strings.HasPrefix(sha256Hex(long), o1.Prompt.SHA256) {
		t.Error("digest is the unkeyed hash")
	}
	if len(o1.Prompt.SHA256) != digestHex {
		t.Errorf("digest length %d", len(o1.Prompt.SHA256))
	}
	short, _, _ := keyed.Emit(mk("yes"))
	if short.Prompt.SHA256 != "" {
		t.Error("values under 32 characters get no digest")
	}
	if short.Prompt.Len != 4 || o1.Prompt.Len != 256 {
		t.Errorf("lengths not bucketed: %d %d", short.Prompt.Len, o1.Prompt.Len)
	}
	full, _, _ := (&Policy{Profile: ProfileFull, Key: testKey}).Emit(mk(long))
	if full.Prompt.Len != len(long) {
		t.Errorf("full keeps exact length, got %d", full.Prompt.Len)
	}

	// The same value seen without content (hash only) gets the same keyed
	// digest as with content.
	hashOnly := mk(long)
	hashOnly.Content = nil
	o4, _, _ := keyed.Emit(hashOnly)
	if o4.Prompt.SHA256 != o1.Prompt.SHA256 {
		t.Errorf("hash-only digest %q != content digest %q", o4.Prompt.SHA256, o1.Prompt.SHA256)
	}

	// Tool input and output digests follow the same rule.
	e := shellEvent("ls -la " + strings.Repeat("/very/long/path ", 4))
	e.Content.ToolOutput = strings.Repeat("total 0\n", 10)
	e.Tool.InputSHA256 = sha256Hex("whatever-normalizer-hash")
	te, _, _ := keyed.Emit(e)
	if te.Tool.InputSHA256 == "" || te.Tool.OutputSHA256 == "" || te.Tool.InputSHA256 == e.Tool.InputSHA256 {
		t.Errorf("tool digests: %+v", te.Tool)
	}
	if te.Tool.OutputLen != 256 {
		t.Errorf("output len bucket = %d", te.Tool.OutputLen)
	}
	tn, _, _ := nokey.Emit(e)
	if tn.Tool.InputSHA256 != "" || tn.Tool.OutputSHA256 != "" {
		t.Errorf("no key: tool digests must be empty: %+v", tn.Tool)
	}
}

func TestAccountAssetDedupDigests(t *testing.T) {
	e := event.New(event.KindDetection, event.TypeDetectionFinding, event.SourceSensor)
	e.Account = &event.Account{ID: "acct-0001-personal", Kind: "personal"}
	e.Detection = &event.Detection{RuleID: "R", Title: "t", Severity: "low", DedupKey: "R|rm -rf /"}
	std, _, _ := (&Policy{Profile: ProfileStandard}).Emit(e)
	if std.Account.ID != "" || std.Detection.DedupKey != "" {
		t.Errorf("no key: account id and dedup key must go: %+v %+v", std.Account, std.Detection)
	}
	k, _, _ := (&Policy{Profile: ProfileStandard, Key: testKey}).Emit(e)
	if !strings.HasPrefix(k.Account.ID, "a_") || k.Detection.DedupKey == "" || strings.Contains(k.Detection.DedupKey, "rm") {
		t.Errorf("keyed: %+v %+v", k.Account, k.Detection)
	}
	full, _, _ := (&Policy{Profile: ProfileFull}).Emit(e)
	if full.Account.ID != "acct-0001-personal" {
		t.Errorf("full keeps the account id: %q", full.Account.ID)
	}

	sha := sha256Hex("x")
	for kind, keep := range map[event.AssetKind]bool{event.AssetAgent: true, event.AssetSkill: true, event.AssetMCPServer: false, event.AssetHook: false} {
		inv := event.New(event.KindInventory, event.TypeInventoryAsset, event.SourceScan)
		inv.Asset = &event.Asset{ID: "a", Kind: kind, SHA256: sha}
		o, _, _ := (&Policy{}).Emit(inv)
		if (o.Asset.SHA256 == sha) != keep {
			t.Errorf("%s: sha256 kept=%v want %v", kind, o.Asset.SHA256 == sha, keep)
		}
	}
}

func TestRewriteMarkers(t *testing.T) {
	m := newMarker("password", "hunter2")
	fp := unkeyedFP("hunter2")
	in := "a " + m + " b " + m
	if got := rewriteMarkers(in, nil); got != "a [REDACTED:password] b [REDACTED:password]" {
		t.Errorf("no key: %q", got)
	}
	got := rewriteMarkers(in, testKey)
	if strings.Contains(got, fp) || !strings.Contains(got, ":hmac=") {
		t.Errorf("keyed: %q", got)
	}
	if rewriteMarkers(got, testKey) != got {
		t.Error("rewrite must be idempotent")
	}
	parts := strings.Split(got, " ")
	if parts[1] != parts[3] {
		t.Error("same secret must give the same keyed marker")
	}
}

func TestBucket(t *testing.T) {
	for n, want := range map[int]int{0: 0, -5: 0, 1: 1, 2: 4, 4: 4, 5: 16, 16: 16, 17: 64, 1000: 1024, 5000: 16384} {
		if got := bucket(n); got != want {
			t.Errorf("bucket(%d) = %d, want %d", n, got, want)
		}
	}
}

func TestValidate(t *testing.T) {
	if err := (&Policy{}).Validate(); err != nil {
		t.Errorf("zero policy: %v", err)
	}
	for name, p := range map[string]*Policy{
		"profile":   {Profile: "everything"},
		"short key": {Key: []byte("short")},
		"pseudo":    {PseudonymizeUsers: true},
		"maxline":   {MaxLine: 100},
		"maxfield":  {MaxField: 10},
	} {
		if p.Validate() == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if got, err := ParseProfile(" Standard "); err != nil || got != ProfileStandard {
		t.Errorf("ParseProfile = %v %v", got, err)
	}
	// An unknown profile falls back to minimal at emit time.
	_, ship, _ := (&Policy{Profile: "everything"}).Emit(shellEvent("ls"))
	if ship {
		t.Error("unknown profile must behave as minimal")
	}
}
