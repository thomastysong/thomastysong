package mcpconf_test

// External tests: package privacy depends on mcpconf, so tests that run
// mcpconf output through privacy cannot live in package mcpconf.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/thomastysong/spoor/internal/event"
	"github.com/thomastysong/spoor/internal/mcpconf"
	"github.com/thomastysong/spoor/internal/privacy"
)

func unkeyedFP8(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:4])
}

// A capped field is cut after redaction. A cut inside a
// "[REDACTED:<kind>:<fp8>]" marker used to keep the kind and all or part of
// the UNKEYED fingerprint without the closing ']', a shape privacy does not
// rewrite (it rewrites complete markers only), so the fingerprint shipped
// as written, tenant key or not: a guessing oracle for the credential.
// The cut is moved through every offset of the marker here.
func TestCapStringNeverSplitsMarker(t *testing.T) {
	secret := "hunter2" + "hunter2"
	head := unkeyedFP8(secret)[:5] // 20 bits of the unkeyed SHA-256 of the secret
	keys := [][]byte{nil, bytes.Repeat([]byte{9}, 32)}
	whole := 0
	for n := 900; n <= 1024; n++ {
		arg := strings.Repeat("a", n) + " API_KEY=" + secret + " " + strings.Repeat("b", 100)
		srv := mcpconf.Server{Name: "s", Transport: "stdio", Command: "node", Args: []string{"server.js", arg}}
		m := mcpconf.Normalize(srv)
		if len(m.Args) < 2 {
			t.Fatalf("n=%d: args %q", n, m.Args)
		}
		got := m.Args[1]
		if len(got) > 1024 || strings.Contains(got, secret) {
			t.Fatalf("n=%d: %d bytes or the secret survived", n, len(got))
		}
		if k := strings.Index(got, "[REDACTED"); k >= 0 {
			if !strings.Contains(got[k:], "]") {
				t.Fatalf("n=%d: partial marker %q", n, got[k:])
			}
			whole++
		}
		for _, key := range keys {
			ev := event.New(event.KindInventory, event.TypeInventoryAsset, event.SourceScan)
			mm := m
			ev.Asset = &event.Asset{ID: "x", Kind: event.AssetMCPServer, Name: "s", MCP: &mm}
			p := &privacy.Policy{Profile: privacy.ProfileStandard, Key: key, KeyID: "k1"}
			out, ship, ok := p.Emit(ev)
			if !ok || !ship || out == nil {
				t.Fatalf("n=%d: not shipped", n)
			}
			b, err := json.Marshal(out)
			if err != nil {
				t.Fatal(err)
			}
			// privacy rewrites a whole marker to ":hmac=..." or drops its
			// fingerprint; anything else after the kind is unkeyed.
			js := string(b)
			for off := 0; ; {
				i := strings.Index(js[off:], "generic_secret:")
				if i < 0 {
					break
				}
				i += off + len("generic_secret:")
				if !strings.HasPrefix(js[i:], "hmac=") {
					t.Fatalf("n=%d key=%v: an unkeyed fingerprint shipped: %q", n, key != nil, js[max(0, i-30):min(len(js), i+12)])
				}
				off = i
			}
			if strings.Contains(js, head) && strings.Contains(js, "generic_secret:"+head[:1]) {
				t.Fatalf("n=%d key=%v: the fingerprint shipped", n, key != nil)
			}
		}
	}
	if whole == 0 {
		t.Fatal("no cut kept a whole marker: the test does not reach the marker")
	}
}

// Name and Project identify an asset (discovery.AssetID hashes them) and
// differential inventory compares ids with a scan run by another process.
// Their cut forms must be the same in every process: a per-process digest
// made a long-named server new, and its old id removed, on every scan.
func TestLongIdentityStableAcrossProcesses(t *testing.T) {
	long := func(p string, n int) string { return p + strings.Repeat("n", n) }
	cfg := []byte(`{"mcpServers":{"` + long("a", 300) + `":{"command":"npx","args":["-y","pkg@1.2.3"]},` +
		`"` + long("a", 400) + `":{"command":"npx","args":["-y","other@1.0.0"]}},` +
		`"projects":{"/` + long("p", 2000) + `":{"mcpServers":{"` + long("b", 500) + `":{"command":"uvx","args":["x"]}}}}}`)
	ids := func() string {
		ss, err := mcpconf.Parse("/home/u/.claude.json", cfg, mcpconf.FormatAuto)
		if err != nil || len(ss) != 3 {
			t.Fatalf("parse %d %v", len(ss), err)
		}
		var b strings.Builder
		for _, s := range ss {
			if len(s.Name) > 256 || len(s.Project) > 1024 {
				t.Fatalf("unbounded: %d / %d bytes", len(s.Name), len(s.Project))
			}
			fmt.Fprintf(&b, "%x|%x;", s.Project, s.Name)
		}
		return b.String()
	}
	if os.Getenv("SPOOR_MCPCONF_IDENTITY_CHILD") == "1" {
		fmt.Println("IDS=" + ids())
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestLongIdentityStableAcrossProcesses$", "-test.v")
	cmd.Env = append(os.Environ(), "SPOOR_MCPCONF_IDENTITY_CHILD=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	var other string
	for _, l := range strings.Split(string(out), "\n") {
		if v, ok := strings.CutPrefix(l, "IDS="); ok {
			other = v
		}
	}
	if here := ids(); other != here {
		t.Fatalf("the same declarations have different names or projects in another process:\n%s\n%s", here, other)
	}
}
