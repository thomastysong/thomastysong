package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

func TestCatalogList(t *testing.T) {
	cfg, _ := testConfig(t, "")
	ta := newTestApp(t)
	out := ta.mustRun(t, exitOK, "catalog", "list", "--config", cfg, "--hooks")
	if !strings.Contains(out, "claude-code") || !strings.Contains(out, "codex") {
		t.Fatalf("list:\n%s", out)
	}
	var v struct {
		Version  string       `json:"version"`
		Products []productRow `json:"products"`
	}
	decodeJSON(t, ta.mustRun(t, exitOK, "catalog", "list", "--config", cfg, "--kind", "agent", "--json"), &v)
	if v.Version == "" || len(v.Products) < 5 {
		t.Fatalf("%+v", v)
	}
	for _, p := range v.Products {
		if p.Kind != "agent" {
			t.Fatalf("--kind agent returned %s", p.Kind)
		}
	}
}

func TestCatalogVerify(t *testing.T) {
	cfg, _ := testConfig(t, "")
	var npmHits, pypiHits atomic.Int64
	// One fake registry for both: every package exists under its own name,
	// except the one this test pretends was unpublished.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, _ := url.PathUnescape(r.URL.EscapedPath())
		switch {
		case strings.HasPrefix(path, "/pypi/"):
			pypiHits.Add(1)
			name := strings.TrimSuffix(strings.TrimPrefix(path, "/pypi/"), "/json")
			fmt.Fprintf(w, `{"info":{"name":%q}}`, strings.ToUpper(name))
		default:
			npmHits.Add(1)
			name := strings.TrimPrefix(path, "/")
			if name == "@anthropic-ai/claude-code" {
				http.NotFound(w, r)
				return
			}
			fmt.Fprintf(w, `{"name":%q,"dist-tags":{"latest":"1.0.0"},"versions":{"1.0.0":{}}}`, name)
		}
	}))
	defer srv.Close()
	ta := newTestApp(t)
	ta.npmRegistry, ta.pypiRegistry = srv.URL, srv.URL
	ta.client = srv.Client()

	out := ta.mustRun(t, exitCheck, "catalog", "verify", "--config", cfg)
	if !strings.Contains(out, "not_found") || !strings.Contains(out, "npm:@anthropic-ai/claude-code") {
		t.Fatalf("verify:\n%s", out)
	}
	if npmHits.Load() == 0 || pypiHits.Load() == 0 {
		t.Fatalf("registries not asked: npm %d pypi %d", npmHits.Load(), pypiHits.Load())
	}
	// PyPI names are compared PEP 503-normalized: upper case is no rename.
	if strings.Contains(out, "renamed") {
		t.Fatalf("case difference reported as a rename:\n%s", out)
	}
	var v struct {
		Packages []pkgCheck     `json:"packages"`
		Counts   map[string]int `json:"counts"`
	}
	decodeJSON(t, ta.mustRun(t, exitCheck, "catalog", "verify", "--config", cfg, "--json"), &v)
	if v.Counts["not_found"] != 1 || v.Counts["ok"] < 10 {
		t.Fatalf("counts %v", v.Counts)
	}

	ta.mustRun(t, exitOK, "catalog", "verify", "--config", cfg, "--offline")

	// No network: unreachable is reported, not failed.
	ta2 := newTestApp(t)
	out = ta2.mustRun(t, exitOK, "catalog", "verify", "--config", cfg, "--timeout", "2s")
	if !strings.Contains(out, "unreachable") {
		t.Fatalf("offline run:\n%s", out)
	}
}

func TestCatalogVerifyRenameAndDeprecation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/pypi/"):
			fmt.Fprint(w, `{"info":{"name":"something-else"}}`)
		default:
			fmt.Fprint(w, `{"name":"old-cli","dist-tags":{"latest":"2.0.0"},"versions":{"2.0.0":{"deprecated":"moved to @new/cli"}}}`)
		}
	}))
	defer srv.Close()
	ta := newTestApp(t)
	ta.npmRegistry, ta.pypiRegistry, ta.client = srv.URL, srv.URL, srv.Client()
	got := ta.checkPackage(ta.ctx, pkgCheck{Ref: "npm:old-cli", Registry: "npm"})
	if got.Status != "deprecated" || !strings.Contains(got.Detail, "moved to") {
		t.Fatalf("npm: %+v", got)
	}
	got = ta.checkPackage(ta.ctx, pkgCheck{Ref: "pip:aider-chat", Registry: "pypi"})
	if got.Status != "renamed" {
		t.Fatalf("pypi: %+v", got)
	}
	if pep503("Aider_Chat..X") != "aider-chat-x" {
		t.Fatal(pep503("Aider_Chat..X"))
	}
}

// catalog verify streams the npm reply: packuments of 9-27 MB (codex,
// opencode, openclaw, amp, @mastra/core, measured 2026-11-12) are read,
// not reported as unreadable, and the deprecation of the latest version is
// still found among the skipped fields.
func TestCatalogVerifyLargePackument(t *testing.T) {
	big := strings.Repeat("x", 9<<20)
	var accept string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		accept = r.Header.Get("Accept")
		fmt.Fprintf(w, `{"_id":"@openai/codex","readme":%q,"name":"@openai/codex","time":{"1.0.0":"x"},"versions":{"0.9.0":{"deprecated":"old"},"1.0.0":{"name":"@openai/codex","deprecated":false,"dist":{"tarball":"t"}}},"dist-tags":{"latest":"1.0.0"}}`, big)
	}))
	defer srv.Close()
	ta := newTestApp(t)
	ta.npmRegistry = srv.URL
	ta.client = srv.Client()
	got := ta.checkPackage(context.Background(), pkgCheck{Product: "codex", Ref: "npm:@openai/codex", Registry: "npm"})
	if got.Status != "ok" {
		t.Fatalf("an existing package with a 9 MiB packument: status %q (%s), want ok", got.Status, got.Detail)
	}
	if !strings.Contains(accept, "application/vnd.npm.install-v1+json") {
		t.Fatalf("the abbreviated document was not asked for: Accept %q", accept)
	}
}

func TestDecodeNPM(t *testing.T) {
	for _, tc := range []struct {
		in, name, dep string
		depOK         bool
		err           bool
	}{
		{`{"name":"a","dist-tags":{"latest":"2.0.0"},"versions":{"2.0.0":{"deprecated":"use b"}}}`, "a", "use b", true, false},
		{`{"versions":{"2.0.0":{"deprecated":true}},"dist-tags":{"latest":"2.0.0"},"name":"a"}`, "a", "deprecated", true, false},
		{`{"name":"a","dist-tags":{"latest":"2.0.0"},"versions":{"2.0.0":{"deprecated":""},"1.0.0":{"deprecated":"x"}}}`, "a", "", false, false},
		{`{"name":"a","x":[[[[{"y":[1,2,{"z":null}]}]]]],"versions":{}}`, "a", "", false, false},
		{`[1,2]`, "", "", false, true},
		{`{"name":"a","versions":{"1":`, "", "", false, true},
	} {
		doc, err := decodeNPM(strings.NewReader(tc.in))
		if (err != nil) != tc.err {
			t.Errorf("%s: err %v", tc.in, err)
			continue
		}
		if err != nil {
			continue
		}
		dep, ok := doc.deprecated[doc.distTags["latest"]]
		if doc.name != tc.name || ok != tc.depOK || dep != tc.dep {
			t.Errorf("%s: name %q deprecated %q %v", tc.in, doc.name, dep, ok)
		}
	}
	// A reply over the cap is reported as such.
	defer func(v int64) { maxRegistryReply = v }(maxRegistryReply)
	maxRegistryReply = 1 << 20
	huge := io.MultiReader(strings.NewReader(`{"readme":"`), io.LimitReader(zeroReader{}, maxRegistryReply+10))
	if _, err := decodeNPM(huge); err == nil || !strings.Contains(err.Error(), "larger than") {
		t.Fatalf("oversize reply: %v", err)
	}
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 'a'
	}
	return len(p), nil
}
