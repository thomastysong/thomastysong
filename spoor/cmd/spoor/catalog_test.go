package main

import (
	"fmt"
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
