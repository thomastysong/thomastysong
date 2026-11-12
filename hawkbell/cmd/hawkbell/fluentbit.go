package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/thomastysong/thomastysong/hawkbell/internal/daemon"
)

// Fluent Bit checks for `hawkbell doctor`. The shipped configuration was
// verified against the real image (deploy/fluent-bit/VERIFIED.md); these
// checks look for the settings that lost data in those runs: memory
// buffering on the tail input (a restart while the destination is down
// loses everything read but not delivered), bounded retries (the default
// retry_limit is 1) and records dropped by an output.
//
// Every finding is a warning (design/BUILD-C.md section C3: "warn
// shipper.unsafe_config"): the shipper is configured by the operator, and
// doctor fails only on what hawkbell itself controls.
//
// What the HTTP API can show, measured on fluent/fluent-bit 5.2.0:
// /api/v1/metrics lists per-output retries_failed and dropped_records, and
// /api/v1/storage lists a storage_backlog input only when
// service.storage.path is set (no filesystem buffering is possible without
// it). Both answer 404 for a while after start, which doctor reports as
// "rerun": /api/v1/metrics for up to 0.8 s after the API comes up, and
// /api/v1/storage, with storage.metrics on or not set, for the first 4 to
// 5.5 s; with storage.metrics off /api/v1/storage always answers 404
// (deploy/fluent-bit/VERIFIED.md, "Measurements added 2026-11-12"). The
// API does not say which storage type an individual input uses;
// --fluent-bit-config reads the configuration file for that.

type fbFinding struct {
	Code   string `json:"code"` // shipper.unsafe_config | shipper.dropped_records | shipper.unreachable ...
	Status string `json:"status"`
	Detail string `json:"detail"`
}

type fluentBitView struct {
	API      string      `json:"api,omitempty"`
	Config   string      `json:"config,omitempty"`
	TailDB   string      `json:"tail_db,omitempty"`
	Version  string      `json:"version,omitempty"`
	Findings []fbFinding `json:"findings"`
}

// loopbackClient talks to a local API without the egress proxy: a proxy
// cannot reach this machine's loopback interface anyway.
func loopbackClient(timeout time.Duration) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.Proxy = func(r *http.Request) (*url.URL, error) {
		h := r.URL.Hostname()
		if h == "localhost" {
			return nil, nil
		}
		if ip := net.ParseIP(h); ip != nil && ip.IsLoopback() {
			return nil, nil
		}
		return http.ProxyFromEnvironment(r)
	}
	return &http.Client{Timeout: timeout, Transport: tr}
}

func getJSON(ctx context.Context, c *http.Client, u string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return &httpStatusError{url: u, code: resp.StatusCode, status: resp.Status}
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(v)
}

// httpStatusError is an API answer other than 200.
type httpStatusError struct {
	url, status string
	code        int
}

func (e *httpStatusError) Error() string { return e.url + ": " + e.status }

// checkFluentBitAPI queries the Fluent Bit HTTP API.
func checkFluentBitAPI(ctx context.Context, c *http.Client, api string) ([]fbFinding, string) {
	base := strings.TrimRight(api, "/")
	var out []fbFinding
	var root struct {
		FluentBit struct {
			Version string `json:"version"`
		} `json:"fluent-bit"`
	}
	if err := getJSON(ctx, c, base+"/", &root); err != nil {
		return []fbFinding{{Code: "shipper.unreachable", Status: "warn", Detail: fmt.Sprintf("Fluent Bit API %s: %v", api, err)}}, ""
	}
	var metrics struct {
		Output map[string]struct {
			Errors        uint64 `json:"errors"`
			Retries       uint64 `json:"retries"`
			RetriesFailed uint64 `json:"retries_failed"`
			Dropped       uint64 `json:"dropped_records"`
		} `json:"output"`
	}
	var se *httpStatusError
	if err := getJSON(ctx, c, base+"/api/v1/metrics", &metrics); errors.As(err, &se) && se.code == http.StatusNotFound {
		out = append(out, fbFinding{Code: "shipper.metrics", Status: "warn",
			Detail: "/api/v1/metrics answered 404: Fluent Bit may have started less than a second ago (5.2.0 answered 404 there for up to 0.8 s after its API came up in testing); rerun hawkbell doctor"})
	} else if err != nil {
		out = append(out, fbFinding{Code: "shipper.metrics", Status: "warn", Detail: err.Error()})
	} else {
		for _, name := range sortedKeys(metrics.Output) {
			o := metrics.Output[name]
			if o.Dropped > 0 {
				out = append(out, fbFinding{Code: "shipper.dropped_records", Status: "warn",
					Detail: fmt.Sprintf("output %s dropped %d record(s): Fluent Bit gave up on them (5.2.0's http output does so after one answer of 400, 401 or 413, even with retry_limit no_limits); with storage.keep.rejected on, a copy is under storage.path/rejected", name, o.Dropped)})
			}
			if o.RetriesFailed > 0 {
				out = append(out, fbFinding{Code: "shipper.unsafe_config", Status: "warn",
					Detail: fmt.Sprintf("output %s gave up %d time(s): retries are bounded; set retry_limit: no_limits", name, o.RetriesFailed)})
			}
		}
	}
	var storage struct {
		Layer *struct {
			Chunks map[string]int `json:"chunks"`
		} `json:"storage_layer"`
		Inputs map[string]json.RawMessage `json:"input_chunks"`
	}
	err := getJSON(ctx, c, base+"/api/v1/storage", &storage)
	switch {
	case errors.As(err, &se) && se.code == http.StatusNotFound:
		// One 404 cannot tell "storage.metrics is off" from "started
		// seconds ago" (see the top of the file).
		out = append(out, fbFinding{Code: "shipper.storage_metrics", Status: "warn",
			Detail: "/api/v1/storage answered 404: Fluent Bit may have started only seconds ago (5.2.0 answered 404 there for the first 4 to 5.5 s after start in testing), or service storage.metrics is off; rerun hawkbell doctor in a minute, and if it still answers 404 set storage.metrics: on. Until then buffering cannot be checked through the API"})
	case err != nil:
		out = append(out, fbFinding{Code: "shipper.storage_metrics", Status: "warn",
			Detail: fmt.Sprintf("storage metrics could not be read (%v); rerun hawkbell doctor. Until then buffering cannot be checked through the API", err)})
	case storage.Layer == nil:
		out = append(out, fbFinding{Code: "shipper.storage_metrics", Status: "warn",
			Detail: "/api/v1/storage has no storage_layer: buffering cannot be checked through the API"})
	default:
		backlog := false
		for name := range storage.Inputs {
			if strings.HasPrefix(name, "storage_backlog") {
				backlog = true
			}
		}
		if !backlog {
			out = append(out, fbFinding{Code: "shipper.unsafe_config", Status: "warn",
				Detail: "service storage.path is not set, so every input is memory-buffered: records read but not yet delivered are lost on restart (5,000 of 5,000 in testing)"})
		}
	}
	return out, root.FluentBit.Version
}

// fbSection is one [INPUT]/[OUTPUT]/[SERVICE] block or YAML list entry,
// with lower-cased keys.
type fbSection struct {
	kind  string // service | input | output
	props map[string]string
}

// readFluentBitConfig reads a YAML or classic configuration with its
// includes (depth-limited, relative to the including file).
func readFluentBitConfig(path string, depth int) ([]fbSection, error) {
	if depth > 8 {
		return nil, fmt.Errorf("%s: includes nested too deeply", path)
	}
	b, err := readSmall(path, 4<<20)
	if err != nil {
		return nil, err
	}
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".yaml" || ext == ".yml" {
		return readFluentBitYAML(path, b, depth)
	}
	return readFluentBitClassic(path, b, depth)
}

func readFluentBitYAML(path string, b []byte, depth int) ([]fbSection, error) {
	var doc struct {
		Includes []string         `yaml:"includes"`
		Service  map[string]any   `yaml:"service"`
		Pipeline map[string][]any `yaml:"pipeline"`
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	var out []fbSection
	if doc.Service != nil {
		out = append(out, fbSection{kind: "service", props: lowerProps(doc.Service)})
	}
	for _, kind := range []string{"inputs", "outputs"} {
		for _, it := range doc.Pipeline[kind] {
			m, ok := it.(map[string]any)
			if !ok {
				continue
			}
			out = append(out, fbSection{kind: strings.TrimSuffix(kind, "s"), props: lowerProps(m)})
		}
	}
	for _, inc := range doc.Includes {
		p := inc
		if !filepath.IsAbs(p) {
			p = filepath.Join(filepath.Dir(path), p)
		}
		more, err := readFluentBitConfig(p, depth+1)
		if err != nil {
			return out, err
		}
		out = append(out, more...)
	}
	return out, nil
}

func lowerProps(m map[string]any) map[string]string {
	out := map[string]string{}
	for k, v := range m {
		out[strings.ToLower(k)] = fmt.Sprint(v)
	}
	return out
}

func readFluentBitClassic(path string, b []byte, depth int) ([]fbSection, error) {
	var out []fbSection
	var cur *fbSection
	sc := bufio.NewScanner(bytes.NewReader(b))
	sc.Buffer(make([]byte, 64<<10), 1<<20)
	for sc.Scan() {
		l := strings.TrimSpace(sc.Text())
		switch {
		case l == "" || strings.HasPrefix(l, "#"):
			continue
		case strings.HasPrefix(strings.ToUpper(l), "@INCLUDE"):
			p := strings.TrimSpace(l[len("@INCLUDE"):])
			if !filepath.IsAbs(p) {
				p = filepath.Join(filepath.Dir(path), p)
			}
			matches, _ := filepath.Glob(p)
			for _, m := range matches {
				more, err := readFluentBitConfig(m, depth+1)
				if err != nil {
					return out, err
				}
				out = append(out, more...)
			}
		case strings.HasPrefix(l, "[") && strings.HasSuffix(l, "]"):
			kind := strings.ToLower(strings.Trim(l, "[]"))
			out = append(out, fbSection{kind: kind, props: map[string]string{}})
			cur = &out[len(out)-1]
		case cur != nil:
			k, v, _ := strings.Cut(l, " ")
			cur.props[strings.ToLower(strings.TrimSpace(k))] = strings.TrimSpace(v)
		}
	}
	return out, sc.Err()
}

// checkFluentBitConfig applies the transport contract to a configuration:
// every tail input that reads the outbox buffers on the filesystem and
// every output retries without limit.
func checkFluentBitConfig(secs []fbSection, outbox string) []fbFinding {
	var out []fbFinding
	storagePath := ""
	for _, s := range secs {
		if s.kind == "service" && s.props["storage.path"] != "" {
			storagePath = s.props["storage.path"]
		}
	}
	tails := 0
	for _, s := range secs {
		if s.kind != "input" || !strings.EqualFold(s.props["name"], "tail") {
			continue
		}
		p := s.props["path"]
		if !strings.Contains(p, filepath.ToSlash(outbox)) && !strings.Contains(p, outbox) && !strings.Contains(p, "HAWKBELL_OUTBOX") {
			continue
		}
		tails++
		name := firstNonEmpty(s.props["alias"], s.props["tag"], "tail")
		if !strings.EqualFold(s.props["storage.type"], "filesystem") {
			out = append(out, fbFinding{Code: "shipper.unsafe_config", Status: "warn",
				Detail: fmt.Sprintf("tail input %s is memory-buffered: set storage.type: filesystem", name)})
		}
		if s.props["db"] == "" {
			out = append(out, fbFinding{Code: "shipper.unsafe_config", Status: "warn",
				Detail: fmt.Sprintf("tail input %s has no db: offsets are lost on restart", name)})
		}
	}
	if tails == 0 {
		out = append(out, fbFinding{Code: "shipper.no_input", Status: "warn", Detail: "no tail input reads the outbox " + outbox})
	}
	if tails > 0 && storagePath == "" {
		out = append(out, fbFinding{Code: "shipper.unsafe_config", Status: "warn", Detail: "service storage.path is not set: filesystem buffering is impossible"})
	}
	for _, s := range secs {
		if s.kind != "output" {
			continue
		}
		name := firstNonEmpty(s.props["alias"], s.props["name"])
		switch strings.ToLower(s.props["retry_limit"]) {
		case "no_limits", "false", "off":
		case "":
			out = append(out, fbFinding{Code: "shipper.unsafe_config", Status: "warn",
				Detail: fmt.Sprintf("output %s uses the default retry_limit (1): set retry_limit: no_limits", name)})
		default:
			out = append(out, fbFinding{Code: "shipper.unsafe_config", Status: "warn",
				Detail: fmt.Sprintf("output %s has bounded retries (retry_limit %s): set no_limits", name, s.props["retry_limit"])})
		}
	}
	return out
}

// checkTailDB checks output.fluent_bit.tail_db as the daemon reads it: the
// same expansion (daemon.ExpandTailDB: comma-separated paths or globs) and
// the same read (daemon.CheckTailDB), with one finding per database that is
// missing or unreadable and per pattern that matches nothing. The read
// includes the pruner's fallback to a private copy when a database cannot
// be read in place (Fluent Bit's db.locking true holds it locked): the
// pruner copies into its checkpoint directory, doctor into a temporary
// directory it removes. A database read through a copy is not a finding,
// since the pruner reads it too. For a locked database doctor, like the
// pruner, first waits SQLite's 2 s busy timeout (TestFluentBitTailDBLocking).
func checkTailDB(spec string) []fbFinding {
	if strings.TrimSpace(spec) == "" {
		return nil
	}
	var out []fbFinding
	warn := func(format string, args ...any) {
		out = append(out, fbFinding{Code: "shipper.tail_db", Status: "warn", Detail: "output.fluent_bit.tail_db: " + fmt.Sprintf(format, args...)})
	}
	// What the pruner does with a database it cannot read (internal/daemon/outbox.go).
	const unread = "pruning counts nothing as read by it"
	dbs, skipped := daemon.ExpandTailDB(spec)
	if len(dbs) == 0 {
		warn("%q names no database", spec)
	}
	copyDir, terr := os.MkdirTemp("", "hawkbell-doctor-")
	if terr == nil {
		defer os.RemoveAll(copyDir)
	} else {
		copyDir = "" // no copy: a locked database is reported as unreadable
	}
	for _, db := range dbs {
		switch {
		case db.BadPattern:
			warn("%s is not a valid pattern; %s", db.Path, unread)
		case db.NoMatch:
			warn("%s matches no file (Fluent Bit creates a tail database when its input starts); until one exists, %s and treats it as a reader of every stream", db.Path, unread)
		default:
			if _, _, err := daemon.CheckTailDB(db.Path, copyDir); err != nil {
				if terr != nil {
					err = fmt.Errorf("%w (doctor could not create a directory for a copy: %v)", err, terr)
				}
				warn("%s: %v; %s", db.Path, err, unread)
			}
		}
	}
	if skipped > 0 {
		warn("%d more database(s) after the first %d are ignored", skipped, len(dbs))
	}
	return out
}
