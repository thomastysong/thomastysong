package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
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
)

// Fluent Bit checks for `hawkbell doctor`. The shipped configuration was
// verified against the real image (deploy/fluent-bit/VERIFIED.md); these
// checks look for the settings that lost data in those runs: memory
// buffering on the tail input (a restart while the destination is down
// loses everything read but not delivered), bounded retries (the default
// retry_limit is 1) and records dropped by an output.
//
// Every finding is a warning (BUILD-C: "warn shipper.unsafe_config"): the
// shipper is configured by the operator, and doctor fails only on what
// hawkbell itself controls.
//
// What the HTTP API can show, measured on fluent/fluent-bit 5.2.0:
// /api/v1/metrics lists per-output retries_failed and dropped_records, and
// /api/v1/storage lists a storage_backlog input only when
// service.storage.path is set (no filesystem buffering is possible without
// it). The API does not say which storage type an individual input uses;
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
		return fmt.Errorf("%s: %s", u, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(v)
}

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
	if err := getJSON(ctx, c, base+"/api/v1/metrics", &metrics); err != nil {
		out = append(out, fbFinding{Code: "shipper.metrics", Status: "warn", Detail: err.Error()})
	} else {
		for _, name := range sortedKeys(metrics.Output) {
			o := metrics.Output[name]
			if o.Dropped > 0 {
				out = append(out, fbFinding{Code: "shipper.dropped_records", Status: "warn",
					Detail: fmt.Sprintf("output %s dropped %d record(s) (a permanent error such as 401/400/413, or retries exhausted); see storage.keep.rejected", name, o.Dropped)})
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
	if err := getJSON(ctx, c, base+"/api/v1/storage", &storage); err != nil || storage.Layer == nil {
		out = append(out, fbFinding{Code: "shipper.storage_metrics", Status: "warn",
			Detail: "storage metrics are not available (service storage.metrics: on): buffering cannot be checked through the API"})
	} else {
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

func checkTailDB(path string) []fbFinding {
	if path == "" {
		return nil
	}
	if _, err := os.Stat(path); err != nil {
		return []fbFinding{{Code: "shipper.tail_db", Status: "warn", Detail: fmt.Sprintf("output.fluent_bit.tail_db %s: %v (pruning cannot see what was shipped)", path, err)}}
	}
	return nil
}
