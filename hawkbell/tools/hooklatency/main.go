// Command hooklatency measures `hawkbell hook` wall time as an agent sees
// it: one process start per hooked event, the payload on stdin, wait for
// exit. Cases run round-robin, after 10 discarded warm-up rounds, so
// background load on the machine hits every case equally. It prints a
// markdown table (p50, p90, p99, max and non-zero exits per case).
//
// Cases: an empty hook (/bin/true) and, with -hello, an empty Go program as
// floors; the kill switch (process start and package init only); observe,
// guard (guard.mode advisory) and detect-in-hook, each supervised (what
// hookinstall registers) and unsupervised (the worker alone). Supervised
// runs go through each launch path an agent uses: direct exec, sh -c and
// bash -lc, with the command line hookinstall renders, missing-binary guard
// included. With -alt a second binary runs the same cases in the same
// rounds, which is how two builds are compared on a shared machine.
//
// internal/hookcmd/LATENCY.md records the results and the commands:
//
//	CGO_ENABLED=0 go build -trimpath -buildvcs=false -ldflags '-s -w -buildid=' -o /tmp/hb ./cmd/hawkbell
//	go run ./tools/hooklatency -bin /tmp/hb -dir "$(mktemp -d)" \
//	    -payload internal/hookio/testdata/claude/PreToolUse.json -n 300
//
// Every run writes to spools under -dir (HAWKBELL_SPOOL); nothing else on
// the machine is touched.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type tc struct {
	name string
	argv []string
	env  []string
	durs []time.Duration
	bad  int
}

func main() {
	bin := flag.String("bin", "", "hawkbell binary to measure")
	dir := flag.String("dir", "", "work directory for configs and spools")
	payloadPath := flag.String("payload", "", "Claude Code PreToolUse payload")
	n := flag.Int("n", 300, "runs per case")
	only := flag.String("only", "", "comma list of case name substrings")
	hello := flag.String("hello", "", "empty Go program (floor for any Go hook)")
	alt := flag.String("alt", "", "second binary, measured in every mode in the same rounds as -bin")
	altTag := flag.String("alttag", "variant", "label of -alt")
	flag.Parse()
	if *bin == "" || *dir == "" || *payloadPath == "" {
		fmt.Fprintln(os.Stderr, "hooklatency: -bin, -dir and -payload are required")
		os.Exit(2)
	}
	payload, err := os.ReadFile(*payloadPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "hooklatency:", err)
		os.Exit(1)
	}
	cfgs := map[string]string{
		"observe": "",
		"guard":   "guard:\n  mode: advisory\n",
		"detect":  "sources:\n  hooks:\n    detect_in_hook: true\n",
	}
	var cases []*tc
	add := func(name string, argv []string, env ...string) {
		if *only != "" {
			ok := false
			for _, o := range strings.Split(*only, ",") {
				if strings.Contains(name, o) {
					ok = true
				}
			}
			if !ok {
				return
			}
		}
		cases = append(cases, &tc{name: name, argv: argv, env: env})
	}
	paths := []struct {
		name string
		wrap func(cmd string) []string
	}{
		{"direct", nil},
		{"sh -c", func(c string) []string { return []string{"/bin/sh", "-c", c} }},
		{"bash -lc", func(c string) []string { return []string{"/bin/bash", "-lc", c} }},
	}
	for _, p := range paths {
		// The empty hook: what the launch path itself costs.
		if p.wrap == nil {
			add("empty /bin/true | "+p.name, []string{"/bin/true"})
		} else {
			add("empty /bin/true | "+p.name, p.wrap("exec /bin/true"))
		}
	}
	if *hello != "" {
		add("empty Go program | direct", []string{*hello})
	}
	ks := filepath.Join(*dir, "killswitch")
	os.MkdirAll(ks, 0o700)
	os.WriteFile(filepath.Join(ks, "disabled"), nil, 0o600)
	add("hawkbell kill switch (start+init only) | direct", []string{*bin, "hook", "--agent", "claude-code", "--config", filepath.Join(ks, "hawkbell.yaml")})
	if *alt != "" {
		add("hawkbell kill switch (start+init only) ["+*altTag+"] | direct", []string{*alt, "hook", "--agent", "claude-code", "--config", filepath.Join(ks, "hawkbell.yaml")})
	}
	type variant struct{ mode, bin, tag string }
	variants := []variant{{"observe", *bin, ""}, {"guard", *bin, ""}, {"detect", *bin, ""}}
	if *alt != "" {
		for _, m := range []string{"observe", "guard", "detect"} {
			variants = append(variants, variant{m, *alt, " [" + *altTag + "]"})
		}
	}
	for _, v := range variants {
		mode, bin := v.mode, &v.bin
		md := filepath.Join(*dir, mode+strings.NewReplacer(" ", "", "[", "", "]", "").Replace(v.tag))
		os.MkdirAll(md, 0o700)
		cfg := filepath.Join(md, "hawkbell.yaml")
		os.WriteFile(cfg, []byte(cfgs[mode]), 0o600)
		sp := filepath.Join(md, "spool")
		for _, sup := range []bool{true, false} {
			args := []string{*bin, "hook"}
			label := "supervised"
			if !sup {
				args = append(args, "--worker")
				label = "unsupervised"
			}
			args = append(args, "--agent", "claude-code", "--config", cfg)
			for _, p := range paths {
				if !sup && p.wrap != nil {
					continue // unsupervised only on the direct path
				}
				// The command line hookinstall renders, with its
				// missing-binary guard.
				shellCmd := fmt.Sprintf("[ -x '%s' ] || exit 0; exec %s", *bin, quote(args))
				argv := args
				if p.wrap != nil {
					argv = p.wrap(shellCmd)
				}
				add(fmt.Sprintf("%s%s %s | %s", mode, v.tag, label, p.name), argv, "HAWKBELL_SPOOL="+sp)
			}
		}
	}
	base := os.Environ()
	run := func(c *tc) {
		cmd := exec.Command(c.argv[0], c.argv[1:]...)
		cmd.Env = append(append([]string(nil), base...), c.env...)
		cmd.Stdin = bytes.NewReader(payload)
		var out bytes.Buffer
		cmd.Stdout = &out
		start := time.Now()
		err := cmd.Run()
		d := time.Since(start)
		if err != nil || cmd.ProcessState.ExitCode() != 0 {
			c.bad++
		}
		c.durs = append(c.durs, d)
	}
	for i := 0; i < 10; i++ { // warm-up, discarded
		for _, c := range cases {
			run(c)
		}
	}
	for _, c := range cases {
		c.durs, c.bad = nil, 0
	}
	for i := 0; i < *n; i++ {
		for _, c := range cases {
			run(c)
		}
	}
	fmt.Printf("| case | n | p50 ms | p90 ms | p99 ms | max ms | non-zero exits |\n|---|---|---|---|---|---|---|\n")
	for _, c := range cases {
		sort.Slice(c.durs, func(i, j int) bool { return c.durs[i] < c.durs[j] })
		q := func(p float64) float64 {
			i := int(p*float64(len(c.durs))+0.5) - 1
			if i < 0 {
				i = 0
			}
			if i >= len(c.durs) {
				i = len(c.durs) - 1
			}
			return float64(c.durs[i].Microseconds()) / 1000
		}
		fmt.Printf("| %s | %d | %.2f | %.2f | %.2f | %.2f | %d |\n", c.name, len(c.durs), q(0.50), q(0.90), q(0.99), q(1.0), c.bad)
	}
}

func quote(args []string) string {
	q := make([]string, len(args))
	for i, a := range args {
		q[i] = "'" + strings.ReplaceAll(a, "'", `'\''`) + "'"
	}
	return strings.Join(q, " ")
}
