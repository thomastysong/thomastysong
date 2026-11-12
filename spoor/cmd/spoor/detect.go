package main

import (
	"encoding/json"
	"fmt"

	"github.com/thomastysong/spoor/internal/event"
)

const detectAbout = `Evaluates NDJSON events with the detection rules, for central
re-evaluation of shipped records (with rules you do not publish), CI and
benchmarks. Input is files, directories (their *.ndjson files, oldest
segment first) or "-" for stdin (the default). Each line is read as a spoor
event (outbox, local ring), a hook spool record (event plus local content)
or a numbat record; --format forces one reader. Only activity and inventory
records are evaluated; detections, health and summaries in the input are
counted and skipped.

Records keep their own host and user. Output passes through the configured
privacy profile (override with --profile), exactly like the outbox. Give
files in time order: session state and rate limits follow record time.`

func (a *app) cmdDetect(args []string) int {
	fs := a.newFlags("detect", "detect [--format auto|native|numbat] [--rules dir] [--fail-on high] [--json|--ndjson] [files|dirs|-]", detectAbout)
	var cf cfgFlags
	cf.register(fs)
	format := fs.String("format", formatAuto, "input format: auto (per line), native (spoor events and spool records) or numbat")
	var dirs listFlag
	fs.Var(&dirs, "rules", "rules directory merged over the embedded packs (repeatable)")
	noEmbedded := fs.Bool("no-embedded", false, "use only the --rules directories")
	noHost := fs.Bool("no-host-rules", false, "ignore this host's installed bundle and configured rules.dirs")
	failOn := fs.String("fail-on", "high", "exit 3 when a detection is at or above this severity (info..critical) or class (signal, finding, alert); none disables")
	minClass := fs.String("min-class", "", "lowest class written: signal, finding or alert (default: rules.min_class)")
	profile := fs.String("profile", "", "privacy profile of the output: minimal, standard or full (default: privacy.profile)")
	asJSON := fs.Bool("json", false, "print one JSON document")
	asNDJSON := fs.Bool("ndjson", false, "print the detection, posture and session summary records as NDJSON")
	pos, code, done := a.parse(fs, args)
	if done {
		return code
	}
	switch *format {
	case formatAuto, formatNative, formatNumbat:
	default:
		return a.usageErr("detect", "--format %q: want auto, native or numbat", *format)
	}
	if *asJSON && *asNDJSON {
		return a.usageErr("detect", "--json and --ndjson are exclusive")
	}
	th, err := parseFailOn(*failOn)
	if err != nil {
		return a.usageErr("detect", "%v", err)
	}
	cfg, _, err := loadConfig(cf)
	if err != nil {
		return a.fail("detect", err)
	}
	if err := profileOverride(cfg, *profile); err != nil {
		return a.usageErr("detect", "--profile: %v", err)
	}
	if *minClass != "" {
		cfg.Rules.MinClass = *minClass
		if err := cfg.Validate(); err != nil {
			return a.usageErr("detect", "--min-class: %v", err)
		}
	}
	set, _, err := loadRules(cfg, ruleSource{dirs: dirs, noEmbedded: *noEmbedded, noHost: *noHost})
	if err != nil {
		return a.fail("detect", err)
	}
	cat, overlayErr, err := loadCatalog(cfg)
	if err != nil {
		return a.fail("detect", err)
	}
	if overlayErr != nil {
		a.warn("detect", "%v (embedded catalog used)", overlayErr)
	}
	stats := newInputStats()
	rd := &eventReader{format: *format, stats: stats}
	rep, err := evaluate(evalOptions{cfg: cfg, set: set, catalog: cat, now: a.now}, stats, func(emit func(*event.Event)) error {
		return rd.readPaths(pos, a.stdin, emit)
	})
	if err != nil {
		return a.fail("detect", err)
	}
	hits := rep.applyFailOn(th)
	switch {
	case *asJSON:
		if c := a.printJSON(rep); c != exitOK {
			return c
		}
	case *asNDJSON:
		enc := json.NewEncoder(a.stdout)
		enc.SetEscapeHTML(false)
		for _, group := range [][]*event.Event{rep.Detections, rep.Posture, rep.Summaries} {
			for _, e := range group {
				if err := enc.Encode(e); err != nil {
					return a.fail("detect", err)
				}
			}
		}
		fmt.Fprintf(a.stderr, "spoor detect: %d detection(s), %d at or above --fail-on %s\n", rep.Summary.Detections, hits, th.raw)
	default:
		printReport(a.stdout, rep)
	}
	if hits > 0 {
		return exitFindings
	}
	return exitOK
}
