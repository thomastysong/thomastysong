package main

import (
	"bytes"
	"fmt"

	"gopkg.in/yaml.v3"

	"github.com/thomastysong/spoor/internal/config"
)

// configComments documents keys of the written configuration, by dotted
// path. The YAML itself is produced from config.Default, so a key added to
// internal/config appears in the output even before it gets a comment here
// (a test lists keys without one).
// It is a function, not a package variable, so that building the map is
// not part of every process start (`spoor hook` runs twice per tool call).
func configComments() map[string]string {
	return map[string]string{
		"data_dir":  "Holds outbox/, local/, spool/, state.db, bundle/ and checkpoints/.",
		"host_id":   "Overrides host identity detection (set it to Fleet's host UUID if osquery invents one).",
		"host_root": "Filesystem prefix for scanning another root, such as /host in a Kubernetes node sensor.",
		"tags":      "Host or owner roles (offsec, ci, platform-eng ...); rules and suppressions can match them.",
		"labels":    "Copied onto every emitted record.",

		"privacy":                    "What leaves this machine. Detection always runs locally on full content.",
		"privacy.profile":            "minimal: findings, inventory, posture, health and session summaries only.\nstandard: also activity, field-level redacted, no prompt text or tool output.\nfull: also redacted prompt text and tool input/output.",
		"privacy.hmac_key_file":      "Tenant key (root-only file, 32+ bytes) for keyed digests and pseudonyms;\nwithout it no content-derived digest is emitted at all.",
		"privacy.key_id":             "Identifies the key in records, for rotation.",
		"privacy.pseudonymize_users": "Replace user names with keyed pseudonyms (needs hmac_key_file).",
		"privacy.exclude":            "Sessions dropped before any content is processed (globs).",
		"privacy.exclude.paths":      "Session working directories.",
		"privacy.exclude.repos":      "Repository remotes.",
		"privacy.exclude.users":      "OS account names.",
		"privacy.context_events":     "Preceding session events sent with a finding (0 disables).",

		"guard":              "Optional pre-action decisions. Advisory: agents fail open on hook timeouts.",
		"guard.mode":         "off | advisory",
		"guard.deadline":     "Rule evaluation budget in the hook; on expiry the answer is \"ask\".",
		"guard.max_response": "Strongest answer a rule may give: ask | block.",

		"sources":                       "Collectors.",
		"sources.hooks":                 "The spool `spoor hook` writes and the daemon ingests.",
		"sources.hooks.detect_in_hook":  "Evaluate all rules inside the hook (daemonless, containers, CI only).",
		"sources.transcripts":           "Agents' on-disk session logs.",
		"sources.transcripts.agents":    "Catalog ids; empty means every supported agent.",
		"sources.transcripts.backfill":  "Read this far back into logs that existed before first sight (0: start at the end).",
		"sources.processes":             "OS process monitor.",
		"sources.processes.exec_events": "Linux process connector for exec ground truth, when permitted.",
		"sources.osquery_exec":          "Pull exec rows from a running osqueryd over its extension socket (nothing is scheduled in Fleet).",
		"sources.osquery_exec.socket":   "Empty: try the well-known orbit and osquery sockets.",
		"sources.otlp":                  "Loopback receiver for agent-native OpenTelemetry (experimental).",
		"sources.scan":                  "Inventory and posture scans.",
		"sources.scan.full_every":       "How often a complete snapshot is emitted; scans in between emit changes only.",
		"sources.scan.projects":         "Scan the control files of projects agents worked in.",
		"sources.adapters":              "Other sensors' NDJSON to convert (experimental), e.g. {format: numbat, paths: [...]}.",
		"output":                        "Where records go. Fluent Bit tails the outbox (see `spoor export fluent-bit`).",
		"output.format":                 "native | ocsf",
		"output.stdout":                 "Also write shipped records to standard output (containers).",
		"output.max_segment_bytes":      "Roll an outbox segment past this size.",
		"output.max_line_bytes":         "Cap on one encoded record (8192..65536); larger fields are cut and listed in \"truncated\".",
		"output.forward":                "Ship with the Fluent Forward protocol (experimental): {addr, tag_prefix, shared_key, compress, timeout}.",
		"output.otlp":                   "Ship as OTLP/HTTP JSON logs (experimental): {endpoint, headers, gzip, timeout}.",
		"output.fluent_bit":             "Lets the sensor observe its shipper.",
		"output.fluent_bit.tail_db":     "Fluent Bit tail database: prune only segments it has read, report shipper lag.",
		"output.fluent_bit.api":         "Fluent Bit HTTP API (http://127.0.0.1:2020), checked by `spoor doctor`.",
		"output.streams":                "Restrict shipped streams; empty means the profile's default.",
		"output.group":                  "Group allowed to read the outbox (POSIX).",
		"rules":                         "Detection content.",
		"rules.dirs":                    "Extra rule directories (root-owned, not group/world-writable), loaded after the embedded packs and the bundle.",
		"rules.disable":                 "Rule ids switched off.",
		"rules.suppress_for":            "Repeats of one finding inside this window are counted, not re-emitted.",
		"rules.suppressions":            "Operator exceptions: {rule, match: {field: glob}, tags, expires, reason}.",
		"rules.min_class":               "Lowest class written to the detection stream: signal | finding | alert.",
		"bundle":                        "Signed content updates (`spoor bundle`).",
		"bundle.url":                    "https URL of the bundle archive; <url>.sig holds its signature.",
		"bundle.public_keys":            "Trusted signing keys (base64 or hex); required with url.",
		"retention":                     "Bounds of every local store.",
		"retention.outbox":              "Age cap of shipped segments.",
		"retention.outbox_bytes":        "Hard cap; unread data dropped beyond it is reported.",
		"retention.local":               "Local activity ring (records that never leave the host).",
		"retention.spool":               "Fully read hook spool files.",
		"retention.detections":          "State database rows.",
		"limits":                        "Volume and cost.",
		"limits.activity_per_second":    "Per-session token bucket for activity records (detection still sees everything).",
		"limits.max_hook_input_bytes":   "Largest hook payload read.",
		"heartbeat":                     "Interval between health records (minimum 10s).",
		"sources.hooks.enabled":         "false makes `spoor hook` exit at once (like the kill switch).",
		"sources.scan.interval":         "Differential scan interval.",
		"sources.otlp.addr":             "Loopback address only.",
		"sources.hooks.poll":            "How often the daemon reads the spools.",
		"sources.processes.idle":        "Poll interval with no agent running.",
		"sources.processes.active":      "Poll interval while an agent runs.",
		"bundle.interval":               "How often the bundle URL is polled.",
	}
}

const configHeader = `spoor configuration (written by ` + "`spoor export config`" + `, %s).
Every key is optional: a missing key takes the default shown here, and a
missing file means all defaults. Unknown keys are errors, so a typo cannot
silently switch a control off. Reference: docs/PRIVACY.md, docs/FLEET.md,
docs/FLUENT-BIT.md.`

// defaultConfigYAML renders config.Default(dataDir) as commented YAML that
// config.Load reads back to the same configuration.
func defaultConfigYAML(dataDir string) ([]byte, error) {
	cfg := config.Default(dataDir)
	var doc yaml.Node
	if err := doc.Encode(cfg); err != nil {
		return nil, err
	}
	doc.HeadComment = fmt.Sprintf(configHeader, "spoor "+versionString())
	commentNode(&doc, "", configComments())
	var buf bytes.Buffer
	enc := yaml.NewEncoder(&buf)
	enc.SetIndent(2)
	if err := enc.Encode(&doc); err != nil {
		return nil, err
	}
	if err := enc.Close(); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// commentNode attaches configComments to the keys of mapping nodes.
func commentNode(n *yaml.Node, prefix string, comments map[string]string) {
	switch n.Kind {
	case yaml.DocumentNode:
		for _, c := range n.Content {
			commentNode(c, prefix, comments)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			k, v := n.Content[i], n.Content[i+1]
			path := k.Value
			if prefix != "" {
				path = prefix + "." + k.Value
			}
			if c := comments[path]; c != "" {
				k.HeadComment = c
			}
			commentNode(v, path, comments)
		}
	}
}

// configKeys lists the dotted paths of every mapping key in the rendered
// default configuration (for the test that keeps the comments complete).
func configKeys(b []byte) ([]string, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	var out []string
	var walk func(n *yaml.Node, prefix string)
	walk = func(n *yaml.Node, prefix string) {
		switch n.Kind {
		case yaml.DocumentNode:
			for _, c := range n.Content {
				walk(c, prefix)
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(n.Content); i += 2 {
				p := n.Content[i].Value
				if prefix != "" {
					p = prefix + "." + p
				}
				out = append(out, p)
				walk(n.Content[i+1], p)
			}
		}
	}
	walk(&doc, "")
	return out, nil
}
