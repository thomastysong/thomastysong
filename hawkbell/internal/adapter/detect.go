package adapter

import (
	"bytes"
	"encoding/json"
)

// Formats Detect can report.
const (
	FormatHawkbell = "hawkbell" // a hawkbell event line (internal/event)
	FormatNumbat   = "numbat"   // a perplexityai/numbat record
	FormatOsquery  = "osquery"  // an osquery (or Fleet) scheduled-query result line
	FormatUnknown  = "unknown"
)

// MaxDetectLine is the longest line Detect inspects; longer lines report
// "unknown".
const MaxDetectLine = 16 << 20

var detectKeys = map[string]bool{
	// numbat
	"schema_version": true, "record_type": true, "run_id": true, "endpoint": true,
	// hawkbell
	"v": true, "kind": true, "type": true, "source": true, "id": true, "ts": true,
	// osquery
	"name": true, "hostIdentifier": true, "calendarTime": true, "unixTime": true,
	"columns": true, "snapshot": true, "diffResults": true,
}

var numbatRecordTypes = map[string]bool{
	"event": true, "finding": true, "enforcement": true, "indicator": true,
	"scan_summary": true, "diagnostic": true,
}

var hawkbellKinds = map[string]bool{
	"activity": true, "inventory": true, "posture": true, "detection": true, "health": true, "summary": true,
}

// Detect reports which sensor wrote an NDJSON line: "hawkbell", "numbat",
// "osquery" or "unknown". It is meant for choosing a converter for a file or
// stream (the detect command, tailers), so it looks only at the envelope:
//
//   - numbat: record_type is one of numbat's record types, with
//     schema_version and run_id or endpoint.
//   - hawkbell: numeric v, a known kind, and string type, source and id.
//   - osquery: the results-log shapes, hostIdentifier and name with columns
//     (event format), snapshot or diffResults (batch format). Status-log
//     lines are not results and report "unknown".
//
// Anything that is not one well-formed JSON object, that matches none of the
// shapes, or that matches more than one (which no sensor produces) is
// "unknown". Detect never panics and does not decode nested values, so its
// cost is linear in the line length.
func Detect(line []byte) string {
	b := bytes.TrimSpace(bytes.TrimPrefix(line, []byte("\xef\xbb\xbf")))
	if len(b) < 2 || len(b) > MaxDetectLine || b[0] != '{' || !json.Valid(b) {
		return FormatUnknown
	}
	top, ok := scanTop(b, detectKeys)
	if !ok {
		return FormatUnknown
	}
	has := func(key string, kinds string) bool {
		k := top[key].kind
		return k != 0 && bytes.IndexByte([]byte(kinds), k) >= 0
	}
	var matches []string
	if has("record_type", "s") && numbatRecordTypes[top["record_type"].text] && has("schema_version", "s") &&
		(has("run_id", "s") || has("endpoint", "o")) {
		matches = append(matches, FormatNumbat)
	}
	if has("v", "n") && has("kind", "s") && hawkbellKinds[top["kind"].text] && has("type", "s") &&
		has("source", "s") && has("id", "s") {
		matches = append(matches, FormatHawkbell)
	}
	// unixTime is a number unless the logger was told to stringify.
	if has("hostIdentifier", "s") && has("name", "s") && (has("calendarTime", "s") || has("unixTime", "ns")) &&
		(has("columns", "o") || has("snapshot", "a") || has("diffResults", "o")) {
		matches = append(matches, FormatOsquery)
	}
	if len(matches) == 1 {
		return matches[0]
	}
	return FormatUnknown
}
