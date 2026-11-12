package event

// The JSON Schema of the wire record, generated from this package and
// checked against what the binary really writes.
//
//	go test ./internal/event -run TestSchema            check
//	go test ./internal/event -run TestSchema -update    regenerate
//
// The generator reads the Go types by reflection (field names, JSON tags,
// omitempty/omitzero) and this package's source with go/ast (doc comments
// and the constants that make up each closed vocabulary), so a new field or
// constant changes the schema without anyone editing it by hand, and the
// test fails until the regenerated files are committed:
//
//   - docs/schema/event.schema.json (JSON Schema 2020-12);
//   - the field reference between the GENERATED markers in docs/EVENTS.md.
//
// Three facts come from the packages that produce them, also read with
// go/ast: the detection.context type and the privacy profile names
// (internal/privacy), and which fields a skeleton record carries (the
// functions in internal/sink and internal/privacy that write skeletons).
// What each profile never writes is the table neverWritten below, kept in
// step with the profile table in docs/EVENTS.md.
//
// The validator below implements the subset of JSON Schema the generator
// emits, with the standard library only, and refuses any keyword it does
// not implement, so the schema cannot quietly grow a constraint nobody
// checks. Every line under docs/schema/examples (records the real binary
// wrote; docs/schema/examples/regen.sh) must validate, and every example
// record quoted in docs/EVENTS.md must be one of those lines.

import (
	"bufio"
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math/big"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

var updateSchema = flag.Bool("update", false, "rewrite docs/schema/event.schema.json and the generated field reference in docs/EVENTS.md")

var (
	schemaFile  = filepath.Join("..", "..", "docs", "schema", "event.schema.json")
	eventsDoc   = filepath.Join("..", "..", "docs", "EVENTS.md")
	securityDoc = filepath.Join("..", "..", "SECURITY.md")
	examplesDir = filepath.Join("..", "..", "docs", "schema", "examples")
	// The detection-context type is declared where context records are
	// made, and the profile names where profiles are applied; both are part
	// of the wire vocabulary all the same.
	privacyContextSrc = filepath.Join("..", "privacy", "context.go")
	privacyPolicySrc  = filepath.Join("..", "privacy", "policy.go")
)

const (
	genBegin     = "<!-- BEGIN GENERATED: field reference (go test ./internal/event -run TestSchema -update) -->"
	genEnd       = "<!-- END GENERATED: field reference -->"
	profileBegin = "<!-- BEGIN PROFILE FIELDS -->"
	profileEnd   = "<!-- END PROFILE FIELDS -->"
	// Time.MarshalJSON writes TimeLayout in UTC: six fraction digits and Z.
	// Every component is range-checked, month and day together (February
	// 29 in any year: a regular expression cannot know leap years, which is
	// why the Time definition also says format date-time, and this
	// package's validator asserts it).
	timePattern = `^[0-9]{4}-` +
		`(?:(?:0[13578]|1[02])-(?:0[1-9]|[12][0-9]|3[01])|(?:0[469]|11)-(?:0[1-9]|[12][0-9]|30)|02-(?:0[1-9]|1[0-9]|2[0-9]))` +
		`T(?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9]\.[0-9]{6}Z$`
)

// Untyped string fields that carry a closed vocabulary declared as untyped
// constants or in another package (typed fields are matched by their Go
// type).
var fieldEnums = map[string]string{
	"Event.Type":          "EventType",
	"Event.Privacy":       "Profile",
	"Detection.Class":     "DetectionClass",
	"Detection.Severity":  "Severity",
	"Check.Severity":      "Severity",
	"Summary.MaxSeverity": "Severity",
}

// neverWritten lists, per privacy profile, the fields the privacy stage
// never writes (internal/privacy, fields.go): outside full no prompt text,
// tool input or output, or web search query (prompt-derived), and in no
// profile the path of the session log. The schema rejects them, the
// profile table in docs/EVENTS.md must say "never" for exactly these, and
// a profile without an entry here is a generator error.
var neverWritten = map[string][]string{
	"minimal":  {"prompt.text", "tool.input", "tool.output", "target.query", "session.transcript"},
	"standard": {"prompt.text", "tool.input", "tool.output", "target.query", "session.transcript"},
	"full":     {"session.transcript"},
}

// skeletonWriters are the functions that write a skeleton, the content-free
// stand-in for a record that could not be redacted or brought under the
// line cap (truncated ["*"]). The generator reads from their source which
// fields they set, one composite-literal key or assignment at a time, so
// $defs/Skeleton admits exactly those fields and a writer that starts
// setting another one changes the generated schema.
var skeletonWriters = []skeletonWriter{
	{filepath.Join("..", "sink", "shrink.go"), []string{"skeleton"}},
	{filepath.Join("..", "privacy", "emit.go"), []string{"skeleton", "buildSkeleton"}},
}

// fieldNotes describe the fields that have no doc comment in this package,
// for the field reference and the schema. A field's own comment wins; a
// field of a documented type (Host, Kind ...) without either gets its
// type's comment.
var fieldNotes = map[string]string{
	"Event.ID":      "Record id: UUID-shaped and starting with the record time in milliseconds, so ids sort by time. Version 7 ids are random; version 8 ids are derived from the record's natural key (StableID), so a replayed delivery, or the twin of a record from another surface, has the same id. Deduplicate deliveries on it.",
	"Event.TS":      "When the thing happened, as its source says: the hook's clock, the log's timestamp, the triggering record's ts for a finding, the write time for heartbeats and summaries.",
	"Event.Type":    "The record type within its kind.",
	"Event.Account": "The identity the agent is signed in with. No collector in this release sets it; the Claude Code OpenTelemetry receiver records the organization as labels.org_id instead.",
	"Event.Labels":  "Facts that have no field of their own, as strings (hook_event, end_reason, rule_pack, context_for, first_seen and the others named in docs/EVENTS.md). Values pass the same redaction as every other string.",

	"Host.ID":   "Host identifier, meant to equal osquery's system_info.uuid so that records join to Fleet hosts: host_id from the configuration, SPOOR_HOST_ID, the host_id file the osquery extension writes, or the hardware UUID (on Linux without one, machine-id). Empty when nothing is derivable; the heartbeat label host_id_source names the source.",
	"Host.Name": "Host name: SPOOR_HOST_NAME when it is set to a plausible name (the Kubernetes node sensor sets it to the node's name), else the kernel's host name.",
	"User.Name": "Account name. With privacy.pseudonymize_users, a keyed pseudonym (removed when no key is configured).",

	"Agent.Name":    "Product name from the catalog, on process-monitor and inventory records.",
	"Agent.Version": "Version as the surface or the scan reported it.",
	"Agent.PID":     "Process id of the agent, on process-monitor records.",
	"Account.Org":   "Organization the account belongs to.",

	"Session.ID":           "The agent's own session id.",
	"Session.TurnID":       "Id of the current turn (a prompt and the work it caused), when the surface reports one.",
	"Session.CWD":          "Working directory of the session; a path under the acting user's home is written as ~/...",
	"Session.Model":        "Model the session uses, as the agent reports it.",
	"Session.SubagentID":   "Id of the subagent thread the record belongs to; absent on the main thread.",
	"Session.SubagentType": "Type or name of that subagent, as the agent reports it.",

	"Tool.MCPTool":      "Tool name on that MCP server, for kind mcp.",
	"Tool.OutputSHA256": "Keyed digest of the tool output (HMAC with the tenant key); absent without a key.",
	"Tool.OutputLen":    "Size of the tool output in bytes; rounded up to a power of four outside the full profile.",
	"Target.Hosts":      "Further distinct network hosts the call refers to; host holds the first.",
	"Prompt.Len":        "Length of the prompt in bytes; rounded up to a power of four outside the full profile (labels.len_bucketed).",

	"Outcome.Error":      "Error text the agent reported, redacted; at most 256 bytes outside the full profile.",
	"Outcome.DurationMS": "Duration of the call in milliseconds, when the surface reports it.",
	"Outcome.ExitCode":   "Exit status of the command, when the surface reports it.",

	"Process.PID":       "Process id. On hook records, the process that invoked the hook (the agent, or a shell it started); on process-monitor and exec records, the process itself.",
	"Process.PPID":      "Parent process id.",
	"Process.Name":      "Process name as the kernel reports it, which the process can set itself.",
	"Process.Exe":       "Path of the executable.",
	"Process.StartTime": "Start time of the process; with pid, the join key to EDR process telemetry.",
	"Process.User":      "Account the process runs as.",

	"Container.ID":        "Container id, from the process's cgroup (process monitor) or from the container a scan looks into.",
	"Container.Image":     "Image of the container. Not set by the collectors in this release.",
	"Container.Name":      "Name of the container. Not set by the collectors in this release.",
	"Container.Pod":       "Kubernetes pod name. Not set by the collectors in this release.",
	"Container.PodUID":    "Kubernetes pod UID, from the cgroup path; absent outside Kubernetes.",
	"Container.Namespace": "Kubernetes namespace. Not set by the collectors in this release.",
	"Container.Node":      "Kubernetes node name. Not set by the collectors in this release.",
	"Repo.Root":           "Root directory of the repository. Not set by the collectors in this release.",
	"Repo.Branch":         "Branch, when a surface reports it (Claude Code OpenTelemetry, numbat records).",

	"Asset.ID":        "Stable across scans for the same host, kind, identity, owner and location, so downstream can upsert on it.",
	"Asset.Name":      "Name of the asset: the product, the declared server, skill or plugin, or the file.",
	"Asset.Vendor":    "Vendor or publisher, when known.",
	"Asset.Version":   "Version, when known.",
	"Asset.Running":   "True when the scan saw a process of the product running.",
	"Asset.PID":       "The lowest pid of those processes.",
	"Asset.FirstSeen": "Not set by the scanner in this release (last_seen and change are).",
	"Asset.LastSeen":  "Time of the scan that saw the asset.",
	"Asset.Change":    "How the asset differs from the previous scan: new (also when there is no previous state), changed, unchanged (written by a full scan only) or removed (gone since the previous scan, reported by a full scan).",
	"Asset.Detail":    "Other facts about this kind of asset, as strings: for example project, plugin, marketplace, pinned, enabled, status or hooks_shadowed_by.",

	"MCP.Package":         "Package the runner launches (an npm or PyPI name, an image).",
	"MCP.Version":         "Version or tag of that package, when the declaration names one.",
	"MCP.URLHost":         "Host of the endpoint the client connects to (a remote transport, or the endpoint a stdio bridge is given).",
	"MCP.URLPath":         "Path of that endpoint, redacted.",
	"MCP.HeaderKeys":      "Names of the HTTP headers the declaration sets, never their values.",
	"MCP.HasInlineSecret": "True when a credential-shaped literal is written into the declaration itself (command line, arguments, environment or header values, headers helper, OAuth client secret, or a token in the URL) rather than referenced. The value is never written.",
	"MCP.Enabled":         "Whether the client has the server switched on, when its configuration says (false for a server on its disabled list).",

	"Check.Title":    "Title of the rule or check.",
	"Check.Severity": "Severity of the rule or check.",
	"Check.AgentID":  "Catalog id of the agent the checked item belongs to.",
	"Check.AssetID":  "asset.id of the inventory record that failed the check.",
	"Check.Expected": "What the check requires, when it says (the scanner's file-owner check does).",
	"Check.Actual":   "What was found: for an inventory rule, the evidence fields as name=value pairs separated by \"; \" (at most 512 bytes).",
	"Check.Owner":    "Account the checked item belongs to.",
	"Check.Remedy":   "What to do about it.",

	"Detection.RuleID":   "Id of the rule that matched: a rule from a pack, an id the engine itself writes (SPR-COV-901, SPR-COV-902) or a relayed one (numbat:<id>). See docs/RULES.md.",
	"Detection.Title":    "Title of the rule.",
	"Detection.Severity": "Severity of the rule.",
	"Detection.Category": "Category of the rule, for example execution.",
	"Detection.Enforced": "True only when spoor returned the response to the agent (guard mode); absent otherwise.",
	"Detection.Count":    "How many matches this record stands for: repeats inside rules.suppress_for are counted and carried on the next emission instead of being written again.",
	"Detection.Remedy":   "What to do about it.",

	"Health.SensorVersion": "Version of the spoor binary that wrote the record.",
	"Health.UptimeS":       "Seconds since the writing pipeline started.",
	"Health.Counters":      "Counters and gauges by name (see Counters in docs/EVENTS.md).",
	"Health.RulesCount":    "Number of loaded rules.",
	"Health.RulesHash":     "SHA-256 of the loaded rule set; findings carry its first 12 hex digits as labels.rules_hash.",
	"Health.CatalogVer":    "Version of the agent catalog.",
	"Health.LastScan":      "Time of the last inventory scan. Not set by the heartbeat writer in this release.",
	"Health.Detail":        "Free-text detail of a health.error.",

	"SurfaceStatus.LastEvent":   "When the collector last delivered, by the sensor's clock (the arrival of its last record; for the process monitor its last self-check, for the scan the scan's time), not a time a record claims.",
	"SurfaceStatus.Events":      "Records the collector delivered.",
	"SurfaceStatus.Errors":      "Errors the collector counted.",
	"SurfaceStatus.SchemaDrift": "True when the collector met input in a shape it does not know (an agent changed its log or telemetry format).",
	"SurfaceStatus.Reason":      "Why the status is not ok, as a code: for example config, kill_switch, checkpoint or procs_unreadable.",
	"Coverage.AgentID":          "Catalog id of the agent.",
	"Coverage.User":             "Account the row is about: its name, or its uid or SID when the name is unknown.",

	"Summary.Started":     "ts of the session's earliest activity record.",
	"Summary.Ended":       "ts of its latest activity record, on the final summary only.",
	"Summary.Events":      "Activity records counted into the summary.",
	"Summary.Prompts":     "prompt.submit records.",
	"Summary.Subagent":    "subagent.start records.",
	"Summary.HostClasses": "Distinct classes of the network hosts contacted.",
	"Summary.MCPServers":  "Distinct MCP servers called.",
	"Summary.MaxSeverity": "Highest severity among detections, signals included.",
	"Summary.Coverage":    "What the reporting surfaces amount to: covered (hooks and another surface), partial (hooks, or transcript or OpenTelemetry, alone) or blind (only the process monitor or osquery).",
}

// Untyped constant groups by name prefix.
var prefixEnums = []struct{ prefix, enum string }{
	{"Type", "EventType"},
	{"Class", "DetectionClass"},
	{"Sev", "Severity"},
}

// ---- facts from the source -------------------------------------------------

type enumValue struct{ Value, Const, Doc string }

type srcFacts struct {
	typeDoc  map[string]string
	fieldDoc map[string]map[string]string
	enums    map[string][]enumValue
	enumDoc  map[string]string
}

func docText(groups ...*ast.CommentGroup) string {
	var parts []string
	for _, g := range groups {
		if g == nil {
			continue
		}
		if s := strings.Join(strings.Fields(g.Text()), " "); s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " ")
}

// specDoc is a constant's comment: its own, or the declaration's when the
// declaration holds only this one spec ("// X is ...\nconst X = ...").
func specDoc(gd *ast.GenDecl, vs *ast.ValueSpec) string {
	doc := docText(vs.Doc, vs.Comment)
	if doc == "" && len(gd.Specs) == 1 {
		doc = docText(gd.Doc)
	}
	return doc
}

func readSourceFacts(t *testing.T) *srcFacts {
	t.Helper()
	f := &srcFacts{
		typeDoc:  map[string]string{},
		fieldDoc: map[string]map[string]string{},
		enums:    map[string][]enumValue{},
		enumDoc: map[string]string{
			"EventType":      "Event.Type: the activity types (Kind activity) and the types of the other kinds. detection.context is declared in internal/privacy. The Types table in docs/EVENTS.md says what each one means.",
			"DetectionClass": "Detection classes, lowest to highest (ClassRank).",
			"Severity":       "Severity levels, lowest to highest (SeverityRank).",
		},
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	var pkg []string
	for _, name := range files {
		if !strings.HasSuffix(name, "_test.go") {
			pkg = append(pkg, name)
		}
	}
	fset := token.NewFileSet()
	if err := readPackageFacts(fset, pkg, f); err != nil {
		t.Fatal(err)
	}
	// detection.context, from internal/privacy.
	readForeignConsts(t, fset, f, privacyContextSrc, "EventType", func(name string, typ ast.Expr) bool { return name == "TypeContext" })
	// The profile names, from internal/privacy: every constant of type
	// Profile, and the type's comment for the vocabulary.
	readForeignConsts(t, fset, f, privacyPolicySrc, "Profile", func(name string, typ ast.Expr) bool {
		id, ok := typ.(*ast.Ident)
		return ok && id.Name == "Profile"
	})
	for name, vals := range f.enums {
		seen := map[string]string{}
		for _, v := range vals {
			if prev, dup := seen[v.Value]; dup {
				t.Fatalf("closed vocabulary %s: %s and %s have the same value %q", name, prev, v.Const, v.Value)
			}
			seen[v.Value] = v.Const
		}
	}
	return f
}

// readPackageFacts reads type and field comments and the closed
// vocabularies from the given files of one package into f.
func readPackageFacts(fset *token.FileSet, files []string, f *srcFacts) error {
	var parsed []*ast.File
	for _, name := range files {
		af, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if err != nil {
			return err
		}
		parsed = append(parsed, af)
	}
	// Types first, so typed constants know which types are enums.
	named := map[string]bool{}
	for _, af := range parsed {
		for _, d := range af.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, sp := range gd.Specs {
				ts := sp.(*ast.TypeSpec)
				doc := docText(ts.Doc)
				if doc == "" && len(gd.Specs) == 1 {
					doc = docText(gd.Doc)
				}
				f.typeDoc[ts.Name.Name] = doc
				switch st := ts.Type.(type) {
				case *ast.StructType:
					fd := map[string]string{}
					for _, fl := range st.Fields.List {
						for _, n := range fl.Names {
							fd[n.Name] = docText(fl.Doc, fl.Comment)
						}
					}
					f.fieldDoc[ts.Name.Name] = fd
				case *ast.Ident:
					if st.Name == "string" {
						named[ts.Name.Name] = true
					}
				}
			}
		}
	}
	for _, af := range parsed {
		for _, d := range af.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok || gd.Tok != token.CONST {
				continue
			}
			// A spec with neither type nor values repeats the previous
			// one's (const ( A Kind = "a"; B )): it has that type too.
			prevType := ""
			for _, sp := range gd.Specs {
				vs := sp.(*ast.ValueSpec)
				implicit := vs.Type == nil && len(vs.Values) == 0
				if !implicit {
					prevType = ""
					if id, ok := vs.Type.(*ast.Ident); ok {
						prevType = id.Name
					} else if vs.Type == nil && len(vs.Values) > 0 {
						if call, ok := vs.Values[0].(*ast.CallExpr); ok {
							if id, ok := call.Fun.(*ast.Ident); ok && named[id.Name] {
								prevType = id.Name
							}
						}
					}
				}
				for i, n := range vs.Names {
					var val ast.Expr
					if i < len(vs.Values) {
						val = vs.Values[i]
					}
					typ := ""
					if id, ok := vs.Type.(*ast.Ident); ok {
						typ = id.Name
					} else if implicit {
						typ = prevType
					} else if vs.Type == nil {
						// KindX = Kind("x") declares a typed constant too.
						if call, ok := val.(*ast.CallExpr); ok && len(call.Args) == 1 {
							if id, ok := call.Fun.(*ast.Ident); ok && named[id.Name] {
								typ, val = id.Name, call.Args[0]
							}
						}
					}
					enum := ""
					switch {
					case named[typ]:
						enum = typ
					case typ == "" && vs.Type == nil:
						for _, p := range prefixEnums {
							if strings.HasPrefix(n.Name, p.prefix) {
								enum = p.enum
								break
							}
						}
					}
					if enum == "" {
						continue
					}
					// A constant of a vocabulary whose value go/ast cannot
					// read (another constant, an expression, an implicit
					// repetition) would be missing from the schema, which
					// would then reject records the code writes.
					val2, ok := stringLit(val)
					if !ok {
						return fmt.Errorf("%s: constant %s belongs to the closed vocabulary %s but its value is not a string literal, so the schema generator cannot read it: write it as one", fset.Position(n.Pos()), n.Name, enum)
					}
					f.enums[enum] = append(f.enums[enum], enumValue{Value: val2, Const: n.Name, Doc: specDoc(gd, vs)})
					if named[enum] && f.enumDoc[enum] == "" {
						f.enumDoc[enum] = f.typeDoc[enum]
					}
				}
			}
		}
	}
	return nil
}

// stringLit returns the value of a Go string literal.
func stringLit(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(lit.Value)
	return v, err == nil
}

// readForeignConsts adds to vocabulary enum the constants of file that keep
// selects, with the package name in front of the constant's name. A
// vocabulary that is a type there takes that type's comment. It is a fatal
// error when nothing is found or a selected value cannot be read.
func readForeignConsts(t *testing.T, fset *token.FileSet, f *srcFacts, file, enum string, keep func(name string, typ ast.Expr) bool) {
	t.Helper()
	af, err := parser.ParseFile(fset, file, nil, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	pkg := af.Name.Name
	found := 0
	for _, d := range af.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, sp := range gd.Specs {
			switch s := sp.(type) {
			case *ast.TypeSpec:
				if s.Name.Name == enum && f.enumDoc[enum] == "" {
					doc := docText(s.Doc)
					if doc == "" && len(gd.Specs) == 1 {
						doc = docText(gd.Doc)
					}
					f.enumDoc[enum] = doc
				}
			case *ast.ValueSpec:
				if gd.Tok != token.CONST {
					continue
				}
				for i, id := range s.Names {
					if !keep(id.Name, s.Type) {
						continue
					}
					var val ast.Expr
					if i < len(s.Values) {
						val = s.Values[i]
					}
					v, ok := stringLit(val)
					if !ok {
						t.Fatalf("%s: constant %s is not a string literal, so the schema generator cannot read it", fset.Position(id.Pos()), id.Name)
					}
					f.enums[enum] = append(f.enums[enum], enumValue{Value: v, Const: pkg + "." + id.Name, Doc: specDoc(gd, s)})
					found++
				}
			}
		}
	}
	if found == 0 {
		t.Fatalf("%s: no constants for the %s vocabulary found", file, enum)
	}
}

// ---- schema generation ------------------------------------------------------

// jobj is a JSON object that keeps its key order, so the generated file is
// stable and reads in Go field order.
type jobj struct {
	keys []string
	vals map[string]any
}

func newObj() *jobj { return &jobj{vals: map[string]any{}} }

func (o *jobj) set(k string, v any) *jobj {
	if _, ok := o.vals[k]; !ok {
		o.keys = append(o.keys, k)
	}
	o.vals[k] = v
	return o
}

func (o *jobj) MarshalJSON() ([]byte, error) {
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range o.keys {
		if i > 0 {
			b.WriteByte(',')
		}
		kb, err := marshalNoHTML(k)
		if err != nil {
			return nil, err
		}
		b.Write(kb)
		b.WriteByte(':')
		vb, err := marshalNoHTML(o.vals[k])
		if err != nil {
			return nil, err
		}
		b.Write(vb)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}

func marshalNoHTML(v any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return nil, err
	}
	return bytes.TrimRight(b.Bytes(), "\n"), nil
}

type fieldInfo struct {
	Go, JSON string
	Type     reflect.Type
	Required bool // no omitempty/omitzero: always written
	Doc      string
	Enum     string // closed vocabulary of an untyped string field
}

type schemaGen struct {
	t     *testing.T
	src   *srcFacts
	skel  map[string]map[string]bool // struct name -> Go fields a skeleton writer sets
	defs  map[string]*jobj
	order []string // struct defs in first-reference order (for the doc)
	enums []string // enums in first-reference order
	seen  map[string]bool
}

var (
	timeType  = reflect.TypeOf(Time{})
	eventPath = reflect.TypeOf(Event{}).PkgPath()
)

// fields lists the JSON fields of a struct type.
func (g *schemaGen) fields(t reflect.Type) []fieldInfo {
	var out []fieldInfo
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		if !sf.IsExported() {
			continue
		}
		tag := sf.Tag.Get("json")
		if tag == "-" {
			continue
		}
		if sf.Anonymous {
			g.t.Fatalf("%s.%s: embedded fields are not supported by the schema generator", t.Name(), sf.Name)
		}
		name, opts, _ := strings.Cut(tag, ",")
		if name == "" {
			name = sf.Name
		}
		req := true
		for _, o := range strings.Split(opts, ",") {
			if o == "omitempty" || o == "omitzero" {
				req = false
			}
		}
		doc := g.src.fieldDoc[t.Name()][sf.Name]
		if doc == "" {
			doc = fieldNotes[t.Name()+"."+sf.Name]
		}
		if doc == "" {
			doc = g.typeDocOf(sf.Type)
		}
		out = append(out, fieldInfo{
			Go: sf.Name, JSON: name, Type: sf.Type, Required: req,
			Doc:  doc,
			Enum: fieldEnums[t.Name()+"."+sf.Name],
		})
	}
	return out
}

// typeDocOf is the comment of the named type of this package a field holds
// (through pointers, slices and maps); Time's comment is about encoding,
// not about any field, and is never used.
func (g *schemaGen) typeDocOf(t reflect.Type) string {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Map {
		t = t.Elem()
	}
	if t == timeType || t.PkgPath() != eventPath || t.Name() == "" {
		return ""
	}
	return g.src.typeDoc[t.Name()]
}

func ref(name string) *jobj { return newObj().set("$ref", "#/$defs/"+name) }

func (g *schemaGen) enumRef(name string) *jobj {
	vals := g.src.enums[name]
	if len(vals) == 0 {
		g.t.Fatalf("closed vocabulary %s has no constants in internal/event", name)
	}
	if !g.seen["enum:"+name] {
		g.seen["enum:"+name] = true
		g.enums = append(g.enums, name)
		e := make([]string, len(vals))
		for i, v := range vals {
			e[i] = v.Value
		}
		d := newObj().set("type", "string")
		if doc := g.src.enumDoc[name]; doc != "" {
			d.set("description", doc)
		}
		d.set("enum", e)
		g.defs[name] = d
	}
	return ref(name)
}

func (g *schemaGen) schemaFor(t reflect.Type, enum string) *jobj {
	if enum != "" {
		return g.enumRef(enum)
	}
	if t == timeType {
		if !g.seen["Time"] {
			g.seen["Time"] = true
			g.defs["Time"] = newObj().
				set("type", "string").
				set("description", "RFC 3339 in UTC with exactly six fraction digits (TimeLayout), the form Fluent Bit's strict parser needs. Optional time fields are left out when unset. The pattern checks the range of every component, month and day together, and admits February 29 in every year; a validator that asserts format date-time also rejects it outside leap years.").
				set("format", "date-time").
				set("pattern", timePattern)
		}
		return ref("Time")
	}
	switch t.Kind() {
	case reflect.String:
		if t.PkgPath() == eventPath && t.Name() != "" && len(g.src.enums[t.Name()]) > 0 {
			return g.enumRef(t.Name())
		}
		return newObj().set("type", "string")
	case reflect.Bool:
		return newObj().set("type", "boolean")
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return newObj().set("type", "integer")
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		return newObj().set("type", "integer").set("minimum", 0)
	case reflect.Float32, reflect.Float64:
		return newObj().set("type", "number")
	case reflect.Pointer:
		return g.schemaFor(t.Elem(), "")
	case reflect.Slice:
		return newObj().set("type", "array").set("items", g.schemaFor(t.Elem(), ""))
	case reflect.Map:
		if t.Key().Kind() != reflect.String {
			g.t.Fatalf("map %s: only string keys encode as JSON objects", t)
		}
		o := newObj().set("type", "object")
		if t.Elem().Kind() != reflect.Interface {
			o.set("additionalProperties", g.schemaFor(t.Elem(), ""))
		}
		return o
	case reflect.Interface:
		return newObj() // any JSON value
	case reflect.Struct:
		g.structDef(t)
		return ref(t.Name())
	}
	g.t.Fatalf("type %s (%s) is not supported by the schema generator", t, t.Kind())
	return nil
}

func (g *schemaGen) structDef(t reflect.Type) {
	name := t.Name()
	if g.seen[name] {
		return
	}
	g.seen[name] = true
	g.order = append(g.order, name)
	d := newObj().set("type", "object")
	g.defs[name] = d // before the fields: a recursive type must find it
	if doc := g.src.typeDoc[name]; doc != "" {
		d.set("description", doc)
	}
	props := newObj()
	var req []string
	for _, f := range g.fields(t) {
		p := g.schemaFor(f.Type, f.Enum)
		k := f.Type.Kind()
		if f.Required && (k == reflect.Pointer || k == reflect.Slice || k == reflect.Map) {
			// A nil value of a field without omitempty encodes as null.
			p = newObj().set("anyOf", []any{p, newObj().set("type", "null")})
		}
		if name == "Event" && f.Go == "V" {
			p = newObj().set("type", "integer").set("const", SchemaVersion)
		}
		if f.Doc != "" {
			p.set("description", f.Doc)
		}
		props.set(f.JSON, p)
		if f.Required {
			req = append(req, f.JSON)
		}
	}
	d.set("properties", props)
	if len(req) > 0 {
		d.set("required", req)
	}
	d.set("additionalProperties", false)
}

// generateSchema returns the schema document and the generator state.
func generateSchema(t *testing.T) ([]byte, *schemaGen) {
	t.Helper()
	g := &schemaGen{t: t, src: readSourceFacts(t), skel: readSkeletonFields(t), defs: map[string]*jobj{}, seen: map[string]bool{}}
	g.structDef(reflect.TypeOf(Event{}))
	// What each profile never writes, as one branch per profile: a record
	// must name the profile it was written under and carry none of that
	// profile's never-written fields.
	g.defs["Event"].set("anyOf", g.profileBranches())
	// The content-free stand-in the privacy stage and the sinks write when a
	// record cannot be redacted or cut to the line cap.
	g.skeletonDef(reflect.TypeOf(Event{}))

	names := make([]string, 0, len(g.defs))
	for n := range g.defs {
		names = append(names, n)
	}
	sort.Strings(names)
	defs := newObj()
	for _, n := range names {
		defs.set(n, g.defs[n])
	}
	root := newObj().
		set("$schema", "https://json-schema.org/draft/2020-12/schema").
		set("title", "spoor event record").
		set("description", fmt.Sprintf("One NDJSON line written by spoor (outbox segments, local ring, stdout, spoor detect --ndjson). Schema version %d (field v). Generated from internal/event by `go test ./internal/event -run TestSchema -update`; do not edit by hand. Reference: docs/EVENTS.md.", SchemaVersion)).
		set("anyOf", []any{ref("Event"), ref("Skeleton")}).
		set("$defs", defs)
	b, err := marshalNoHTML(root)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := json.Indent(&out, b, "", "  "); err != nil {
		t.Fatal(err)
	}
	out.WriteByte('\n')
	return out.Bytes(), g
}

// profileBranches is one anyOf branch per privacy profile: privacy names
// the profile, and the fields that profile never writes are absent.
func (g *schemaGen) profileBranches() []any {
	profiles := map[string]bool{}
	var out []any
	for _, p := range g.src.enums["Profile"] {
		profiles[p.Value] = true
		never, ok := neverWritten[p.Value]
		if !ok {
			g.t.Fatalf("privacy profile %q (%s) has no entry in neverWritten: say which fields it never writes", p.Value, p.Const)
		}
		props := newObj().set("privacy", newObj().set("const", p.Value))
		subs := map[string]*jobj{}
		var objs []string
		for _, path := range never {
			if !jsonFieldExists(path) {
				g.t.Fatalf("neverWritten[%q]: %s is not a field of the record", p.Value, path)
			}
			obj, field, _ := strings.Cut(path, ".")
			if subs[obj] == nil {
				subs[obj] = newObj()
				objs = append(objs, obj)
			}
			subs[obj].set(field, false)
		}
		for _, o := range objs {
			props.set(o, newObj().set("properties", subs[o]))
		}
		out = append(out, newObj().
			set("description", fmt.Sprintf("Written under the %s profile.", p.Value)).
			set("properties", props).
			set("required", []string{"privacy"}))
	}
	for p := range neverWritten {
		if !profiles[p] {
			g.t.Fatalf("neverWritten names %q, which is not a privacy profile in %s", p, privacyPolicySrc)
		}
	}
	return out
}

// jsonFieldExists reports whether a dotted path of JSON names
// ("prompt.text") is a field of the record.
func jsonFieldExists(path string) bool {
	t := reflect.TypeOf(Event{})
	for _, name := range strings.Split(path, ".") {
		for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct {
			return false
		}
		found := false
		for i := 0; i < t.NumField(); i++ {
			sf := t.Field(i)
			if n, _, _ := strings.Cut(sf.Tag.Get("json"), ","); n == name && sf.IsExported() {
				t, found = sf.Type, true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// eventStructs maps the name of every struct type reachable from Event to
// the type.
func eventStructs() map[string]reflect.Type {
	out := map[string]reflect.Type{}
	var walk func(t reflect.Type)
	walk = func(t reflect.Type) {
		for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Map {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct || t == timeType || out[t.Name()] != nil {
			return
		}
		out[t.Name()] = t
		for i := 0; i < t.NumField(); i++ {
			walk(t.Field(i).Type)
		}
	}
	walk(reflect.TypeOf(Event{}))
	return out
}

// eventLit returns T and the literal for event.T{...} or &event.T{...}.
func eventLit(e ast.Expr) (string, *ast.CompositeLit) {
	if u, ok := e.(*ast.UnaryExpr); ok && u.Op == token.AND {
		e = u.X
	}
	cl, ok := e.(*ast.CompositeLit)
	if !ok {
		return "", nil
	}
	sel, ok := cl.Type.(*ast.SelectorExpr)
	if !ok {
		return "", nil
	}
	if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "event" {
		return "", nil
	}
	return sel.Sel.Name, cl
}

// structField is the struct type a field holds, through a pointer; nil for
// any other field (Time counts as a value).
func structField(sf reflect.StructField) reflect.Type {
	t := sf.Type
	if t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.Kind() == reflect.Struct && t != timeType {
		return t
	}
	if t.Kind() == reflect.Slice || t.Kind() == reflect.Map {
		if e := t.Elem(); e.Kind() == reflect.Struct || (e.Kind() == reflect.Pointer && e.Elem().Kind() == reflect.Struct) {
			return e
		}
	}
	return nil
}

// readSkeletonFields reads, from the source of the skeleton writers, which
// fields of which struct they set. A sub-object must be built field by field
// in the writer (&event.Host{ID: ...}): one copied whole could carry
// anything, and is an error here rather than an open schema.
func readSkeletonFields(t *testing.T) map[string]map[string]bool {
	t.Helper()
	set, err := readSkeletonFieldsFrom(skeletonWriters)
	if err != nil {
		t.Fatal(err)
	}
	return set
}

type skeletonWriter struct {
	file  string
	funcs []string
}

func readSkeletonFieldsFrom(writers []skeletonWriter) (map[string]map[string]bool, error) {
	var problems []string
	fail := func(format string, a ...any) { problems = append(problems, fmt.Sprintf(format, a...)) }
	structs := eventStructs()
	set := map[string]map[string]bool{}
	add := func(typ, field string) {
		if set[typ] == nil {
			set[typ] = map[string]bool{}
		}
		set[typ][field] = true
	}
	fset := token.NewFileSet()
	for _, w := range writers {
		af, err := parser.ParseFile(fset, w.file, nil, 0)
		if err != nil {
			return nil, err
		}
		decls := map[string]*ast.FuncDecl{}
		for _, d := range af.Decls {
			if fd, ok := d.(*ast.FuncDecl); ok {
				decls[fd.Name.Name] = fd
			}
		}
		writer := map[string]bool{}
		for _, name := range w.funcs {
			writer[name] = true
		}
		for _, name := range w.funcs {
			fd := decls[name]
			if fd == nil || fd.Body == nil {
				fail("%s: func %s not found: update skeletonWriters in internal/event/schema_test.go", w.file, name)
				continue
			}
			where := func(n ast.Node) string { return fmt.Sprintf("%s (%s)", fset.Position(n.Pos()), name) }
			// checkValue: a struct-valued field must be set from a literal
			// of its own type, which the walk below then reads.
			checkValue := func(sf reflect.StructField, v ast.Expr) {
				st := structField(sf)
				if st == nil {
					return
				}
				if typ, _ := eventLit(v); typ != st.Name() || sf.Type.Kind() == reflect.Slice || sf.Type.Kind() == reflect.Map {
					fail("%s: field %s is not set from an event.%s literal; the schema generator can only bound sub-objects a skeleton writer builds field by field", where(v), sf.Name, st.Name())
				}
			}
			// Identifiers that hold the skeleton being built.
			holders := map[string]bool{}
			ast.Inspect(fd.Body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CompositeLit:
					typ, _ := eventLit(x)
					if typ == "" {
						return true
					}
					st, ok := structs[typ]
					if !ok {
						fail("%s: event.%s is not a struct of the record", where(x), typ)
						return true
					}
					if set[typ] == nil {
						set[typ] = map[string]bool{}
					}
					for _, el := range x.Elts {
						kv, ok := el.(*ast.KeyValueExpr)
						if !ok {
							fail("%s: event.%s literal without field names", where(el), typ)
							continue
						}
						key, ok := kv.Key.(*ast.Ident)
						if !ok {
							fail("%s: unexpected key in event.%s literal", where(kv), typ)
							continue
						}
						sf, ok := st.FieldByName(key.Name)
						if !ok {
							fail("%s: event.%s has no field %s", where(kv), typ, key.Name)
							continue
						}
						checkValue(sf, kv.Value)
						add(typ, key.Name)
					}
				case *ast.AssignStmt:
					for i, l := range x.Lhs {
						var rhs ast.Expr
						if len(x.Rhs) == len(x.Lhs) {
							rhs = x.Rhs[i]
						}
						if id, ok := l.(*ast.Ident); ok && rhs != nil {
							typ, _ := eventLit(rhs)
							call, isCall := rhs.(*ast.CallExpr)
							if typ == "Event" {
								holders[id.Name] = true
							} else if isCall {
								if fn, ok := call.Fun.(*ast.Ident); ok && writer[fn.Name] {
									holders[id.Name] = true
								}
							}
							continue
						}
						target, indexed := l, false
						if ix, ok := target.(*ast.IndexExpr); ok {
							target, indexed = ix.X, true
						}
						sel, ok := target.(*ast.SelectorExpr)
						if !ok {
							continue
						}
						if id, ok := sel.X.(*ast.Ident); !ok || !holders[id.Name] {
							continue
						}
						sf, ok := structs["Event"].FieldByName(sel.Sel.Name)
						if !ok {
							fail("%s: event.Event has no field %s", where(sel), sel.Sel.Name)
							continue
						}
						if !indexed && rhs != nil {
							checkValue(sf, rhs)
						}
						add("Event", sel.Sel.Name)
					}
				}
				return true
			})
		}
	}
	for _, f := range []string{"Truncated", "Privacy"} {
		if !set["Event"][f] {
			fail("no skeleton writer sets Event.%s; the Skeleton definition requires it", f)
		}
	}
	if len(problems) > 0 {
		return nil, fmt.Errorf("reading the skeleton writers:\n\t%s", strings.Join(problems, "\n\t"))
	}
	return set, nil
}

// skeletonDef defines the skeleton variant of struct t and returns its
// name: only the fields a skeleton writer sets (and those the encoder
// always writes), closed like every struct object, and with each
// vocabulary relaxed to its values and their prefixes, because the writers
// clip strings to a byte budget.
func (g *schemaGen) skeletonDef(t reflect.Type) string {
	name := "Skeleton"
	if t.Name() != "Event" {
		name += t.Name()
	}
	if g.seen["skeleton:"+name] {
		return name
	}
	g.seen["skeleton:"+name] = true
	d := newObj().set("type", "object")
	g.defs[name] = d
	if t.Name() == "Event" {
		d.set("description", "Content-free stand-in written when redaction failed or a record could not be brought under the line cap. It carries only the fields the skeleton writers set (internal/sink, shrink.go: skeleton; internal/privacy, emit.go: skeleton and buildSkeleton), read from their source when this schema is generated; its truncated list contains \"*\" and, when the privacy stage wrote it, a label names the reason (privacy_error or line_cap). A writer may clip strings, so a vocabulary field holds a value of its vocabulary, a prefix of one, or nothing.")
	} else {
		d.set("description", fmt.Sprintf("The fields of %s a skeleton keeps.", t.Name()))
	}
	props := newObj()
	var req []string
	for _, f := range g.fields(t) {
		if !f.Required && !g.skel[t.Name()][f.Go] {
			continue
		}
		var p *jobj
		switch {
		case t.Name() == "Event" && f.Go == "V":
			p = newObj().set("type", "integer").set("const", SchemaVersion)
		case t.Name() == "Event" && f.Go == "Truncated":
			p = g.skeletonSchemaFor(f.Type, f.Enum).set("contains", newObj().set("const", "*"))
		case t.Name() == "Event" && f.Go == "Privacy":
			// Both writers take the profile name as the privacy stage
			// stamped it; no profile name is long enough to be clipped.
			p = g.enumRef("Profile")
		default:
			p = g.skeletonSchemaFor(f.Type, f.Enum)
		}
		k := f.Type.Kind()
		if f.Required && (k == reflect.Pointer || k == reflect.Slice || k == reflect.Map) {
			p = newObj().set("anyOf", []any{p, newObj().set("type", "null")})
		}
		props.set(f.JSON, p)
		if f.Required {
			req = append(req, f.JSON)
		}
	}
	if t.Name() == "Event" {
		req = append(req, "privacy", "truncated")
	}
	d.set("properties", props)
	if len(req) > 0 {
		d.set("required", req)
	}
	d.set("additionalProperties", false)
	return name
}

func (g *schemaGen) skeletonSchemaFor(t reflect.Type, enum string) *jobj {
	if enum != "" {
		return g.prefixRef(enum)
	}
	if t == timeType {
		return g.schemaFor(t, "")
	}
	switch t.Kind() {
	case reflect.String:
		if t.PkgPath() == eventPath && t.Name() != "" && len(g.src.enums[t.Name()]) > 0 {
			return g.prefixRef(t.Name())
		}
	case reflect.Pointer:
		return g.skeletonSchemaFor(t.Elem(), "")
	case reflect.Slice:
		return newObj().set("type", "array").set("items", g.skeletonSchemaFor(t.Elem(), ""))
	case reflect.Map:
		o := newObj().set("type", "object")
		if t.Elem().Kind() != reflect.Interface {
			o.set("additionalProperties", g.skeletonSchemaFor(t.Elem(), ""))
		}
		return o
	case reflect.Struct:
		return ref(g.skeletonDef(t))
	}
	return g.schemaFor(t, "")
}

// prefixRef is the skeleton form of a closed vocabulary: a value, a prefix
// of one, or empty.
func (g *schemaGen) prefixRef(enum string) *jobj {
	name := enum + "Prefix"
	if !g.seen["prefix:"+name] {
		g.seen["prefix:"+name] = true
		var vals []string
		for _, v := range g.src.enums[enum] {
			vals = append(vals, v.Value)
		}
		if len(vals) == 0 {
			g.t.Fatalf("closed vocabulary %s has no constants", enum)
		}
		g.defs[name] = newObj().
			set("type", "string").
			set("description", fmt.Sprintf("In a skeleton: a %s value, a prefix of one, or empty (a skeleton writer may clip its strings).", enum)).
			set("pattern", prefixPattern(vals))
	}
	return ref(name)
}

// prefixPattern matches exactly the strings that are a prefix of one of
// vals, the empty string included. It is the vocabulary's trie written as
// nested optional groups: "ab" and "b" give ^(?:a(?:b)?|b)?$.
func prefixPattern(vals []string) string {
	type node struct{ next map[byte]*node }
	root := &node{next: map[byte]*node{}}
	for _, v := range vals {
		n := root
		for i := 0; i < len(v); i++ {
			c := n.next[v[i]]
			if c == nil {
				c = &node{next: map[byte]*node{}}
				n.next[v[i]] = c
			}
			n = c
		}
	}
	var re func(n *node) string
	re = func(n *node) string {
		if len(n.next) == 0 {
			return ""
		}
		keys := make([]int, 0, len(n.next))
		for c := range n.next {
			keys = append(keys, int(c))
		}
		sort.Ints(keys)
		alts := make([]string, 0, len(keys))
		for _, c := range keys {
			alts = append(alts, regexp.QuoteMeta(string(rune(c)))+re(n.next[byte(c)]))
		}
		return "(?:" + strings.Join(alts, "|") + ")?"
	}
	return "^" + re(root) + "$"
}

// ---- validation -------------------------------------------------------------

// validator checks a decoded JSON value (json.Decoder.UseNumber) against
// the subset of JSON Schema 2020-12 the generator emits. Only local $refs
// ("#/$defs/<name>") are resolved.
type validator struct {
	root map[string]any
	re   map[string]*regexp.Regexp
}

var knownKeywords = map[string]bool{
	"$schema": true, "$defs": true, "title": true, "description": true, "$comment": true,
	// format is asserted, not only an annotation: date-time with
	// time.Parse (which knows month lengths and leap years); any other
	// format is an unimplemented keyword.
	"format": true,
	"$ref":   true, "anyOf": true, "type": true, "const": true, "enum": true,
	"pattern": true, "minimum": true, "properties": true, "required": true,
	"additionalProperties": true, "items": true, "contains": true,
}

func newValidator(schema []byte) (*validator, error) {
	var root map[string]any
	dec := json.NewDecoder(bytes.NewReader(schema))
	dec.UseNumber()
	if err := dec.Decode(&root); err != nil {
		return nil, err
	}
	return &validator{root: root, re: map[string]*regexp.Regexp{}}, nil
}

func (v *validator) Validate(x any) []string {
	return v.check(v.root, x, "", 0)
}

// ValidateDef checks x against one definition only (#/$defs/<name>).
func (v *validator) ValidateDef(name string, x any) []string {
	return v.check(map[string]any{"$ref": "#/$defs/" + name}, x, "", 0)
}

func (v *validator) check(s any, x any, path string, depth int) []string {
	at := path
	if at == "" {
		at = "(record)"
	}
	if depth > 64 {
		return []string{at + ": schema nesting too deep"}
	}
	switch sb := s.(type) {
	case bool:
		if sb {
			return nil
		}
		return []string{at + ": not allowed"}
	case map[string]any:
	default:
		return []string{at + ": invalid schema node"}
	}
	sm := s.(map[string]any)
	keys := make([]string, 0, len(sm))
	for k := range sm {
		if !knownKeywords[k] {
			return []string{fmt.Sprintf("%s: schema keyword %q is not implemented by the validator", at, k)}
		}
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var errs []string
	for _, k := range keys {
		kw := sm[k]
		switch k {
		case "$ref":
			name, ok := strings.CutPrefix(kw.(string), "#/$defs/")
			defs, _ := v.root["$defs"].(map[string]any)
			def, found := defs[name]
			if !ok || !found {
				errs = append(errs, fmt.Sprintf("%s: unresolvable $ref %v", at, kw))
				continue
			}
			errs = append(errs, v.check(def, x, path, depth+1)...)
		case "anyOf":
			var branchErrs []string
			matched := false
			for i, b := range kw.([]any) {
				e := v.check(b, x, path, depth+1)
				if len(e) == 0 {
					matched = true
					break
				}
				branchErrs = append(branchErrs, fmt.Sprintf("[branch %d: %s]", i, strings.Join(e, "; ")))
			}
			if !matched {
				errs = append(errs, fmt.Sprintf("%s: no anyOf branch matched %s", at, strings.Join(branchErrs, " ")))
			}
		case "type":
			var types []string
			switch tv := kw.(type) {
			case string:
				types = []string{tv}
			case []any:
				for _, e := range tv {
					types = append(types, e.(string))
				}
			}
			ok := false
			for _, ty := range types {
				ok = ok || hasJSONType(x, ty)
			}
			if !ok {
				errs = append(errs, fmt.Sprintf("%s: %s is not of type %s", at, jsonTypeName(x), strings.Join(types, "|")))
			}
		case "const":
			if !jsonEqual(kw, x) {
				errs = append(errs, fmt.Sprintf("%s: %s, want %v", at, short(x), kw))
			}
		case "enum":
			ok := false
			for _, e := range kw.([]any) {
				ok = ok || jsonEqual(e, x)
			}
			if !ok {
				errs = append(errs, fmt.Sprintf("%s: %s is not in the closed vocabulary", at, short(x)))
			}
		case "format":
			if kw != "date-time" {
				errs = append(errs, fmt.Sprintf("%s: format %v is not implemented by the validator", at, kw))
				continue
			}
			str, isStr := x.(string)
			if !isStr {
				continue
			}
			if _, err := time.Parse(time.RFC3339Nano, str); err != nil {
				errs = append(errs, fmt.Sprintf("%s: %s is not an RFC 3339 date-time (%v)", at, short(x), err))
			}
		case "pattern":
			str, isStr := x.(string)
			if !isStr {
				continue
			}
			p := kw.(string)
			re := v.re[p]
			if re == nil {
				var err error
				if re, err = regexp.Compile(p); err != nil {
					errs = append(errs, fmt.Sprintf("%s: bad pattern: %v", at, err))
					continue
				}
				v.re[p] = re
			}
			if !re.MatchString(str) {
				errs = append(errs, fmt.Sprintf("%s: %s does not match %s", at, short(x), p))
			}
		case "minimum":
			n, isNum := x.(json.Number)
			if !isNum {
				continue
			}
			got, ok1 := new(big.Rat).SetString(n.String())
			lim, ok2 := new(big.Rat).SetString(fmt.Sprint(kw))
			if !ok1 || !ok2 || got.Cmp(lim) < 0 {
				errs = append(errs, fmt.Sprintf("%s: %s is below the minimum %v", at, n, kw))
			}
		case "properties", "required", "additionalProperties":
			obj, isObj := x.(map[string]any)
			if !isObj {
				continue
			}
			props, _ := sm["properties"].(map[string]any)
			switch k {
			case "properties":
				names := make([]string, 0, len(obj))
				for name := range obj {
					names = append(names, name)
				}
				sort.Strings(names)
				for _, name := range names {
					if ps, ok := props[name]; ok {
						errs = append(errs, v.check(ps, obj[name], joinPath(path, name), depth+1)...)
					}
				}
			case "required":
				for _, r := range kw.([]any) {
					if _, ok := obj[r.(string)]; !ok {
						errs = append(errs, fmt.Sprintf("%s: required field %q is missing", at, r))
					}
				}
			case "additionalProperties":
				names := make([]string, 0, len(obj))
				for name := range obj {
					if _, ok := props[name]; !ok {
						names = append(names, name)
					}
				}
				sort.Strings(names)
				for _, name := range names {
					if b, isBool := kw.(bool); isBool && !b {
						errs = append(errs, fmt.Sprintf("%s: field %q is not part of the schema", at, name))
						continue
					}
					errs = append(errs, v.check(kw, obj[name], joinPath(path, name), depth+1)...)
				}
			}
		case "items":
			arr, isArr := x.([]any)
			if !isArr {
				continue
			}
			for i, e := range arr {
				errs = append(errs, v.check(kw, e, fmt.Sprintf("%s[%d]", path, i), depth+1)...)
			}
		case "contains":
			arr, isArr := x.([]any)
			if !isArr {
				continue
			}
			ok := false
			for _, e := range arr {
				ok = ok || len(v.check(kw, e, path, depth+1)) == 0
			}
			if !ok {
				errs = append(errs, fmt.Sprintf("%s: no element matches %s", at, short(kw)))
			}
		}
	}
	return errs
}

func joinPath(p, k string) string {
	if p == "" {
		return k
	}
	return p + "." + k
}

func hasJSONType(x any, ty string) bool {
	switch ty {
	case "object":
		_, ok := x.(map[string]any)
		return ok
	case "array":
		_, ok := x.([]any)
		return ok
	case "string":
		_, ok := x.(string)
		return ok
	case "boolean":
		_, ok := x.(bool)
		return ok
	case "null":
		return x == nil
	case "number":
		_, ok := x.(json.Number)
		return ok
	case "integer":
		n, ok := x.(json.Number)
		if !ok {
			return false
		}
		r, ok := new(big.Rat).SetString(n.String())
		return ok && r.IsInt()
	}
	return false
}

func jsonTypeName(x any) string {
	switch x.(type) {
	case map[string]any:
		return "object"
	case []any:
		return "array"
	case string:
		return "string " + short(x)
	case bool:
		return "boolean"
	case json.Number:
		return "number " + short(x)
	case nil:
		return "null"
	}
	return fmt.Sprintf("%T", x)
}

func jsonEqual(a, b any) bool {
	if na, ok := numOf(a); ok {
		nb, ok := numOf(b)
		return ok && na.Cmp(nb) == 0
	}
	switch av := a.(type) {
	case []any:
		bv, ok := b.([]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for i := range av {
			if !jsonEqual(av[i], bv[i]) {
				return false
			}
		}
		return true
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok || len(av) != len(bv) {
			return false
		}
		for k, x := range av {
			y, ok := bv[k]
			if !ok || !jsonEqual(x, y) {
				return false
			}
		}
		return true
	}
	return a == b
}

func numOf(x any) (*big.Rat, bool) {
	switch n := x.(type) {
	case json.Number:
		return new(big.Rat).SetString(n.String())
	case float64:
		return new(big.Rat).SetFloat64(n), true
	case int:
		return new(big.Rat).SetInt64(int64(n)), true
	}
	return nil, false
}

func short(x any) string {
	b, _ := json.Marshal(x)
	s := string(b)
	if len(s) > 80 {
		s = s[:80] + "..."
	}
	return s
}

func decodeJSON(b []byte) (any, error) {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.UseNumber()
	var x any
	if err := dec.Decode(&x); err != nil {
		return nil, err
	}
	if dec.More() {
		return nil, fmt.Errorf("trailing data after the JSON value")
	}
	return x, nil
}

// ---- helpers ----------------------------------------------------------------

func readText(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	// A Windows checkout may have CRLF line ends; the files are LF.
	return strings.ReplaceAll(string(b), "\r\n", "\n")
}

func firstDiff(a, b string) string {
	al, bl := strings.Split(a, "\n"), strings.Split(b, "\n")
	for i := 0; i < len(al) || i < len(bl); i++ {
		var x, y string
		if i < len(al) {
			x = al[i]
		}
		if i < len(bl) {
			y = bl[i]
		}
		if x != y {
			return fmt.Sprintf("line %d:\n  committed: %s\n  generated: %s", i+1, x, y)
		}
	}
	return "(none)"
}

type exampleLine struct {
	file string
	line int
	raw  string
	val  any
}

func readExamples(t *testing.T) []exampleLine {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(examplesDir, "*.ndjson"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatalf("no example records under %s (docs/schema/examples/regen.sh writes them)", examplesDir)
	}
	sort.Strings(files)
	var out []exampleLine
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		n := 0
		for sc.Scan() {
			n++
			raw := strings.TrimRight(sc.Text(), "\r")
			if raw == "" {
				continue
			}
			x, err := decodeJSON([]byte(raw))
			if err != nil {
				t.Errorf("%s:%d: %v", filepath.Base(f), n, err)
				continue
			}
			out = append(out, exampleLine{file: filepath.Base(f), line: n, raw: raw, val: x})
		}
		if err := sc.Err(); err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		fh.Close()
	}
	return out
}

func getPath(x any, path ...string) (any, bool) {
	for _, p := range path {
		m, ok := x.(map[string]any)
		if !ok {
			return nil, false
		}
		if x, ok = m[p]; !ok {
			return nil, false
		}
	}
	return x, true
}

// ---- tests ------------------------------------------------------------------

func TestSchemaFileIsGenerated(t *testing.T) {
	got, _ := generateSchema(t)
	if *updateSchema {
		if err := os.MkdirAll(filepath.Dir(schemaFile), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(schemaFile, got, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want := readText(t, schemaFile)
	if want != string(got) {
		t.Fatalf("docs/schema/event.schema.json is not what internal/event generates; run\n\tgo test ./internal/event -run TestSchema -update\nfirst difference at %s", firstDiff(want, string(got)))
	}
}

func TestSchemaValidatesExampleRecords(t *testing.T) {
	schema, _ := generateSchema(t)
	v, err := newValidator(schema)
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]int{}
	types := map[string]int{}
	for _, ex := range readExamples(t) {
		for _, e := range v.Validate(ex.val) {
			t.Errorf("%s:%d: %s", ex.file, ex.line, e)
		}
		// The Go type reads every field back.
		dec := json.NewDecoder(strings.NewReader(ex.raw))
		dec.DisallowUnknownFields()
		var ev Event
		if err := dec.Decode(&ev); err != nil {
			t.Errorf("%s:%d: decode into event.Event: %v", ex.file, ex.line, err)
			continue
		}
		kinds[string(ev.Kind)]++
		types[ev.Type]++

		// What the profiles promise, checked on the binary's own output
		// (the schema checks the same; this names the field outright).
		prof, _ := getPath(ex.val, "privacy")
		ps, _ := prof.(string)
		for _, p := range neverWritten[ps] {
			if _, ok := getPath(ex.val, strings.Split(p, ".")...); ok {
				t.Errorf("%s:%d: %s record carries %s", ex.file, ex.line, ps, p)
			}
		}
		// The outbox of the minimal profile has no activity stream.
		if prof == "minimal" && ev.Kind == KindActivity {
			t.Errorf("%s:%d: an activity record in the minimal profile's output", ex.file, ex.line)
		}
	}
	for _, k := range Streams {
		if kinds[k] == 0 {
			t.Errorf("the examples have no %s record: regenerate them (docs/schema/examples/regen.sh)", k)
		}
	}
	t.Logf("validated example records by kind %v, by type %v", kinds, types)
}

// TestSchemaValidatesGivenFiles checks other NDJSON against the schema, for
// example a live outbox: SPOOR_SCHEMA_VALIDATE is a list of files or
// directories (their *.ndjson files) separated by the OS path-list
// separator. Skipped when unset; finding no record at all fails, so a
// mistyped or empty directory is never reported as a pass.
func TestSchemaValidatesGivenFiles(t *testing.T) {
	spec := os.Getenv("SPOOR_SCHEMA_VALIDATE")
	if spec == "" {
		t.Skip("set SPOOR_SCHEMA_VALIDATE to files or directories of NDJSON records")
	}
	schema, _ := generateSchema(t)
	v, err := newValidator(schema)
	if err != nil {
		t.Fatal(err)
	}
	var files []string
	for _, p := range filepath.SplitList(spec) {
		fi, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if !fi.IsDir() {
			files = append(files, p)
			continue
		}
		m, err := filepath.Glob(filepath.Join(p, "*.ndjson"))
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, m...)
	}
	n := 0
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		line := 0
		for sc.Scan() {
			line++
			raw := strings.TrimRight(sc.Text(), "\r")
			if raw == "" {
				continue
			}
			n++
			x, err := decodeJSON([]byte(raw))
			if err != nil {
				t.Errorf("%s:%d: %v", f, line, err)
				continue
			}
			for _, e := range v.Validate(x) {
				t.Errorf("%s:%d: %s", f, line, e)
			}
		}
		if err := sc.Err(); err != nil {
			t.Errorf("%s: %v", f, err)
		}
		fh.Close()
	}
	if n == 0 {
		t.Fatalf("SPOOR_SCHEMA_VALIDATE=%s: no records found (%d files matched; directories are searched for *.ndjson, not recursively)", spec, len(files))
	}
	t.Logf("validated %d records in %d files", n, len(files))
}

func TestSchemaRejectsInvalidRecords(t *testing.T) {
	schema, _ := generateSchema(t)
	v, err := newValidator(schema)
	if err != nil {
		t.Fatal(err)
	}
	ts := At(time.Date(2026, 11, 12, 9, 0, 0, 0, time.UTC))
	base := &Event{
		V: SchemaVersion, ID: StableID(ts.Time, "schema-test"), TS: ts, Seq: 3,
		Kind: KindDetection, Type: TypeDetectionFinding, Source: SourceSensor,
		Sources: []Source{SourceHook, SourceTranscript}, Integrity: IntegrityUser,
		Host:      &Host{ID: "h", Name: "devbox", OS: "linux", Arch: "amd64"},
		Session:   &Session{ID: "s"},
		Tool:      &Tool{Name: "Bash", Kind: ToolShell},
		Target:    &Target{Command: "ls"},
		Prompt:    &Prompt{Len: 16},
		Detection: &Detection{RuleID: "SPR-EXEC-001", Title: "t", Class: ClassFinding, Severity: SevHigh},
		Health:    &Health{SensorVersion: "dev", Mode: "daemon", Counters: map[string]uint64{"events_in": 1}},
		Asset:     &Asset{ID: "a", Kind: AssetAgent, Name: "x"},
		Privacy:   "standard",
		Labels:    map[string]string{"k": "v"},
	}
	line, err := base.MarshalLine()
	if err != nil {
		t.Fatal(err)
	}
	fresh := func() map[string]any {
		x, err := decodeJSON(line)
		if err != nil {
			t.Fatal(err)
		}
		return x.(map[string]any)
	}
	if errs := v.Validate(fresh()); len(errs) > 0 {
		t.Fatalf("the base record does not validate: %v", errs)
	}
	sub := func(m map[string]any, k string) map[string]any { return m[k].(map[string]any) }
	cases := []struct {
		name string
		mut  func(m map[string]any)
	}{
		{"unknown top-level field", func(m map[string]any) { m["extra"] = "x" }},
		{"unknown nested field", func(m map[string]any) { sub(m, "host")["serial"] = "x" }},
		{"kind outside the vocabulary", func(m map[string]any) { m["kind"] = "telemetry" }},
		{"type outside the vocabulary", func(m map[string]any) { m["type"] = "tool.run" }},
		{"source outside the vocabulary", func(m map[string]any) { m["source"] = "cloud" }},
		{"sources element outside the vocabulary", func(m map[string]any) { m["sources"] = []any{"hook", "email"} }},
		{"integrity outside the vocabulary", func(m map[string]any) { m["integrity"] = "kernel" }},
		{"tool kind outside the vocabulary", func(m map[string]any) { sub(m, "tool")["kind"] = "terminal" }},
		{"asset kind outside the vocabulary", func(m map[string]any) { sub(m, "asset")["kind"] = "vm" }},
		{"severity outside the vocabulary", func(m map[string]any) { sub(m, "detection")["severity"] = "urgent" }},
		{"class outside the vocabulary", func(m map[string]any) { sub(m, "detection")["class"] = "page" }},
		{"schema version 2", func(m map[string]any) { m["v"] = json.Number("2") }},
		{"time without fraction", func(m map[string]any) { m["ts"] = "2026-11-12T09:00:00Z" }},
		{"time with an offset", func(m map[string]any) { m["ts"] = "2026-11-12T10:00:00.000000+01:00" }},
		{"time as a number", func(m map[string]any) { m["ts"] = json.Number("1700000000") }},
		{"negative seq", func(m map[string]any) { m["seq"] = json.Number("-1") }},
		{"fractional seq", func(m map[string]any) { m["seq"] = json.Number("1.5") }},
		{"seq as a string", func(m map[string]any) { m["seq"] = "3" }},
		{"missing type", func(m map[string]any) { delete(m, "type") }},
		{"missing id", func(m map[string]any) { delete(m, "id") }},
		{"missing rule id", func(m map[string]any) { delete(sub(m, "detection"), "rule_id") }},
		{"missing prompt length", func(m map[string]any) { delete(sub(m, "prompt"), "len") }},
		{"label value not a string", func(m map[string]any) { sub(m, "labels")["k"] = json.Number("1") }},
		{"negative counter", func(m map[string]any) { sub(sub(m, "health"), "counters")["events_in"] = json.Number("-4") }},
		{"truncated not a list", func(m map[string]any) { m["truncated"] = "target.command" }},
		{"host not an object", func(m map[string]any) { m["host"] = "devbox" }},
		{"null where a value is required", func(m map[string]any) { m["kind"] = nil }},
		{"clipped type without the skeleton marker", func(m map[string]any) { m["type"] = "detectio" }},

		// Times that have the right shape but cannot exist.
		{"month 13", func(m map[string]any) { m["ts"] = "2026-13-12T09:00:00.000000Z" }},
		{"month 00", func(m map[string]any) { m["ts"] = "2026-00-12T09:00:00.000000Z" }},
		{"day 32", func(m map[string]any) { m["ts"] = "2026-01-32T09:00:00.000000Z" }},
		{"day 00", func(m map[string]any) { m["ts"] = "2026-01-00T09:00:00.000000Z" }},
		{"April 31", func(m map[string]any) { m["ts"] = "2026-04-31T09:00:00.000000Z" }},
		{"February 30", func(m map[string]any) { m["ts"] = "2028-02-30T09:00:00.000000Z" }},
		{"February 29 outside a leap year", func(m map[string]any) { m["ts"] = "2026-02-29T09:00:00.000000Z" }},
		{"hour 24", func(m map[string]any) { m["ts"] = "2026-11-12T24:00:00.000000Z" }},
		{"minute 60", func(m map[string]any) { m["ts"] = "2026-11-12T09:60:00.000000Z" }},
		{"second 60", func(m map[string]any) { m["ts"] = "2026-11-12T09:00:60.000000Z" }},
		{"impossible everything", func(m map[string]any) { m["ts"] = "2026-13-45T25:61:61.000000Z" }},
		{"impossible nested time", func(m map[string]any) { sub(m, "asset")["last_seen"] = "2026-06-31T09:00:00.000000Z" }},

		// What a profile never writes, and the profile itself.
		{"prompt text in standard", func(m map[string]any) { sub(m, "prompt")["text"] = "x" }},
		{"prompt text in minimal", func(m map[string]any) { m["privacy"] = "minimal"; sub(m, "prompt")["text"] = "x" }},
		{"tool input in standard", func(m map[string]any) { sub(m, "tool")["input"] = map[string]any{"command": "x"} }},
		{"tool output in minimal", func(m map[string]any) { m["privacy"] = "minimal"; sub(m, "tool")["output"] = "x" }},
		{"search query in standard", func(m map[string]any) { sub(m, "target")["query"] = "x" }},
		{"transcript path in standard", func(m map[string]any) { sub(m, "session")["transcript"] = "/x" }},
		{"transcript path in full", func(m map[string]any) { m["privacy"] = "full"; sub(m, "session")["transcript"] = "/x" }},
		{"privacy outside the vocabulary", func(m map[string]any) { m["privacy"] = "redacted"; sub(m, "prompt")["text"] = "x" }},
		{"no privacy, so no profile stage", func(m map[string]any) { delete(m, "privacy"); sub(m, "prompt")["text"] = "x" }},

		// The skeleton marker turns none of this off.
		{"marker with prompt text", func(m map[string]any) { m["truncated"] = []any{"*"}; sub(m, "prompt")["text"] = "x" }},
		{"marker with an unknown field", func(m map[string]any) { m["truncated"] = []any{"*"}; m["extra"] = "x" }},
		{"marker with an unknown nested field", func(m map[string]any) { m["truncated"] = []any{"*"}; sub(m, "host")["serial"] = "x" }},
		{"marker with a kind outside the vocabulary", func(m map[string]any) { m["truncated"] = []any{"*"}; m["kind"] = "telemetry" }},
		{"marker with a host that is not an object", func(m map[string]any) { m["truncated"] = []any{"*"}; m["host"] = "devbox" }},
		{"marker with a negative seq", func(m map[string]any) { m["truncated"] = []any{"*"}; m["seq"] = json.Number("-5") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := fresh()
			c.mut(m)
			if errs := v.Validate(m); len(errs) == 0 {
				t.Fatalf("accepted: %s", short(m))
			}
		})
	}

	// Content is fine where the profile writes it, and real times are.
	for name, mut := range map[string]func(m map[string]any){
		"prompt text in full": func(m map[string]any) { m["privacy"] = "full"; sub(m, "prompt")["text"] = "x" },
		"tool input and output full": func(m map[string]any) {
			m["privacy"] = "full"
			sub(m, "tool")["input"] = map[string]any{"a": "b"}
			sub(m, "tool")["output"] = "x"
		},
		"February 29 in a leap year": func(m map[string]any) { m["ts"] = "2028-02-29T23:59:59.999999Z" },
		"the last microsecond":       func(m map[string]any) { m["ts"] = "2026-12-31T23:59:59.999999Z" },
		"the first instant":          func(m map[string]any) { m["ts"] = "0001-01-01T00:00:00.000001Z" },
	} {
		m := fresh()
		mut(m)
		if errs := v.Validate(m); len(errs) > 0 {
			t.Errorf("%s: rejected: %v", name, errs)
		}
	}
}

// TestSchemaRejectsInvalidSkeletons: a record that carries the skeleton
// marker is held to what the skeleton writers set, closed objects, the
// closed vocabularies (as prefixes) and the JSON types. Most cases have a
// clipped type ("tool.p"), which no ordinary record may have, so only the
// Skeleton branch could take them; every case must fail that branch alone
// as well as the whole schema.
func TestSchemaRejectsInvalidSkeletons(t *testing.T) {
	schema, _ := generateSchema(t)
	v, err := newValidator(schema)
	if err != nil {
		t.Fatal(err)
	}
	const head = `"v":1,"id":"x","ts":"2026-11-12T09:00:00.000000Z","truncated":["*"]`
	const clipped = head + `,"kind":"activity","type":"tool.p","source":"hook"`
	for name, line := range map[string]string{
		"prompt text and tool output in a minimal record": `{` + head + `,"kind":"activity","type":"prompt.submit","source":"hook","privacy":"minimal","prompt":{"len":20,"text":"the user's whole prompt"},"tool":{"output":"whole tool output","input":{"command":"cat ~/.aws/credentials"}}}`,
		"unknown top-level field":                         `{` + head + `,"kind":"activity","type":"tool.pre","source":"hook","privacy":"minimal","exfil":{"anything":"goes"}}`,
		"kind outside the vocabulary":                     `{` + head + `,"kind":"telemetry","type":"whatever","source":"cloud","privacy":"minimal"}`,
		"host is not an object, seq negative":             `{` + head + `,"kind":"activity","type":"tool.pre","source":"hook","privacy":"minimal","host":"devbox","seq":-5}`,
		"no privacy":                                      `{` + clipped + `}`,
		"privacy outside the vocabulary":                  `{` + clipped + `,"privacy":"min"}`,
		"type that is no prefix of a type":                `{` + head + `,"kind":"activity","type":"tool.run","source":"hook","privacy":"minimal"}`,
		"source that is no prefix of a source":            `{` + head + `,"kind":"activity","type":"tool.p","source":"cloud","privacy":"minimal"}`,
		"target command":                                  `{` + clipped + `,"privacy":"minimal","target":{"command":"curl -u a:b x"}}`,
		"tool input, even in full":                        `{` + clipped + `,"privacy":"full","tool":{"name":"Bash","input":{"command":"x"}}}`,
		"tool output, even in full":                       `{` + clipped + `,"privacy":"full","tool":{"name":"Bash","output":"x"}}`,
		"process":                                         `{` + clipped + `,"privacy":"minimal","process":{"pid":1}}`,
		"an agent field no writer sets":                   `{` + clipped + `,"privacy":"minimal","agent":{"id":"claude-code","surface":"cli"}}`,
		"a session field no writer sets":                  `{` + clipped + `,"privacy":"minimal","session":{"id":"s","cwd":"/home/u/secret-project"}}`,
		"an unknown nested field":                         `{` + clipped + `,"privacy":"minimal","host":{"id":"h","serial":"x"}}`,
		"tool kind outside the vocabulary":                `{` + clipped + `,"privacy":"minimal","tool":{"kind":"terminal"}}`,
		"detection severity outside the vocabulary":       `{` + clipped + `,"privacy":"minimal","detection":{"rule_id":"r","title":"t","severity":"urgent"}}`,
		"detection without its rule id":                   `{` + clipped + `,"privacy":"minimal","detection":{"title":"t","severity":"high"}}`,
		"label value not a string":                        `{` + clipped + `,"privacy":"minimal","labels":{"line_cap":true}}`,
		"summary":                                         `{` + head + `,"kind":"summary","type":"session.sum","source":"sensor","privacy":"minimal","summary":{"events":1}}`,
		"marker missing":                                  `{"v":1,"id":"x","ts":"2026-11-12T09:00:00.000000Z","truncated":["tool.output"],"kind":"detection","type":"detectio","source":"sensor","privacy":"minimal"}`,
		"impossible time":                                 `{"v":1,"id":"x","ts":"2026-02-30T09:00:00.000000Z","truncated":["*"],"kind":"activity","type":"tool.p","source":"hook","privacy":"minimal"}`,
		"schema version 2":                                `{"v":2,"id":"x","ts":"2026-11-12T09:00:00.000000Z","truncated":["*"],"kind":"activity","type":"tool.p","source":"hook","privacy":"minimal"}`,
	} {
		t.Run(name, func(t *testing.T) {
			x, err := decodeJSON([]byte(line))
			if err != nil {
				t.Fatal(err)
			}
			if errs := v.ValidateDef("Skeleton", x); len(errs) == 0 {
				t.Errorf("the Skeleton definition accepts: %s", short(x))
			}
			if errs := v.Validate(x); len(errs) == 0 {
				t.Errorf("accepted: %s", short(x))
			}
		})
	}
}

// TestSchemaValidatorHostileInput: the validator is bounded by the schema,
// not by the input, and refuses schemas it cannot fully check.
func TestSchemaValidatorHostileInput(t *testing.T) {
	schema, _ := generateSchema(t)
	v, err := newValidator(schema)
	if err != nil {
		t.Fatal(err)
	}
	nested := func(depth int, leaf string) string {
		return strings.Repeat(`{"a":`, depth) + leaf + strings.Repeat(`}`, depth)
	}
	manyFields := func(n int) string {
		var b strings.Builder
		for i := 0; i < n; i++ {
			fmt.Fprintf(&b, `,"x%d":1`, i)
		}
		return b.String()
	}
	base := `"v":1,"id":"x","ts":"2026-11-12T09:00:00.000000Z","kind":"activity","type":"tool.pre","source":"hook","privacy":"full"`
	cases := []struct {
		name    string
		line    string
		valid   bool
		decodes bool
	}{
		{"deep JSON inside the open tool.input", `{` + base + `,"tool":{"input":` + nested(5000, `"x"`) + `}}`, true, true},
		{"deep JSON where labels want strings", `{` + base + `,"labels":` + nested(5000, `"x"`) + `}`, false, true},
		{"a 1 MiB command", `{` + base + `,"target":{"command":"` + strings.Repeat("A", 1<<20) + `"}}`, true, true},
		{"invalid UTF-8 in a string", `{` + base + `,"target":{"command":"` + "\xff\xfe" + `"}}`, true, true},
		{"an unknown field", `{` + base + `,"x":1}`, false, true},
		{"10,000 unknown fields", `{` + base + manyFields(10000) + `}`, false, true},
		{"trailing data", `{` + base + `} {}`, false, false},
		{"not an object", `[1,2,3]`, false, true},
		{"null", `null`, false, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			start := time.Now()
			x, err := decodeJSON([]byte(c.line))
			if (err == nil) != c.decodes {
				t.Fatalf("decode error %v, want decodes=%v", err, c.decodes)
			}
			if err != nil {
				return
			}
			errs := v.Validate(x)
			if (len(errs) == 0) != c.valid {
				t.Fatalf("valid=%v, want %v: %v", len(errs) == 0, c.valid, errs)
			}
			if d := time.Since(start); d > 5*time.Second {
				t.Fatalf("took %v", d)
			}
		})
	}

	// A schema the validator cannot fully check is an error, never a pass.
	for name, s := range map[string]string{
		"unknown keyword": `{"type":"object","maxProperties":1}`,
		"unknown format":  `{"type":"object","format":"email"}`,
		"ref cycle":       `{"$defs":{"A":{"$ref":"#/$defs/A"}},"$ref":"#/$defs/A"}`,
		"dangling ref":    `{"$ref":"#/$defs/Missing"}`,
		"remote ref":      `{"$ref":"https://example.com/s.json"}`,
	} {
		v, err := newValidator([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		if errs := v.Validate(map[string]any{}); len(errs) == 0 {
			t.Errorf("%s: schema %s accepted a record", name, s)
		}
	}
}

func TestSchemaAcceptsSkeletons(t *testing.T) {
	schema, _ := generateSchema(t)
	v, err := newValidator(schema)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range []string{
		// internal/sink: identity only, strings clipped to a safe subset.
		`{"v":1,"id":"01a1cefe-efcc-8941-bb24-f6e74ac7821e","ts":"2026-11-12T09:02:56.460197Z","seq":4,"kind":"activity","type":"tool.pre","source":"hook","privacy":"standard","truncated":["*"],"host":{"id":"h","name":"devbox","os":"linux","arch":"amd64"}}`,
		// internal/privacy routing-only fallback: no id or type survived.
		`{"v":1,"id":"","ts":"2026-11-12T09:02:56.460197Z","kind":"detection","type":"","source":"","privacy":"minimal","truncated":["*"],"labels":{"line_cap":"true"}}`,
		// a value clipped by the per-value budget
		`{"v":1,"id":"x","ts":"2026-11-12T09:02:56.460197Z","kind":"detection","type":"detectio","source":"sensor","privacy":"minimal","truncated":["*"],"labels":{"privacy_error":"true"}}`,
		// internal/privacy: a finding, every value clipped to 8 bytes.
		`{"v":1,"id":"01a1cefe","ts":"2026-11-12T09:02:56.460197Z","emitted":"2026-11-12T10:02:56.460197Z","seq":2,"kind":"detectio","type":"detectio","source":"sensor","fidelity":"inferre","integrity":"use","writer":"daemon-0","privacy":"full","truncated":["*"],"labels":{"line_cap":"true","rule_pac":"executio"},"host":{"id":"7d3f9a2e","os":"linux","arch":"amd64"},"agent":{"id":"claude-c"},"session":{"id":"6f1c2d3e"},"detection":{"rule_id":"SPR-EXEC","title":"Remote s","class":"findi","severity":"hig"}}`,
		// internal/sink: a tool call and an inventory record.
		`{"v":1,"id":"x","ts":"2026-11-12T09:02:56.460197Z","kind":"activity","type":"tool.post","source":"transcript","fidelity":"observed","privacy":"standard","truncated":["*"],"labels":{"target.command.len":"70000"},"user":{"name":"dev","id":"1000"},"agent":{"id":"codex","version":"0.98.0","pid":4242},"tool":{"name":"shell","kind":"shell","use_id":"call_1","input_sha256":"ab","output_sha256":"cd","output_len":65536}}`,
		`{"v":1,"id":"x","ts":"2026-11-12T09:02:56.460197Z","kind":"inventory","type":"inventory.asset","source":"scan","privacy":"minimal","truncated":["*"],"asset":{"id":"a","kind":"mcp_server","name":"github"},"check":{"id":"SPR-SCAN-001","status":"fail","severity":"high"},"health":{"sensor_version":"dev","mode":"daemon","reason":"x"}}`,
	} {
		x, err := decodeJSON([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		if errs := v.ValidateDef("Skeleton", x); len(errs) > 0 {
			t.Errorf("skeleton rejected: %v\n%s", errs, s)
		}
		if errs := v.Validate(x); len(errs) > 0 {
			t.Errorf("skeleton rejected: %v\n%s", errs, s)
		}
	}
}

// TestSchemaSkeletonIsWhatTheWritersSet: the Skeleton definitions declare
// exactly the fields the writers set (plus those the encoder always
// writes); a record with all of them, every vocabulary value clipped,
// validates; and each other field of the record, added to it, is refused.
func TestSchemaSkeletonIsWhatTheWritersSet(t *testing.T) {
	schema, g := generateSchema(t)
	v, err := newValidator(schema)
	if err != nil {
		t.Fatal(err)
	}
	defs := v.root["$defs"].(map[string]any)
	structs := eventStructs()

	// The writers' fields, as read from their source, are those declared.
	for typ, fields := range g.skel {
		st := structs[typ]
		name := "Skeleton"
		if typ != "Event" {
			name += typ
		}
		def, ok := defs[name].(map[string]any)
		if !ok {
			t.Errorf("a writer sets fields of %s, and there is no %s definition", typ, name)
			continue
		}
		props := def["properties"].(map[string]any)
		want := map[string]bool{}
		for _, f := range g.fields(st) {
			if f.Required || fields[f.Go] {
				want[f.JSON] = true
			}
		}
		for k := range props {
			if !want[k] {
				t.Errorf("%s declares %q, which no writer sets", name, k)
			}
		}
		for k := range want {
			if _, ok := props[k]; !ok {
				t.Errorf("%s does not declare %q, which a writer sets", name, k)
			}
		}
	}
	for _, f := range []string{"ID", "Kind", "Type", "Source", "Host", "Detection", "Truncated", "Privacy", "Labels"} {
		if !g.skel["Event"][f] {
			t.Errorf("the writers' Event.%s was not read from their source", f)
		}
	}

	// Every field of the record, filled.
	var ev Event
	fill(t, g, reflect.ValueOf(&ev).Elem(), "")
	ev.V = SchemaVersion
	line, err := ev.MarshalLine()
	if err != nil {
		t.Fatal(err)
	}
	full := func() map[string]any {
		x, err := decodeJSON(line)
		if err != nil {
			t.Fatal(err)
		}
		return x.(map[string]any)
	}
	// prune keeps what def declares, clips the vocabulary values, and
	// returns every (object path, field) it removed.
	type removed struct {
		def, path, field string
		val              any
	}
	var gone []removed
	var prune func(def string, obj map[string]any, path string, rec *[]removed)
	prune = func(def string, obj map[string]any, path string, rec *[]removed) {
		props := defs[def].(map[string]any)["properties"].(map[string]any)
		for k, val := range obj {
			ps, ok := props[k].(map[string]any)
			if !ok {
				if rec != nil {
					*rec = append(*rec, removed{def, path, k, val})
				}
				delete(obj, k)
				continue
			}
			r, _ := ps["$ref"].(string)
			r = strings.TrimPrefix(r, "#/$defs/")
			switch {
			case strings.HasSuffix(r, "Prefix"):
				s := val.(string)
				obj[k] = s[:len(s)/2]
			case strings.HasPrefix(r, "Skeleton"):
				prune(r, val.(map[string]any), joinPath(path, k), rec)
			}
		}
	}
	sk := full()
	prune("Skeleton", sk, "", &gone)
	sk["truncated"] = []any{"*"}
	if errs := v.ValidateDef("Skeleton", sk); len(errs) > 0 {
		t.Fatalf("a skeleton with every field the writers set does not validate: %v\n%s", errs, short(sk))
	}
	if errs := v.Validate(sk); len(errs) > 0 {
		t.Fatalf("a skeleton with every field the writers set does not validate: %v", errs)
	}
	if len(gone) == 0 {
		t.Fatal("the skeleton kept every field of the record")
	}
	for _, r := range gone {
		x := full()
		prune("Skeleton", x, "", nil)
		x["truncated"] = []any{"*"}
		obj := x
		if r.path != "" {
			o, ok := getPath(x, strings.Split(r.path, ".")...)
			if !ok {
				t.Fatalf("%s: lost after pruning", r.path)
			}
			obj = o.(map[string]any)
		}
		obj[r.field] = r.val
		if errs := v.ValidateDef("Skeleton", x); len(errs) == 0 {
			t.Errorf("%s accepts %s", r.def, joinPath(r.path, r.field))
		}
	}
	t.Logf("skeleton: %d fields of the full record refused", len(gone))
}

// fill sets every field reachable from v to a non-zero value the encoder
// writes, picking the first value of a closed vocabulary.
func fill(t *testing.T, g *schemaGen, v reflect.Value, enum string) {
	switch v.Kind() {
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		fill(t, g, v.Elem(), enum)
	case reflect.Struct:
		if v.Type() == timeType {
			v.Set(reflect.ValueOf(At(time.Date(2026, 11, 12, 9, 0, 0, 123456000, time.UTC))))
			return
		}
		for _, f := range g.fields(v.Type()) {
			fill(t, g, v.FieldByName(f.Go), f.Enum)
		}
	case reflect.String:
		name := enum
		if name == "" && v.Type().PkgPath() == eventPath {
			name = v.Type().Name()
		}
		if vals := g.src.enums[name]; len(vals) > 0 {
			v.SetString(vals[0].Value)
		} else {
			v.SetString("x")
		}
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int64, reflect.Int32:
		v.SetInt(1)
	case reflect.Uint, reflect.Uint64, reflect.Uint32:
		v.SetUint(1)
	case reflect.Float64:
		v.SetFloat(1.5)
	case reflect.Slice:
		s := reflect.MakeSlice(v.Type(), 1, 1)
		fill(t, g, s.Index(0), "")
		v.Set(s)
	case reflect.Map:
		m := reflect.MakeMap(v.Type())
		e := reflect.New(v.Type().Elem()).Elem()
		if e.Kind() == reflect.Interface {
			e.Set(reflect.ValueOf("x"))
		} else {
			fill(t, g, e, "")
		}
		m.SetMapIndex(reflect.ValueOf("k"), e)
		v.Set(m)
	case reflect.Interface:
		v.Set(reflect.ValueOf("x"))
	default:
		t.Fatalf("fill: unsupported kind %s", v.Kind())
	}
}

// TestSchemaMatchesTheEncoder fills every field of an Event, encodes it with
// MarshalLine and requires that the schema declares exactly the keys the
// encoder wrote, object by object, and that the record validates once the
// fields its profile never writes are taken out.
func TestSchemaMatchesTheEncoder(t *testing.T) {
	schema, g := generateSchema(t)
	v, err := newValidator(schema)
	if err != nil {
		t.Fatal(err)
	}
	var ev Event
	fill(t, g, reflect.ValueOf(&ev).Elem(), "")
	ev.V = SchemaVersion
	ev.Content = &Content{PromptText: "local only"}
	ev.Feat = map[string]any{"local": true}
	line, err := ev.MarshalLine()
	if err != nil {
		t.Fatal(err)
	}
	decode := func() map[string]any {
		x, err := decodeJSON(line)
		if err != nil {
			t.Fatal(err)
		}
		return x.(map[string]any)
	}
	x := decode()
	for _, p := range g.src.enums["Profile"] {
		y := decode()
		y["privacy"] = p.Value
		if errs := v.Validate(y); len(errs) == 0 && len(neverWritten[p.Value]) > 0 {
			t.Errorf("a %s record with every field validates, %v included", p.Value, neverWritten[p.Value])
		}
		for _, path := range neverWritten[p.Value] {
			parts := strings.Split(path, ".")
			obj, _ := getPath(y, parts[:len(parts)-1]...)
			delete(obj.(map[string]any), parts[len(parts)-1])
		}
		if errs := v.Validate(y); len(errs) > 0 {
			t.Errorf("a fully populated %s record, without %v, does not validate: %v", p.Value, neverWritten[p.Value], errs)
		}
	}
	defs := v.root["$defs"].(map[string]any)
	var walk func(def string, obj map[string]any, path string)
	walk = func(def string, obj map[string]any, path string) {
		props := defs[def].(map[string]any)["properties"].(map[string]any)
		for k := range obj {
			if _, ok := props[k]; !ok {
				t.Errorf("%s: the encoder wrote %q, the schema does not declare it", def, joinPath(path, k))
			}
		}
		for k, p := range props {
			val, ok := obj[k]
			if !ok {
				t.Errorf("%s: the schema declares %q, the encoder never wrote it", def, joinPath(path, k))
				continue
			}
			pm := p.(map[string]any)
			if r, ok := pm["$ref"].(string); ok {
				if sub, ok := val.(map[string]any); ok {
					walk(strings.TrimPrefix(r, "#/$defs/"), sub, joinPath(path, k))
				}
			}
			if items, ok := pm["items"].(map[string]any); ok {
				if r, ok := items["$ref"].(string); ok {
					if arr, ok := val.([]any); ok && len(arr) > 0 {
						if sub, ok := arr[0].(map[string]any); ok {
							walk(strings.TrimPrefix(r, "#/$defs/"), sub, joinPath(path, k)+"[0]")
						}
					}
				}
			}
		}
	}
	walk("Event", x, "")
}

// TestSchemaVocabulariesMatchTheCode cross-checks what go/ast read from the
// source with the compiled package. Two halves make it complete: every
// constant below, as the compiler sees it, must be among the values go/ast
// read, and readSourceFacts fails on a vocabulary constant whose value it
// cannot read, so a constant added later cannot go missing either.
func TestSchemaVocabulariesMatchTheCode(t *testing.T) {
	src := readSourceFacts(t)
	vals := func(name string) []string {
		var out []string
		for _, v := range src.enums[name] {
			out = append(out, v.Value)
		}
		sort.Strings(out)
		return out
	}
	streams := append([]string(nil), Streams...)
	sort.Strings(streams)
	if got := vals("Kind"); !reflect.DeepEqual(got, streams) {
		t.Errorf("Kind constants %v, Streams %v", got, streams)
	}
	for _, k := range src.enums["Kind"] {
		if Kind(k.Value).Stream() != k.Value {
			t.Errorf("kind %s writes to stream %s", k.Value, Kind(k.Value).Stream())
		}
	}
	if got := vals("Severity"); len(got) != 5 {
		t.Errorf("severities %v", got)
	}
	for _, s := range src.enums["Severity"] {
		if SeverityRank(s.Value) == 0 {
			t.Errorf("severity %s has no rank", s.Value)
		}
	}
	want := map[string]int{ClassSignal: 1, ClassFinding: 2, ClassAlert: 3}
	if got := vals("DetectionClass"); len(got) != len(want) {
		t.Errorf("classes %v", got)
	}
	for _, c := range src.enums["DetectionClass"] {
		if ClassRank(c.Value) != want[c.Value] {
			t.Errorf("class %s ranks %d", c.Value, ClassRank(c.Value))
		}
	}
	compiled := map[string][]string{
		"Kind": {string(KindActivity), string(KindInventory), string(KindPosture), string(KindDetection), string(KindHealth), string(KindSummary)},
		"Source": {string(SourceHook), string(SourceTranscript), string(SourceProcess), string(SourceScan), string(SourceOTel),
			string(SourceOsquery), string(SourceAdapter), string(SourceSensor)},
		"Fidelity":  {string(FidelityObserved), string(FidelityInferred)},
		"Integrity": {string(IntegrityRoot), string(IntegrityUser)},
		"ToolKind": {string(ToolShell), string(ToolFileRead), string(ToolFileWrite), string(ToolFileEdit), string(ToolFileList),
			string(ToolWebFetch), string(ToolWebSearch), string(ToolMCP), string(ToolSubagent), string(ToolBrowser), string(ToolOther)},
		"AssetKind": {string(AssetAgent), string(AssetApp), string(AssetIDEExtension), string(AssetBrowser), string(AssetBrowserExtension),
			string(AssetModelRuntime), string(AssetMCPServer), string(AssetSkill), string(AssetPlugin), string(AssetHook),
			string(AssetRulesFile), string(AssetSubagent), string(AssetCommand), string(AssetCIAgent), string(AssetProjectConfig)},
		"Scope":  {string(ScopeManaged), string(ScopeSystem), string(ScopeUser), string(ScopeProject), string(ScopePlugin)},
		"Change": {string(ChangeNew), string(ChangeChanged), string(ChangeRemoved), string(ChangeUnchanged)},
		"EventType": {TypeSessionStart, TypeSessionEnd, TypePromptSubmit, TypeToolPre, TypeToolPost, TypeTurnEnd,
			TypeSubagentStart, TypeSubagentStop, TypePermissionDecision, TypeConfigChange, TypeNotification, TypeCompact,
			TypeAgentProcessStart, TypeAgentProcessStop, TypeProcessExec, TypePayloadAnomaly,
			TypeInventoryAsset, TypePostureCheck, TypeDetectionFinding, TypeHealthHeartbeat, TypeHealthError, TypeSessionSummary,
			"detection.context"},
		"DetectionClass": {ClassSignal, ClassFinding, ClassAlert},
		"Severity":       {SevInfo, SevLow, SevMedium, SevHigh, SevCritical},
		// internal/privacy cannot be imported from here (it imports this
		// package); its profile names are the configuration's.
		"Profile": {"minimal", "standard", "full"},
	}
	for name, want := range compiled {
		got := map[string]bool{}
		for _, v := range src.enums[name] {
			got[v.Value] = true
		}
		for _, w := range want {
			if !got[w] {
				t.Errorf("%s: the compiled constant %q is missing from the values go/ast read %v", name, w, vals(name))
			}
		}
	}
	// A skeleton writer copies the profile name through a 16-byte clip that
	// keeps letters (internal/sink, skelString): Skeleton's privacy is the
	// exact vocabulary only while that changes nothing.
	for _, p := range src.enums["Profile"] {
		if len(p.Value) > 16 || strings.Trim(p.Value, "abcdefghijklmnopqrstuvwxyz") != "" {
			t.Errorf("profile name %q would be altered by a skeleton writer", p.Value)
		}
	}
}

// TestSchemaVocabularyReaderRefusesWhatItCannotRead runs the go/ast reader
// over made-up sources: literal and converted constants are read, and a
// vocabulary constant whose value is not a literal is an error, because the
// schema would otherwise reject a value the code writes.
func TestSchemaVocabularyReaderRefusesWhatItCannotRead(t *testing.T) {
	dir := t.TempDir()
	read := func(body string) (*srcFacts, error) {
		p := filepath.Join(dir, "x.go")
		if err := os.WriteFile(p, []byte("package x\n\n// Kind is a kind.\ntype Kind string\n\n"+body), 0o600); err != nil {
			t.Fatal(err)
		}
		f := &srcFacts{typeDoc: map[string]string{}, fieldDoc: map[string]map[string]string{}, enums: map[string][]enumValue{}, enumDoc: map[string]string{}}
		return f, readPackageFacts(token.NewFileSet(), []string{p}, f)
	}
	f, err := read("const (\n\tKindA Kind = \"a\" // the first\n\tKindB = Kind(\"b\")\n)\n\nconst TypeX = \"x.y\"\n\nconst other = 3\n")
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, v := range f.enums["Kind"] {
		got = append(got, v.Const+"="+v.Value+":"+v.Doc)
	}
	if want := []string{"KindA=a:the first", "KindB=b:"}; !reflect.DeepEqual(got, want) {
		t.Errorf("Kind read as %v, want %v", got, want)
	}
	if len(f.enums["EventType"]) != 1 || f.enumDoc["Kind"] != "Kind is a kind." {
		t.Errorf("read %v, docs %v", f.enums, f.enumDoc)
	}
	for name, body := range map[string]string{
		"another constant":         "const KindA Kind = \"a\"\nconst KindC Kind = KindA\n",
		"an expression":            "const TypeY = \"a\" + \".b\"\n",
		"an implicit repetition":   "const (\n\tKindD Kind = \"d\"\n\tKindE\n)\n",
		"a repeated conversion":    "const (\n\tKindF = Kind(\"f\")\n\tKindG\n)\n",
		"a converted non-literal":  "const KindH = Kind(TypeZ)\nconst TypeZ = \"z\"\n",
		"an untyped implicit type": "const (\n\tTypeP = \"p\"\n\tTypeQ\n)\n",
	} {
		if _, err := read(body); err == nil || !strings.Contains(err.Error(), "not a string literal") {
			t.Errorf("%s: error %v, want one about a value that is not a string literal", name, err)
		}
	}
}

// TestSchemaSkeletonReaderFollowsTheWriters runs the reader of the skeleton
// writers over made-up writers: a field a writer starts to set is picked
// up, and a sub-object it copies whole (which could carry anything) is an
// error, not an open schema.
func TestSchemaSkeletonReaderFollowsTheWriters(t *testing.T) {
	dir := t.TempDir()
	write := func(name, body string) string {
		p := filepath.Join(dir, name)
		src := "package x\n\nimport \"github.com/thomastysong/spoor/internal/event\"\n\n" + body
		if err := os.WriteFile(p, []byte(src), 0o600); err != nil {
			t.Fatal(err)
		}
		return p
	}
	ok := write("ok.go", `
func skeleton(c *event.Event) *event.Event {
	s := &event.Event{V: c.V, ID: c.ID, Privacy: c.Privacy, Truncated: []string{"*"}}
	s.Prompt = &event.Prompt{Len: c.Prompt.Len}
	s.Labels = map[string]string{}
	return s
}

func outer(c *event.Event) *event.Event {
	sk := skeleton(c)
	sk.Target = &event.Target{Host: c.Target.Host}
	sk.Labels["x"] = "y"
	return sk
}
`)
	set, err := readSkeletonFieldsFrom([]skeletonWriter{{ok, []string{"skeleton", "outer"}}})
	if err != nil {
		t.Fatal(err)
	}
	for typ, fields := range map[string][]string{
		"Event":  {"V", "ID", "Privacy", "Truncated", "Prompt", "Labels", "Target"},
		"Prompt": {"Len"},
		"Target": {"Host"},
	} {
		for _, f := range fields {
			if !set[typ][f] {
				t.Errorf("%s.%s was not read; got %v", typ, f, set)
			}
		}
	}
	if set["Prompt"]["Text"] || set["Event"]["Tool"] {
		t.Errorf("fields no writer sets were read: %v", set)
	}

	for name, c := range map[string]struct {
		body, want string
	}{
		"a sub-object copied whole":     {`func skeleton(c *event.Event) *event.Event { s := &event.Event{Privacy: "minimal", Truncated: []string{"*"}}; s.Tool = c.Tool; return s }`, "Tool is not set from an event.Tool literal"},
		"a sub-object in a literal key": {`func skeleton(c *event.Event) *event.Event { return &event.Event{Privacy: "minimal", Truncated: []string{"*"}, Host: c.Host} }`, "Host is not set from an event.Host literal"},
		"a literal of the wrong type":   {`func skeleton(c *event.Event) *event.Event { return &event.Event{Privacy: "minimal", Truncated: []string{"*"}, Host: &event.User{}} }`, "Host is not set from an event.Host literal"},
		"fields without names":          {`func skeleton(c *event.Event) *event.Event { return &event.Event{Privacy: "minimal", Truncated: []string{"*"}, Host: &event.Host{"a", "b", "c", "d"}} }`, "literal without field names"},
		"no privacy":                    {`func skeleton(c *event.Event) *event.Event { return &event.Event{Truncated: []string{"*"}} }`, "Event.Privacy"},
		"the writer is gone":            {`func other() {}`, "func skeleton not found"},
	} {
		p := write(strings.ReplaceAll(name, " ", "_")+".go", c.body)
		_, err := readSkeletonFieldsFrom([]skeletonWriter{{p, []string{"skeleton"}}})
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: error %v, want one that says %q", name, err, c.want)
		}
	}
}

// TestSchemaPrefixPattern: the skeleton form of a vocabulary admits a value,
// every prefix of one and the empty string, and nothing else.
func TestSchemaPrefixPattern(t *testing.T) {
	vals := []string{"detection.finding", "detection.context", "health.error", "a.b"}
	re := regexp.MustCompile(prefixPattern(vals))
	for _, s := range []string{"", "d", "detectio", "detection.", "detection.f", "detection.finding", "detection.c", "health.err", "a", "a.", "a.b"} {
		if !re.MatchString(s) {
			t.Errorf("%q rejected", s)
		}
	}
	for _, s := range []string{"x", "detection.finding.x", "detection.x", "aXb", "a.bc", "health.error ", " health", "Health"} {
		if re.MatchString(s) {
			t.Errorf("%q accepted", s)
		}
	}
}

// ---- docs/EVENTS.md ---------------------------------------------------------

func mdEscape(s string) string {
	r := strings.NewReplacer("|", `\|`, "<", "&lt;", ">", "&gt;", "\n", " ")
	return r.Replace(s)
}

func (g *schemaGen) mdType(t reflect.Type, enum string) string {
	if enum != "" {
		return fmt.Sprintf("[`%s`](#%s-values)", enum, strings.ToLower(enum))
	}
	if t == timeType {
		return "[`Time`](#time-string)"
	}
	switch t.Kind() {
	case reflect.String:
		if t.PkgPath() == eventPath && len(g.src.enums[t.Name()]) > 0 {
			return fmt.Sprintf("[`%s`](#%s-values)", t.Name(), strings.ToLower(t.Name()))
		}
		return "string"
	case reflect.Bool:
		return "boolean"
	case reflect.Int, reflect.Int64, reflect.Int32:
		return "integer"
	case reflect.Uint, reflect.Uint64, reflect.Uint32:
		return "integer ≥ 0"
	case reflect.Float64:
		return "number"
	case reflect.Pointer:
		return g.mdType(t.Elem(), "")
	case reflect.Slice:
		return "array of " + g.mdType(t.Elem(), "")
	case reflect.Map:
		if t.Elem().Kind() == reflect.Interface {
			return "object (any JSON)"
		}
		return "object of " + g.mdType(t.Elem(), "")
	case reflect.Struct:
		return fmt.Sprintf("[`%s`](#%s-object)", t.Name(), strings.ToLower(t.Name()))
	}
	return t.String()
}

func (g *schemaGen) fieldReference() string {
	var b strings.Builder
	b.WriteString(genBegin + "\n\n")
	b.WriteString("Generated from the Go types in `internal/event` and their doc comments; a field without one is described by a note in `internal/event/schema_test.go` (`fieldNotes`) or by its type's comment. \"always\" fields are written on every record of that object (an empty string or zero when unset); the others are left out when empty.\n\n")
	for _, name := range g.order {
		t := g.structType(name)
		fmt.Fprintf(&b, "### `%s` object\n\n", name)
		if doc := g.src.typeDoc[name]; doc != "" {
			b.WriteString(mdEscape(doc) + "\n\n")
		}
		b.WriteString("| Field | Type | Present | Description |\n|---|---|---|---|\n")
		for _, f := range g.fields(t) {
			ty := g.mdType(f.Type, f.Enum)
			doc := f.Doc
			if name == "Event" && f.Go == "V" {
				ty = "integer"
				doc = fmt.Sprintf("Schema version, %d (SchemaVersion). Bumped only on breaking changes; adding optional fields is not breaking.", SchemaVersion)
			}
			present := "when set"
			if f.Required {
				present = "always"
			}
			fmt.Fprintf(&b, "| `%s` | %s | %s | %s |\n", f.JSON, ty, present, mdEscape(doc))
		}
		b.WriteString("\n")
	}
	b.WriteString("### `Time` string\n\n")
	b.WriteString("RFC 3339 in UTC with exactly six fraction digits, for example `2026-11-12T09:02:56.460197Z` (`TimeLayout`; Fluent Bit's strict parser needs the fraction). Optional time fields are left out when unset.\n\n")
	for _, name := range g.enums {
		fmt.Fprintf(&b, "### `%s` values\n\n", name)
		if doc := g.src.enumDoc[name]; doc != "" {
			b.WriteString(mdEscape(doc) + "\n\n")
		}
		b.WriteString("| Value | Constant | Meaning |\n|---|---|---|\n")
		for _, v := range g.src.enums[name] {
			fmt.Fprintf(&b, "| `%s` | `%s` | %s |\n", v.Value, v.Const, mdEscape(v.Doc))
		}
		b.WriteString("\n")
	}
	b.WriteString(genEnd)
	return b.String()
}

// structType finds a struct type reachable from Event by name.
func (g *schemaGen) structType(name string) reflect.Type {
	var found reflect.Type
	seen := map[reflect.Type]bool{}
	var walk func(t reflect.Type)
	walk = func(t reflect.Type) {
		for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Map {
			t = t.Elem()
		}
		if t.Kind() != reflect.Struct || seen[t] || found != nil {
			return
		}
		seen[t] = true
		if t.Name() == name {
			found = t
			return
		}
		for i := 0; i < t.NumField(); i++ {
			walk(t.Field(i).Type)
		}
	}
	walk(reflect.TypeOf(Event{}))
	if found == nil {
		g.t.Fatalf("struct %s not reachable from Event", name)
	}
	return found
}

func TestSchemaFieldReferenceInEventsDoc(t *testing.T) {
	_, g := generateSchema(t)
	// Every field is described: by its own comment, a note, or its type.
	structs := eventStructs()
	for _, name := range g.order {
		for _, f := range g.fields(structs[name]) {
			if f.Doc == "" && !(name == "Event" && f.Go == "V") {
				t.Errorf("%s.%s has no description: give it a doc comment in internal/event or an entry in fieldNotes", name, f.Go)
			}
		}
	}
	for k := range fieldNotes {
		typ, field, _ := strings.Cut(k, ".")
		st, ok := structs[typ]
		if !ok {
			t.Errorf("fieldNotes[%q]: no struct %s in the record", k, typ)
			continue
		}
		if _, ok := st.FieldByName(field); !ok {
			t.Errorf("fieldNotes[%q]: %s has no field %s", k, typ, field)
			continue
		}
		if g.src.fieldDoc[typ][field] != "" {
			t.Logf("fieldNotes[%q] is unused: the field has its own doc comment now", k)
		}
	}
	doc := readText(t, eventsDoc)
	i := strings.Index(doc, genBegin)
	j := strings.Index(doc, genEnd)
	if i < 0 || j < i {
		t.Fatalf("docs/EVENTS.md has no generated field reference between %q and %q", genBegin, genEnd)
	}
	want := g.fieldReference()
	cur := doc[i : j+len(genEnd)]
	if cur == want {
		return
	}
	if *updateSchema {
		if err := os.WriteFile(eventsDoc, []byte(doc[:i]+want+doc[j+len(genEnd):]), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	t.Fatalf("the field reference in docs/EVENTS.md is stale; run\n\tgo test ./internal/event -run TestSchema -update\nfirst difference at %s", firstDiff(cur, want))
}

// TestSchemaProfileTableNamesRealFields keeps the hand-written profile table
// in docs/EVENTS.md honest about field names.
func TestSchemaProfileTableNamesRealFields(t *testing.T) {
	schema, _ := generateSchema(t)
	v, err := newValidator(schema)
	if err != nil {
		t.Fatal(err)
	}
	defs := v.root["$defs"].(map[string]any)
	resolve := func(path string) bool {
		def := "Event"
		parts := strings.Split(path, ".")
		for i, p := range parts {
			props, _ := defs[def].(map[string]any)["properties"].(map[string]any)
			ps, ok := props[p].(map[string]any)
			if !ok {
				return false
			}
			if i == len(parts)-1 {
				return true
			}
			if it, ok := ps["items"].(map[string]any); ok {
				ps = it
			}
			r, ok := ps["$ref"].(string)
			if !ok {
				return false
			}
			def = strings.TrimPrefix(r, "#/$defs/")
		}
		return false
	}
	doc := readText(t, eventsDoc)
	i, j := strings.Index(doc, profileBegin), strings.Index(doc, profileEnd)
	if i < 0 || j < i {
		t.Fatalf("docs/EVENTS.md has no profile table between %q and %q", profileBegin, profileEnd)
	}
	rows := 0
	cell := regexp.MustCompile("^\\| `([a-z0-9_.]+)`")
	// The table has one column for minimal and standard, then full; a cell
	// that starts with "never" must match neverWritten, which the schema
	// enforces, and every field there must have a row.
	never := map[string]map[string]bool{"minimal and standard": {}, "full": {}}
	for _, l := range strings.Split(doc[i:j], "\n") {
		m := cell.FindStringSubmatch(l)
		if m == nil {
			continue
		}
		rows++
		if !resolve(m[1]) {
			t.Errorf("profile table names %q, which is not a field of the record", m[1])
		}
		cells := strings.Split(l, "|")
		if len(cells) != 5 {
			t.Errorf("profile table row %q: want 3 cells", l)
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(cells[2]), "never") {
			never["minimal and standard"][m[1]] = true
		}
		if strings.HasPrefix(strings.TrimSpace(cells[3]), "never") {
			never["full"][m[1]] = true
		}
	}
	if rows == 0 {
		t.Fatal("the profile table has no field rows")
	}
	set := func(l []string) map[string]bool {
		m := map[string]bool{}
		for _, x := range l {
			m[x] = true
		}
		return m
	}
	if !reflect.DeepEqual(set(neverWritten["minimal"]), set(neverWritten["standard"])) {
		t.Errorf("neverWritten differs for minimal and standard, which the profile table shows in one column")
	}
	for col, prof := range map[string]string{"minimal and standard": "minimal", "full": "full"} {
		if want := set(neverWritten[prof]); !reflect.DeepEqual(never[col], want) {
			t.Errorf("profile table says %q never for %v; the schema (neverWritten[%q]) rejects %v", col, keys(never[col]), prof, keys(want))
		}
	}
}

func keys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestSecurityPolicyNamesAReportingChannel: SECURITY.md asks reporters to
// report privately, so it must say where, and must not ship with a
// placeholder. (It is the reference documentation's one check that is not
// about the record; it lives with the docs/EVENTS.md checks.)
func TestSecurityPolicyNamesAReportingChannel(t *testing.T) {
	doc := readText(t, securityDoc)
	if i := strings.Index(doc, "TODO"); i >= 0 {
		t.Errorf("SECURITY.md has a placeholder: %q", doc[i:min(len(doc), i+80)])
	}
	const head = "## Reporting a vulnerability"
	i := strings.Index(doc, head)
	if i < 0 {
		t.Fatalf("SECURITY.md has no %q section", head)
	}
	sec := doc[i+len(head):]
	if j := strings.Index(sec, "\n## "); j >= 0 {
		sec = sec[:j]
	}
	// HTML comments are notes for the maintainer, not a channel.
	sec = regexp.MustCompile(`(?s)<!--.*?-->`).ReplaceAllString(sec, "")
	if !regexp.MustCompile(`https://[^\s)>]+/security/advisories/new|mailto:[^\s)>]+@|[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+\.[A-Za-z.]{2,}`).MatchString(sec) {
		t.Errorf("SECURITY.md %q names no private reporting channel (a security advisory link or an address)", head)
	}
}

// TestSchemaDocExamplesAreReal requires every example record quoted in
// docs/EVENTS.md (a ```json block after an "<!-- example: <file> -->"
// comment) to be one of the lines the binary wrote under
// docs/schema/examples, value for value.
func TestSchemaDocExamplesAreReal(t *testing.T) {
	doc := readText(t, eventsDoc)
	re := regexp.MustCompile("(?s)<!-- example: ([a-z0-9_.-]+\\.ndjson) -->\\s*```json\\n(.*?)\\n```")
	ms := re.FindAllStringSubmatch(doc, -1)
	if len(ms) < 3 {
		t.Fatalf("docs/EVENTS.md quotes %d example records, want at least 3", len(ms))
	}
	byFile := map[string][]exampleLine{}
	for _, ex := range readExamples(t) {
		byFile[ex.file] = append(byFile[ex.file], ex)
	}
	for _, m := range ms {
		x, err := decodeJSON([]byte(m[2]))
		if err != nil {
			t.Errorf("example from %s is not JSON: %v", m[1], err)
			continue
		}
		found := false
		for _, ex := range byFile[m[1]] {
			if jsonEqual(ex.val, x) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("the example quoted from %s is not a line of that file: %s", m[1], short(x))
		}
	}
}
