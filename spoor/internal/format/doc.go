// Package format converts the native spoor event into the wire shapes that
// downstream systems expect: the generic JSON object (Native), an OCSF 1.9.0
// event (OCSF) and an OTLP/HTTP JSON logs export request (OTLPLogs).
//
// The native event is always the source of truth. Both mappings are lossless
// by construction rather than by the standards: OCSF output carries the full
// native event under unmapped.spoor and the OTLP log record body is the native
// event as a kvlistValue (which Fluent Bit's opentelemetry input turns back
// into the record map).
//
// Everything here is a pure function of its input. Inputs are treated as
// hostile: Tool.Input is the only field with unbounded shape, so its nesting
// is cut at MaxDepth before any encoder recurses into it, and every entry
// point recovers from panics and reports them as errors (or, for OCSF, as a
// minimal base event) instead of taking the sensor down.
//
// What is not supported: OCSF output is hand-checked against the v1.9.0
// schema files for required attributes and names but is not run through the
// official validator; ATT&CK and ATLAS technique names are not emitted (only
// ids, which is all the rule tags carry); OTLP output is logs only.
package format
