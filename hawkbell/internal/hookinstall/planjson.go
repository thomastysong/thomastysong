package hookinstall

import (
	"bytes"
	"strings"
)

// installJSON plans the hook registration in a JSON file. refused is a
// separate plan when native telemetry was asked for but cannot be written.
func installJSON(t target, o Options, cur fileState, want []entry, rel related) (action string, after []byte, note string, refused *Plan) {
	spec, useOTel := otelFor(t, o)
	refuse := func(why string) {
		refused = &Plan{
			AgentID: t.agentID, Path: t.path, Scope: t.scope, root: o.Root,
			Action: ActionUnsupported, Before: cur.data,
			Note: "native OpenTelemetry not written: " + why + "; each agent has one OTLP destination per signal and hawkbell does not take over an existing one",
		}
		useOTel = false
	}
	if useOTel && rel.otelPinned != "" {
		refuse("a telemetry destination is already configured in " + rel.otelPinned)
	}

	if !cur.exists || len(bytes.TrimSpace(cur.data)) == 0 {
		var extra jobj
		if useOTel {
			extra = jobj{{spec.key, spec.set}}
		}
		action = ActionCreate
		if cur.exists {
			action = ActionMerge
		}
		return action, newDocument(want, t.kind, extra), "", refused
	}

	d, err := parseJSON(cur.data)
	if err != nil {
		return ActionUnsupported, nil, "the file is not a JSON object hawkbell can edit (" + err.Error() + "); it is never rewritten", refused
	}
	if (d.comments || d.trailingCommas) && !o.Force {
		return ActionUnsupported, nil, "the file has comments or trailing commas (JSONC); rerun with --force to patch it in place, keeping them", refused
	}
	sc := scanHooks(d, t.kind)
	if sc.malformed != "" {
		return ActionUnsupported, nil, sc.malformed + "; hawkbell cannot add hooks without destroying it", refused
	}
	if useOTel {
		if c := spec.conflicts(d); len(c) > 0 {
			refuse("this file already sets " + strings.Join(c, ", "))
		}
	}

	src := cur.data
	if state, _ := sc.compare(want, t.kind); state != contentOK {
		if src, _, err = removeHawkbell(src, t.kind); err == nil {
			src, err = addEntries(src, want, t.kind)
		}
		if err != nil {
			return ActionUnsupported, nil, "the hooks in this file have a shape hawkbell cannot extend (" + err.Error() + ")", refused
		}
	}
	if t.kind == kindFlat {
		var vnote string
		if src, vnote, err = ensureVersion(src); err != nil {
			return ActionUnsupported, nil, err.Error(), refused
		}
		note = vnote
	}
	if useOTel {
		if src, err = spec.apply(src); err != nil {
			return ActionUnsupported, nil, err.Error(), refused
		}
	}
	// What was produced must read back as exactly the wanted registration.
	if d2, err := parseJSON(src); err != nil {
		return ActionUnsupported, nil, "editing the file would not leave valid JSON", refused
	} else if st, _ := scanHooks(d2, t.kind).compare(want, t.kind); st != contentOK {
		return ActionUnsupported, nil, "the hooks in this file have a shape hawkbell cannot extend", refused
	}
	if bytes.Equal(src, cur.data) {
		return ActionUnchanged, nil, note, refused
	}
	return ActionMerge, src, note, refused
}

// otelFor returns the telemetry settings to place in t's JSON file.
func otelFor(t target, o Options) (otelSpec, bool) {
	if o.OTel == "" {
		return otelSpec{}, false
	}
	ep, err := parseOTelEndpoint(o.OTel)
	if err != nil {
		return otelSpec{}, false
	}
	return jsonOTel(t.dialect, ep)
}

// Residues are what a file hawkbell created holds once its entries are gone.
// A file in exactly that state is removed by uninstall, so a user's
// configuration directory looks the way it did before install.
var (
	residueGroups = []byte("{}\n")
	residueFlat   = []byte("{\n  \"version\": 1\n}\n")
)

func isResidue(src []byte, kind fileKind) bool {
	if kind == kindFlat {
		return bytes.Equal(src, residueFlat)
	}
	return bytes.Equal(src, residueGroups)
}

// uninstallJSON removes hawkbell's entries and telemetry settings.
func uninstallJSON(t target, o Options, cur fileState) (action string, after []byte, note string) {
	if !cur.exists {
		return ActionUnchanged, nil, "no hook file"
	}
	d, err := parseJSON(cur.data)
	if err != nil {
		return ActionUnsupported, nil, "the file is not a JSON object hawkbell can edit (" + err.Error() + "); it is never rewritten"
	}
	sc := scanHooks(d, t.kind)
	spec, haveSpec := otelFor(t, o)
	if !haveSpec && t.owned {
		// The drop-in is hawkbell's own: whatever telemetry settings it holds
		// were written by hawkbell, whatever the endpoint was.
		spec, haveSpec = jsonOTel(t.dialect, otelEndpoint{})
	}
	if len(sc.hawkbellAll()) == 0 && !haveSpec {
		return ActionUnchanged, nil, leftOTel(t, d)
	}
	if (d.comments || d.trailingCommas) && !o.Force {
		return ActionUnsupported, nil, "the file has comments or trailing commas (JSONC); rerun with --force to patch it in place, keeping them"
	}
	src, _, err := removeHawkbell(cur.data, t.kind)
	if err != nil {
		return ActionUnsupported, nil, err.Error()
	}
	if haveSpec {
		var kept []string
		if src, kept, err = spec.remove(src, t.owned); err != nil {
			return ActionUnsupported, nil, err.Error()
		}
		if len(kept) > 0 {
			note = spec.key + "." + strings.Join(kept, ", "+spec.key+".") + " left in place: other telemetry settings in " + spec.key + " still use it"
		}
	} else if d2, err := parseJSON(src); err == nil {
		note = leftOTel(t, d2)
	}
	if bytes.Equal(src, cur.data) {
		return ActionUnchanged, nil, note
	}
	if (t.owned && onlyHawkbellLeft(src, t.kind)) || isResidue(src, t.kind) {
		return ActionRemove, nil, note
	}
	return ActionMerge, src, note
}

// leftOTel explains telemetry settings that uninstall cannot attribute.
func leftOTel(t target, d *jsonDoc) string {
	spec, ok := jsonOTel(t.dialect, otelEndpoint{})
	if !ok {
		return ""
	}
	if _, obj := d.root.member(spec.key); obj != nil {
		if _, v := obj.member(spec.anchor); v != nil {
			return "native telemetry settings (" + spec.key + "." + spec.anchor + ") were left in place: uninstall with the same OTel endpoint to remove them if hawkbell wrote them"
		}
	}
	return ""
}
