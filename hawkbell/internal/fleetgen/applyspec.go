package fleetgen

import (
	"bytes"
	"errors"
	"strings"
	"unicode"

	"gopkg.in/yaml.v3"
)

// ApplySpecs renders a profile's labels, policies and reports as
// `fleetctl apply -f` documents (kinds label, policy and report), every name
// prefixed with prefix. It exists for verification against a live server,
// where objects must be applied one by one under names that cannot collide
// with anything already there, and deleted afterwards: `fleetctl gitops`
// replaces the whole server configuration and must never be used for that.
// Policies are global (Fleet Free has no fleets).
func ApplySpecs(p Profile, prefix string) ([]byte, error) {
	if err := checkPrefix(prefix); err != nil {
		return nil, err
	}
	var docs []*yaml.Node
	doc := func(kind string, spec *yaml.Node) {
		docs = append(docs, mapping("apiVersion", scalar("v1"), "kind", scalar(kind), "spec", spec))
	}
	for _, l := range p.Labels {
		spec := mapping("name", scalar(prefix+l.Name), "description", scalar(l.Description),
			"query", sqlScalar(l.Query), "label_membership_type", scalar("dynamic"))
		if l.Platform != "" {
			spec.Content = append(spec.Content, scalar("platform"), scalar(l.Platform))
		}
		doc("label", spec)
	}
	for _, pol := range p.Policies {
		pol.Name = prefix + pol.Name
		doc("policy", policyNode(pol))
	}
	for _, r := range p.Reports {
		r.Name = prefix + r.Name
		doc("report", reportNode(r))
	}
	var b bytes.Buffer
	for i, d := range docs {
		if i > 0 {
			b.WriteString("---\n")
		}
		e := yaml.NewEncoder(&b)
		e.SetIndent(2)
		if err := e.Encode(d); err != nil {
			return nil, err
		}
		if err := e.Close(); err != nil {
			return nil, err
		}
	}
	return b.Bytes(), nil
}

// checkPrefix keeps verification prefixes recognisable and harmless: they
// end up in object names on a shared server and in the names cleanup
// matches on.
func checkPrefix(prefix string) error {
	if len(prefix) < 3 || len(prefix) > 40 {
		return errors.New("fleetgen: prefix must be 3 to 40 characters")
	}
	for _, r := range prefix {
		if !(unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("-_. ", r)) || r > unicode.MaxASCII {
			return errors.New("fleetgen: prefix may contain only ASCII letters, digits, '-', '_', '.' and spaces")
		}
	}
	return nil
}
