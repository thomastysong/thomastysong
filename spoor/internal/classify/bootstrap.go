// Package classify assigns closed-vocabulary classes to paths and hosts,
// finds and redacts credentials, and scans text for hidden or injected
// instructions.
//
// BOOTSTRAP FILE: this placeholder exists only so packages that import
// classify compile while the real implementation is being written. The owner
// of this package deletes this file.
package classify

// SecretHit locates one credential in a string.
type SecretHit struct {
	Kind        string
	Start, End  int
	Fingerprint string
}

// FindSecrets is a placeholder that finds nothing.
func FindSecrets(s string) []SecretHit { return nil }
