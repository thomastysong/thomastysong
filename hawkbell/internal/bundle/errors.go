package bundle

import (
	"errors"
	"fmt"
	"strconv"
)

// Sentinel errors. Every error returned by this package wraps exactly one of
// them (or an *os.PathError / context error for plain I/O and cancellation),
// so callers can branch with errors.Is and report a stable reason.
var (
	// ErrSignature: the signature is malformed or matches no trusted key.
	ErrSignature = errors.New("bundle: signature does not verify against any trusted key")
	// ErrNoKeys: no usable public key was supplied. Unsigned content is
	// never accepted, so this is an error rather than a bypass.
	ErrNoKeys = errors.New("bundle: no trusted public key")
	// ErrFormat: the bytes are not a gzip-compressed tar archive in the
	// strict form this package accepts.
	ErrFormat = errors.New("bundle: malformed archive")
	// ErrTooLarge: more than MaxFiles entries or more than MaxBytes.
	ErrTooLarge = errors.New("bundle: size or file-count limit exceeded")
	// ErrUnsafePath: an entry name is absolute, climbs out of the tree,
	// contains a separator or device name another OS would interpret, or is
	// otherwise not a plain relative path.
	ErrUnsafePath = errors.New("bundle: unsafe path")
	// ErrNotRegular: an entry is a symlink, hard link, directory, device or
	// any other non-regular file.
	ErrNotRegular = errors.New("bundle: entry is not a regular file")
	// ErrNotAllowed: a well-formed name that is not on the allow-list.
	ErrNotAllowed = errors.New("bundle: file is not on the allow-list")
	// ErrManifest: manifest.json is missing, unparsable or inconsistent.
	ErrManifest = errors.New("bundle: invalid manifest")
	// ErrMismatch: the content differs from what the manifest lists.
	ErrMismatch = errors.New("bundle: content does not match the manifest")
	// ErrDowngrade: the offered version is lower than the installed one, or
	// reuses its number with different content.
	ErrDowngrade = errors.New("bundle: version is not newer than the installed one")
	// ErrAlreadyInstalled: the offered bundle is the installed one.
	ErrAlreadyInstalled = errors.New("bundle: this version is already installed")
	// ErrNotVerified: Install was given a manifest that Verify did not
	// return for these exact bytes.
	ErrNotVerified = errors.New("bundle: manifest was not returned by Verify for this tarball")
	// ErrRejected: the caller's Validate callback refused the content.
	ErrRejected = errors.New("bundle: content rejected by the validator")
	// ErrBusy: another installer held the lock for the whole wait.
	ErrBusy = errors.New("bundle: another install is in progress")
	// ErrInsecure: the destination could be modified by another user.
	ErrInsecure = errors.New("bundle: insecure ownership or permissions")
	// ErrNotInstalled: the destination holds no bundle.
	ErrNotInstalled = errors.New("bundle: no bundle is installed")
	// ErrCorrupt: the destination holds something this package cannot read
	// back (damaged pointer, missing version directory, bad manifest).
	ErrCorrupt = errors.New("bundle: installed state is damaged")
	// ErrURL: the pull URL breaks the transport policy.
	ErrURL = errors.New("bundle: URL not allowed")
	// ErrFetch: the download failed or the server answered unexpectedly.
	ErrFetch = errors.New("bundle: download failed")
	// ErrKey: a key string could not be parsed.
	ErrKey = errors.New("bundle: invalid key")
)

// VersionError is returned by Install when the offered version does not move
// the host forward. It matches ErrAlreadyInstalled when the offered bundle is
// the installed one (benign: a second installer, or a server that ignores
// conditional requests) and ErrDowngrade otherwise (an older bundle was
// replayed, or a version number was reused for different content).
type VersionError struct {
	Installed uint64
	Offered   uint64
	Identical bool
}

func (e *VersionError) Error() string {
	off, inst := strconv.FormatUint(e.Offered, 10), strconv.FormatUint(e.Installed, 10)
	switch {
	case e.Identical:
		return "bundle: version " + off + " is already installed"
	case e.Offered == e.Installed:
		return "bundle: version " + off + " is already installed with different content; publish a higher version"
	default:
		return "bundle: refusing version " + off + ": version " + inst + " is installed (no downgrade)"
	}
}

// Is lets errors.Is match the two sentinels without exposing which one
// applies to callers that only care that the version was refused.
func (e *VersionError) Is(target error) bool {
	if e.Identical {
		return target == ErrAlreadyInstalled
	}
	return target == ErrDowngrade
}

// Reason maps an error from this package to a short, stable, content-free
// token suitable for a health record ("bundle." + Reason(err)). It returns ""
// for nil and "error" for anything it does not recognise.
func Reason(err error) string {
	if err == nil {
		return ""
	}
	for _, r := range reasons {
		if errors.Is(err, r.err) {
			return r.name
		}
	}
	return "error"
}

// reasons is ordered: the first match wins, and wrapped causes are listed
// before the generic errors that may wrap them.
var reasons = []struct {
	err  error
	name string
}{
	{ErrSignature, "signature"},
	{ErrNoKeys, "no_keys"},
	{ErrDowngrade, "downgrade"},
	{ErrAlreadyInstalled, "already_installed"},
	{ErrNotVerified, "not_verified"},
	{ErrRejected, "rejected"},
	{ErrTooLarge, "too_large"},
	{ErrUnsafePath, "unsafe_path"},
	{ErrNotRegular, "not_regular"},
	{ErrNotAllowed, "not_allowed"},
	{ErrMismatch, "mismatch"},
	{ErrManifest, "manifest"},
	{ErrFormat, "format"},
	{ErrInsecure, "insecure_permissions"},
	{ErrBusy, "busy"},
	{ErrCorrupt, "corrupt"},
	{ErrNotInstalled, "not_installed"},
	{ErrURL, "url"},
	{ErrFetch, "fetch"},
	{ErrKey, "key"},
}

// recovered turns a panic value into an error. Every exported function that
// touches untrusted bytes defers a recover: the sensor must keep running
// whatever a hostile archive or server response manages to trigger.
func recovered(r any) error {
	return fmt.Errorf("bundle: internal error: %v", r)
}

// quote renders an untrusted name for an error message: escaped, and cut so
// a megabyte-long name cannot flood a log line.
func quote(s string) string {
	const max = 80
	if len(s) > max {
		return strconv.Quote(s[:max]) + "..."
	}
	return strconv.Quote(s)
}
