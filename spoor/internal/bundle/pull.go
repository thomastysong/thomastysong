package bundle

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	stateName      = "pull.json"
	maxStateBytes  = 4096
	maxURLBytes    = 2048
	maxETagBytes   = 256
	maxRedirects   = 5
	defaultTimeout = 2 * time.Minute
	// userAgent is deliberately generic: the request must not describe the
	// host it comes from.
	userAgent = "spoor-bundle"
)

// PullOptions configure Pull.
type PullOptions struct {
	// URL of the bundle archive. The signature is fetched from the same
	// URL with ".sig" appended to the path.
	URL string
	// Pubs are the trusted signing keys. At least one is required.
	Pubs []ed25519.PublicKey
	// DestDir is the directory Install and Current work on.
	DestDir string
	// Client defaults to a client with a two minute timeout that honours
	// the proxy environment. Its redirect policy is always tightened (see
	// Pull); the client itself is not modified.
	Client *http.Client
	// MaxBytes caps the download. Zero, or anything above MaxBytes, means
	// MaxBytes (32 MiB).
	MaxBytes int64
	// Validate is passed to the install step: see InstallOptions.Validate.
	Validate func(dir string, m *Manifest) error
}

// Pull fetches the bundle at o.URL, verifies it and installs it when it is
// newer than the installed one.
//
// It sends If-None-Match with the ETag of the last successful pull, so an
// unchanged bundle costs one 304 response. On a 200 it fetches <URL>.sig,
// runs Verify and then Install. updated is true when the files on disk
// changed; m is the manifest that is current afterwards. A server that
// serves the installed bundle again without honouring the conditional
// request is not an error: updated is false.
//
// The scheme must be https, except that plain http is accepted for a
// loopback host (a local mirror or a test server). Redirects are followed at
// most five times, never from https to http and never from a remote host to
// a loopback address. Integrity never depends on the transport: whatever
// arrives is only used after the signature check.
//
// Errors do not contain the URL's credentials, path or query.
func Pull(ctx context.Context, o PullOptions) (updated bool, m *Manifest, err error) {
	defer func() {
		if r := recover(); r != nil {
			updated, m, err = false, nil, recovered(r)
		}
	}()
	if ctx == nil {
		ctx = context.Background()
	}
	if len(usableKeys(o.Pubs)) == 0 {
		return false, nil, ErrNoKeys
	}
	if o.DestDir == "" {
		return false, nil, errors.New("bundle: empty destination directory")
	}
	u, err := parsePullURL(o.URL)
	if err != nil {
		return false, nil, err
	}
	limit := int64(MaxBytes)
	if o.MaxBytes > 0 && o.MaxBytes < limit {
		limit = o.MaxBytes
	}
	client := pullClient(o.Client, u)

	cur, err := Installed(o.DestDir)
	if errors.Is(err, ErrInsecure) {
		// Install would refuse the destination anyway; do not download.
		return false, nil, err
	}
	// The stored ETag is only offered when it describes what is installed
	// right now. If the bundle directory was wiped or replaced by other
	// means, a 304 would leave the host without the content it should have.
	urlSum := sha256.Sum256([]byte(o.URL))
	st := pullState{URLSum: hex.EncodeToString(urlSum[:])}
	etag := ""
	if cur != nil {
		if old, ok := readPullState(o.DestDir); ok && old.URLSum == st.URLSum &&
			old.Version == cur.Manifest.Version && old.Digest == cur.Manifest.Digest() {
			etag = old.ETag
		}
	}

	archive, err := fetch(ctx, client, u, etag, limit, "bundle")
	if err != nil {
		return false, nil, err
	}
	if archive.notModified {
		return false, cur.Manifest, nil
	}
	sig, err := fetch(ctx, client, sigURL(u), "", maxSigBytes, "signature")
	if err != nil {
		return false, nil, err
	}
	verified, err := Verify(archive.body, sig.body, o.Pubs)
	if err != nil {
		return false, nil, err
	}
	err = InstallWith(archive.body, verified, o.DestDir, InstallOptions{Validate: o.Validate})
	switch {
	case errors.Is(err, ErrAlreadyInstalled):
		// The server ignored the conditional request, or another puller
		// installed the same bundle first.
	case err != nil:
		return false, nil, err
	default:
		updated = true
	}
	m = verified.clone()
	st.ETag, st.Version, st.Digest = archive.etag, m.Version, m.Digest()
	savePullState(o.DestDir, st)
	return updated, m, nil
}

// parsePullURL applies the transport policy to the configured URL. Its
// errors never repeat the URL, which may embed credentials.
func parsePullURL(raw string) (*url.URL, error) {
	if raw == "" || len(raw) > maxURLBytes {
		return nil, fmt.Errorf("%w: empty or longer than %d bytes", ErrURL, maxURLBytes)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot be parsed", ErrURL)
	}
	if u.Opaque != "" || u.Hostname() == "" {
		return nil, fmt.Errorf("%w: no host", ErrURL)
	}
	if u.Path == "" || strings.HasSuffix(u.Path, "/") {
		return nil, fmt.Errorf("%w: the URL must name the bundle file", ErrURL)
	}
	u.Fragment, u.RawFragment = "", ""
	switch u.Scheme {
	case "https":
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return nil, fmt.Errorf("%w: http is only accepted for a loopback host; use https", ErrURL)
		}
	default:
		return nil, fmt.Errorf("%w: scheme must be https", ErrURL)
	}
	return u, nil
}

// isLoopbackHost reports whether host is the name localhost or a loopback
// address literal. Other names are never treated as loopback, whatever they
// resolve to.
func isLoopbackHost(host string) bool {
	host = strings.TrimSuffix(host, ".")
	if strings.EqualFold(host, "localhost") {
		return true
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	return addr.Unmap().IsLoopback()
}

func sigURL(u *url.URL) *url.URL {
	s := *u
	s.Path += ".sig"
	if s.RawPath != "" {
		s.RawPath += ".sig"
	}
	return &s
}

// origin is the only part of a URL that goes into error text.
func origin(u *url.URL) string { return u.Scheme + "://" + u.Host }

// pullClient returns a copy of the caller's client (or a default one) whose
// redirect policy cannot be used to downgrade the transport or to make a
// privileged process issue requests to services on the local host.
func pullClient(c *http.Client, start *url.URL) *http.Client {
	var out http.Client
	if c != nil {
		out = *c
	} else {
		out.Timeout = defaultTimeout
	}
	prev := out.CheckRedirect
	loopbackStart := isLoopbackHost(start.Hostname())
	out.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) > maxRedirects {
			return fmt.Errorf("%w: more than %d redirects", ErrURL, maxRedirects)
		}
		loopback := isLoopbackHost(req.URL.Hostname())
		switch {
		case loopback && !loopbackStart:
			return fmt.Errorf("%w: redirect from a remote host to a loopback address", ErrURL)
		case req.URL.Scheme == "https", req.URL.Scheme == "http" && loopback:
		default:
			return fmt.Errorf("%w: redirect to a URL that is not https", ErrURL)
		}
		if prev != nil {
			return prev(req, via)
		}
		return nil
	}
	return &out
}

type fetched struct {
	body        []byte
	etag        string
	notModified bool
}

func fetch(ctx context.Context, c *http.Client, u *url.URL, etag string, limit int64, what string) (*fetched, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: cannot build the %s request", ErrFetch, what)
	}
	req.Header.Set("User-Agent", userAgent)
	// Asking for identity stops the transport from transparently inflating
	// a response a server labelled Content-Encoding: gzip, which would hand
	// back the tar stream instead of the signed .tar.gz bytes.
	req.Header.Set("Accept-Encoding", "identity")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := c.Do(req)
	if err != nil {
		return nil, fetchError(what, u, err)
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusNotModified && etag != "":
		return &fetched{notModified: true}, nil
	case resp.StatusCode != http.StatusOK:
		return nil, fmt.Errorf("%w: %s from %s: HTTP status %d", ErrFetch, what, origin(u), resp.StatusCode)
	}
	if resp.ContentLength > limit {
		return nil, fmt.Errorf("%w: %s from %s is larger than %d bytes", ErrTooLarge, what, origin(u), limit)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fetchError(what, u, err)
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("%w: %s from %s is larger than %d bytes", ErrTooLarge, what, origin(u), limit)
	}
	return &fetched{body: body, etag: cleanETag(resp.Header.Get("ETag"))}, nil
}

// fetchError drops the *url.Error wrapper, whose text repeats the full URL
// including any query-string token, and keeps the cause.
func fetchError(what string, u *url.URL, err error) error {
	var ue *url.Error
	if errors.As(err, &ue) && ue.Err != nil {
		err = ue.Err
	}
	return fmt.Errorf("%w: %s from %s: %w", ErrFetch, what, origin(u), err)
}

// cleanETag keeps an entity tag only when it can be sent back safely in a
// request header.
func cleanETag(s string) string {
	if s == "" || len(s) > maxETagBytes {
		return ""
	}
	for i := 0; i < len(s); i++ {
		if s[i] <= 0x20 || s[i] >= 0x7f {
			return ""
		}
	}
	return s
}

// pullState is what Pull remembers between runs. The URL is stored as a
// digest only: the file sits in a directory hook processes can list, and the
// URL may carry a token.
type pullState struct {
	URLSum  string `json:"url_sha256"`
	ETag    string `json:"etag"`
	Version uint64 `json:"version"`
	Digest  string `json:"digest"`
}

func readPullState(destDir string) (pullState, bool) {
	var st pullState
	b, err := readRegular(filepath.Join(destDir, stateName), maxStateBytes)
	if err != nil {
		return st, false
	}
	if json.Unmarshal(b, &st) != nil {
		return pullState{}, false
	}
	st.ETag = cleanETag(st.ETag)
	return st, st.ETag != ""
}

// savePullState is best effort. Losing the state costs one unconditional
// download on the next pull and nothing else, so failures are not reported.
func savePullState(destDir string, st pullState) {
	b, err := json.Marshal(st)
	if err != nil {
		return
	}
	// A unique temporary name keeps two concurrent pulls from interleaving
	// their writes. os.CreateTemp creates the file 0600.
	f, err := os.CreateTemp(destDir, stateName+".*"+stageSuffix)
	if err != nil {
		return
	}
	tmp := f.Name()
	_, werr := f.Write(append(b, '\n'))
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr == nil {
		werr = renameRetry(tmp, filepath.Join(destDir, stateName))
	}
	if werr != nil {
		os.Remove(tmp)
	}
}
