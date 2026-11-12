package bundle

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

// origin is a static file host for one bundle, like an object store or an
// nginx directory. It records what the client asked for.
type originServer struct {
	mu      sync.Mutex
	tarball []byte
	sig     []byte
	etag    string // "" = the host sends no ETag
	// honour says whether the host answers If-None-Match with 304.
	honour bool
	// tweak, when set, may take over a response.
	tweak func(w http.ResponseWriter, r *http.Request) bool

	bundleGETs, sigGETs, notModified int
	lastINM                          string
	lastHeaders                      http.Header
	lastSigURL                       string
}

func (o *originServer) publish(tarball, sig []byte, etag string) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.tarball, o.sig, o.etag = tarball, sig, etag
}

func (o *originServer) counts() (bundle, sig, notModified int) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.bundleGETs, o.sigGETs, o.notModified
}

func (o *originServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.tweak != nil && o.tweak(w, r) {
		return
	}
	switch {
	case strings.HasSuffix(r.URL.Path, "/bundle.tgz.sig"):
		o.sigGETs++
		o.lastSigURL = r.URL.String()
		w.Write(o.sig)
	case strings.HasSuffix(r.URL.Path, "/bundle.tgz"):
		o.bundleGETs++
		o.lastINM = r.Header.Get("If-None-Match")
		o.lastHeaders = r.Header.Clone()
		if o.etag != "" {
			w.Header().Set("ETag", o.etag)
			if o.honour && o.lastINM == o.etag {
				o.notModified++
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
		w.Header().Set("Content-Type", "application/gzip")
		w.Write(o.tarball)
	default:
		http.NotFound(w, r)
	}
}

func newOrigin(t *testing.T) (*originServer, *httptest.Server) {
	t.Helper()
	o := &originServer{honour: true}
	srv := httptest.NewServer(o)
	t.Cleanup(srv.Close)
	return o, srv
}

func pullOpts(srv *httptest.Server, dest string) PullOptions {
	return PullOptions{URL: srv.URL + "/content/bundle.tgz", Pubs: trusted(), DestDir: dest}
}

func TestPullInstallsThenUsesETag(t *testing.T) {
	o, srv := newOrigin(t)
	tarball, sig := build(t, 5, sampleFiles("v5"))
	o.publish(tarball, sig, `"etag-v5"`)
	dest := filepath.Join(t.TempDir(), "bundle")
	ctx := context.Background()

	updated, m, err := Pull(ctx, pullOpts(srv, dest))
	if err != nil || !updated || m == nil || m.Version != 5 {
		t.Fatalf("first Pull = %v, %+v, %v", updated, m, err)
	}
	if o.lastINM != "" {
		t.Errorf("first request sent If-None-Match %q", o.lastINM)
	}
	if got := o.lastHeaders.Get("Accept-Encoding"); got != "identity" {
		t.Errorf("Accept-Encoding = %q, want identity", got)
	}
	if ua := o.lastHeaders.Get("User-Agent"); ua != userAgent || strings.Contains(ua, "Go-http-client") {
		t.Errorf("User-Agent = %q", ua)
	}
	if got := currentVersion(t, dest); got != 5 {
		t.Fatalf("current = v%d", got)
	}
	// Install only takes manifests from Verify; the one Pull hands back is
	// for reporting.
	if err := Install(tarball, m, t.TempDir()); !errors.Is(err, ErrNotVerified) {
		t.Errorf("Pull's manifest unlocked Install: %v", err)
	}

	// Unchanged bundle: one conditional request, a 304, no signature fetch.
	updated, m, err = Pull(ctx, pullOpts(srv, dest))
	if err != nil || updated || m == nil || m.Version != 5 {
		t.Fatalf("second Pull = %v, %+v, %v", updated, m, err)
	}
	if o.lastINM != `"etag-v5"` {
		t.Errorf("If-None-Match = %q, want the stored ETag", o.lastINM)
	}
	if b, s, nm := o.counts(); b != 2 || s != 1 || nm != 1 {
		t.Errorf("requests: bundle=%d sig=%d 304=%d, want 2, 1, 1", b, s, nm)
	}

	// A new version changes the ETag: the conditional request gets a 200.
	tarball6, sig6 := build(t, 6, sampleFiles("v6"))
	o.publish(tarball6, sig6, `"etag-v6"`)
	updated, m, err = Pull(ctx, pullOpts(srv, dest))
	if err != nil || !updated || m.Version != 6 {
		t.Fatalf("third Pull = %v, %+v, %v", updated, m, err)
	}
	if _, err := Audit(dest); err != nil {
		t.Fatal(err)
	}
	updated, _, err = Pull(ctx, pullOpts(srv, dest))
	if err != nil || updated || o.lastINM != `"etag-v6"` {
		t.Fatalf("fourth Pull = %v, %v, If-None-Match %q", updated, err, o.lastINM)
	}

	// The state file is private and does not store the URL.
	state, err := os.ReadFile(filepath.Join(dest, stateName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(state), "127.0.0.1") || strings.Contains(string(state), "bundle.tgz") {
		t.Errorf("pull state stores the URL: %s", state)
	}
	if fi, _ := os.Stat(filepath.Join(dest, stateName)); runtime.GOOS != "windows" && fi.Mode().Perm() != 0o600 {
		t.Errorf("pull state mode = %04o, want 0600", fi.Mode().Perm())
	}
}

func TestPullWithoutConditionalSupport(t *testing.T) {
	for name, setup := range map[string]func(o *originServer){
		"no ETag header":         func(o *originServer) { o.etag = "" },
		"ETag but always 200":    func(o *originServer) { o.honour = false },
		"unusable ETag (spaces)": func(o *originServer) { o.etag = "has spaces" },
		"unusable ETag (bytes)":  func(o *originServer) { o.etag = "\"caf\xe9\"" },
		"oversized ETag":         func(o *originServer) { o.etag = `"` + strings.Repeat("e", 1000) + `"` },
	} {
		t.Run(name, func(t *testing.T) {
			o, srv := newOrigin(t)
			tarball, sig := build(t, 5, sampleFiles("v5"))
			o.publish(tarball, sig, `"e5"`)
			setup(o)
			dest := filepath.Join(t.TempDir(), "bundle")
			if updated, _, err := Pull(context.Background(), pullOpts(srv, dest)); err != nil || !updated {
				t.Fatalf("first Pull = %v, %v", updated, err)
			}
			before := listTree(t, dest)
			for i := 0; i < 3; i++ {
				updated, m, err := Pull(context.Background(), pullOpts(srv, dest))
				if err != nil || updated || m == nil || m.Version != 5 {
					t.Fatalf("repeat Pull %d = %v, %+v, %v; the same bundle served again is not an error", i, updated, m, err)
				}
			}
			if after := listTree(t, dest); strings.Join(after, "|") != strings.Join(before, "|") {
				t.Errorf("repeat pulls changed the destination:\n%v\n%v", before, after)
			}
			if name != "ETag but always 200" && o.lastINM != "" {
				t.Errorf("sent If-None-Match %q although the host gave no usable ETag", o.lastINM)
			}
		})
	}
}

func TestPullRefusesWhatInstallRefuses(t *testing.T) {
	o, srv := newOrigin(t)
	v5, sig5 := build(t, 5, sampleFiles("v5"))
	v4, sig4 := build(t, 4, sampleFiles("v4"))
	v5b, sig5b := build(t, 5, sampleFiles("v5-other"))
	dest := filepath.Join(t.TempDir(), "bundle")
	o.publish(v5, sig5, `"e5"`)
	if _, _, err := Pull(context.Background(), pullOpts(srv, dest)); err != nil {
		t.Fatal(err)
	}

	// A compromised or rolled-back host serves an older, validly signed
	// bundle.
	o.publish(v4, sig4, `"e4"`)
	updated, m, err := Pull(context.Background(), pullOpts(srv, dest))
	if !errors.Is(err, ErrDowngrade) || updated || m != nil {
		t.Fatalf("Pull of an older bundle = %v, %+v, %v; want ErrDowngrade", updated, m, err)
	}
	o.publish(v5b, sig5b, `"e5b"`)
	if _, _, err := Pull(context.Background(), pullOpts(srv, dest)); !errors.Is(err, ErrDowngrade) {
		t.Fatalf("Pull of a reused version number = %v, want ErrDowngrade", err)
	}
	if got := currentVersion(t, dest); got != 5 {
		t.Fatalf("current = v%d, want v5", got)
	}
	// The refused bundle's ETag was not remembered: once the host serves
	// the right content again the client must look at it.
	o.publish(v5, sig5, `"e4"`)
	if updated, _, err := Pull(context.Background(), pullOpts(srv, dest)); err != nil || updated {
		t.Fatalf("Pull after the host recovered = %v, %v", updated, err)
	}
}

func TestPullSignatureFailures(t *testing.T) {
	good, goodSig := build(t, 5, sampleFiles("v5"))
	other, otherSig := build(t, 6, sampleFiles("v6"))
	_ = other
	tests := map[string]struct {
		sig  []byte
		pubs []ed25519.PublicKey
		want error
	}{
		"signature of another bundle": {otherSig, trusted(), ErrSignature},
		"signed by an untrusted key":  {Sign(good, otherPriv), trusted(), ErrSignature},
		"wrong key configured":        {goodSig, []ed25519.PublicKey{otherPub}, ErrSignature},
		"empty signature file":        {nil, trusted(), ErrSignature},
		"html error page as sig":      {[]byte("<html>404</html>"), trusted(), ErrSignature},
		"oversized signature file":    {make([]byte, maxSigBytes+1), trusted(), ErrTooLarge},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			o, srv := newOrigin(t)
			o.publish(good, tc.sig, `"e"`)
			dest := filepath.Join(t.TempDir(), "bundle")
			opts := pullOpts(srv, dest)
			opts.Pubs = tc.pubs
			updated, m, err := Pull(context.Background(), opts)
			if !errors.Is(err, tc.want) || updated || m != nil {
				t.Fatalf("Pull = %v, %+v, %v; want %v", updated, m, err, tc.want)
			}
			if _, _, ok := Current(dest); ok {
				t.Fatal("unverified content was installed")
			}
			if _, err := os.Stat(filepath.Join(dest, stateName)); err == nil {
				t.Error("an ETag was stored for content that failed verification")
			}
		})
	}

	t.Run("signature missing", func(t *testing.T) {
		o, srv := newOrigin(t)
		o.publish(good, goodSig, `"e"`)
		o.tweak = func(w http.ResponseWriter, r *http.Request) bool {
			if strings.HasSuffix(r.URL.Path, ".sig") {
				http.NotFound(w, r)
				return true
			}
			return false
		}
		_, _, err := Pull(context.Background(), pullOpts(srv, t.TempDir()))
		if !errors.Is(err, ErrFetch) || !strings.Contains(err.Error(), "404") {
			t.Fatalf("Pull = %v, want ErrFetch mentioning 404", err)
		}
	})
	t.Run("no keys: nothing is requested", func(t *testing.T) {
		o, srv := newOrigin(t)
		o.publish(good, goodSig, `"e"`)
		opts := pullOpts(srv, t.TempDir())
		for _, pubs := range [][]ed25519.PublicKey{nil, {}, {nil}, {make(ed25519.PublicKey, 32)}} {
			opts.Pubs = pubs
			if _, _, err := Pull(context.Background(), opts); !errors.Is(err, ErrNoKeys) {
				t.Fatalf("Pull without keys = %v, want ErrNoKeys", err)
			}
		}
		if b, s, _ := o.counts(); b+s != 0 {
			t.Errorf("%d requests were made without any trusted key", b+s)
		}
	})
}

func TestPullSizeLimits(t *testing.T) {
	tarball, sig := build(t, 5, sampleFiles("v5"))
	t.Run("MaxBytes with Content-Length", func(t *testing.T) {
		o, srv := newOrigin(t)
		o.publish(tarball, sig, "")
		opts := pullOpts(srv, t.TempDir())
		opts.MaxBytes = int64(len(tarball) - 1)
		if _, _, err := Pull(context.Background(), opts); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("Pull = %v, want ErrTooLarge", err)
		}
		opts.MaxBytes = int64(len(tarball))
		if updated, _, err := Pull(context.Background(), opts); err != nil || !updated {
			t.Fatalf("Pull at exactly MaxBytes = %v, %v", updated, err)
		}
	})
	t.Run("endless chunked body", func(t *testing.T) {
		o, srv := newOrigin(t)
		o.tweak = func(w http.ResponseWriter, r *http.Request) bool {
			chunk := make([]byte, 64<<10)
			for i := 0; i < 1024; i++ { // 64 MiB if the client kept reading
				if _, err := w.Write(chunk); err != nil {
					return true
				}
				w.(http.Flusher).Flush()
			}
			return true
		}
		opts := pullOpts(srv, t.TempDir())
		opts.MaxBytes = 1 << 20
		if _, _, err := Pull(context.Background(), opts); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("Pull = %v, want ErrTooLarge", err)
		}
	})
	t.Run("MaxBytes cannot raise the package limit", func(t *testing.T) {
		o, srv := newOrigin(t)
		o.tweak = func(w http.ResponseWriter, r *http.Request) bool {
			w.Header().Set("Content-Length", fmt.Sprint(MaxBytes+1))
			w.WriteHeader(http.StatusOK)
			return true
		}
		opts := pullOpts(srv, t.TempDir())
		opts.MaxBytes = 1 << 40
		if _, _, err := Pull(context.Background(), opts); !errors.Is(err, ErrTooLarge) {
			t.Fatalf("Pull = %v, want ErrTooLarge", err)
		}
	})
}

func TestPullURLPolicy(t *testing.T) {
	good := []string{
		"https://updates.example.com/hawkbell/bundle.tgz",
		"https://updates.example.com:8443/b.tgz?X-Amz-Signature=abc",
		"https://user:pass@updates.example.com/b.tgz",
		"https://10.0.0.5/b.tgz",
		"http://localhost/b.tgz",
		"http://LOCALHOST.:8080/b.tgz",
		"http://127.0.0.1:8080/b.tgz",
		"http://127.8.9.10/b.tgz",
		"http://[::1]:8080/b.tgz",
		"http://[::ffff:127.0.0.1]/b.tgz",
		"HTTPS://updates.example.com/b.tgz",
	}
	for _, raw := range good {
		if _, err := parsePullURL(raw); err != nil {
			t.Errorf("parsePullURL(%q) = %v, want accepted", raw, err)
		}
	}
	bad := []string{
		"",
		"http://updates.example.com/b.tgz",
		"http://10.0.0.5/b.tgz",
		"http://169.254.169.254/latest/meta-data/x",
		"http://127.0.0.1.evil.example/b.tgz",
		"http://localhost.evil.example/b.tgz",
		"http://evil.example/localhost/b.tgz",
		"http://localhost@evil.example/b.tgz",
		"http://0.0.0.0/b.tgz",
		"http://[::]/b.tgz",
		"ftp://updates.example.com/b.tgz",
		"file:///var/lib/hawkbell/b.tgz",
		"//updates.example.com/b.tgz",
		"updates.example.com/b.tgz",
		"/var/lib/hawkbell/b.tgz",
		"https:///b.tgz",
		"https://updates.example.com",
		"https://updates.example.com/",
		"https://updates.example.com/dir/",
		"mailto:ops@example.com",
		"https://up dates.example.com/b.tgz",
		"https://updates.example.com/%zz",
		"https://" + strings.Repeat("a", 3000) + ".example.com/b.tgz",
	}
	for _, raw := range bad {
		_, err := parsePullURL(raw)
		if !errors.Is(err, ErrURL) {
			t.Errorf("parsePullURL(%q) = %v, want ErrURL", raw, err)
			continue
		}
		if raw != "" && len(raw) < 100 && strings.Contains(err.Error(), raw) {
			t.Errorf("error repeats the URL: %v", err)
		}
	}
	// Refused before any connection is attempted.
	_, _, err := Pull(context.Background(), PullOptions{URL: "http://updates.example.com/b.tgz", Pubs: trusted(), DestDir: t.TempDir(),
		Client: &http.Client{Transport: failTransport{t}}})
	if !errors.Is(err, ErrURL) {
		t.Fatalf("Pull over plain http = %v, want ErrURL", err)
	}
	if _, _, err := Pull(context.Background(), PullOptions{URL: "https://x.example/b.tgz", Pubs: trusted()}); err == nil {
		t.Fatal("Pull accepted an empty destination")
	}
}

// failTransport fails the test if any request reaches the network layer.
type failTransport struct{ t *testing.T }

func (f failTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	f.t.Errorf("unexpected request to %s", r.URL.Host)
	return nil, errors.New("no network in tests")
}

// scripted answers requests from a table keyed by URL, so redirect chains
// across "remote" hosts can be exercised without a network.
type scripted map[string]func(r *http.Request) *http.Response

func (s scripted) RoundTrip(r *http.Request) (*http.Response, error) {
	key := r.URL.Scheme + "://" + r.URL.Host + r.URL.Path
	fn, ok := s[key]
	if !ok {
		return nil, fmt.Errorf("scripted transport: no answer for %s", key)
	}
	resp := fn(r)
	resp.Request = r
	return resp, nil
}

func redirectTo(loc string) func(*http.Request) *http.Response {
	return func(*http.Request) *http.Response {
		return &http.Response{StatusCode: http.StatusFound, Header: http.Header{"Location": {loc}}, Body: http.NoBody}
	}
}

func serve(body []byte) func(*http.Request) *http.Response {
	return func(*http.Request) *http.Response {
		return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: io.NopCloser(strings.NewReader(string(body))), ContentLength: int64(len(body))}
	}
}

func TestPullRedirectPolicy(t *testing.T) {
	tarball, sig := build(t, 5, sampleFiles("v5"))
	const start = "https://updates.example.com/b.tgz"
	touched := func(hit *bool) func(*http.Request) *http.Response {
		return func(*http.Request) *http.Response {
			*hit = true
			return &http.Response{StatusCode: http.StatusOK, Header: http.Header{}, Body: http.NoBody}
		}
	}

	t.Run("https to https on another host is followed", func(t *testing.T) {
		tr := scripted{
			start:                                 redirectTo("https://cdn.example.net/objects/abc"),
			"https://cdn.example.net/objects/abc": serve(tarball),
			start + ".sig":                        serve(sig),
		}
		dest := filepath.Join(t.TempDir(), "bundle")
		updated, m, err := Pull(context.Background(), PullOptions{URL: start, Pubs: trusted(), DestDir: dest, Client: &http.Client{Transport: tr}})
		if err != nil || !updated || m.Version != 5 {
			t.Fatalf("Pull = %v, %+v, %v", updated, m, err)
		}
	})

	refused := map[string]string{
		"https to http":                "http://cdn.example.net/b.tgz",
		"https to loopback http":       "http://127.0.0.1:8080/admin",
		"https to loopback https":      "https://localhost:8443/admin",
		"https to IPv6 loopback":       "https://[::1]/admin",
		"https to another scheme":      "ftp://cdn.example.net/b.tgz",
		"https to cloud metadata http": "http://169.254.169.254/latest/meta-data/",
	}
	for name, target := range refused {
		t.Run(name, func(t *testing.T) {
			hit := false
			tr := scripted{start: redirectTo(target)}
			if u, err := url.Parse(target); err == nil {
				tr[u.Scheme+"://"+u.Host+u.Path] = touched(&hit)
			}
			_, _, err := Pull(context.Background(), PullOptions{URL: start, Pubs: trusted(), DestDir: t.TempDir(), Client: &http.Client{Transport: tr}})
			if !errors.Is(err, ErrURL) {
				t.Fatalf("Pull = %v, want ErrURL", err)
			}
			if Reason(err) != "url" {
				t.Errorf("Reason = %q, want url", Reason(err))
			}
			if hit {
				t.Error("the redirect target was requested")
			}
		})
	}

	t.Run("redirect loop is cut", func(t *testing.T) {
		n := 0
		tr := scripted{start: func(*http.Request) *http.Response {
			n++
			return redirectTo(start)(nil)
		}}
		_, _, err := Pull(context.Background(), PullOptions{URL: start, Pubs: trusted(), DestDir: t.TempDir(), Client: &http.Client{Transport: tr}})
		if !errors.Is(err, ErrURL) || n > maxRedirects+2 {
			t.Fatalf("Pull = %v after %d requests", err, n)
		}
	})

	t.Run("the caller's own redirect policy still applies", func(t *testing.T) {
		tr := scripted{start: redirectTo("https://cdn.example.net/b.tgz")}
		mine := errors.New("no redirects here")
		c := &http.Client{Transport: tr, CheckRedirect: func(*http.Request, []*http.Request) error { return mine }}
		_, _, err := Pull(context.Background(), PullOptions{URL: start, Pubs: trusted(), DestDir: t.TempDir(), Client: c})
		if !errors.Is(err, mine) {
			t.Fatalf("Pull = %v, want the caller's redirect error", err)
		}
		if c.CheckRedirect == nil || c.Timeout != 0 {
			t.Error("Pull modified the caller's client")
		}
	})

	t.Run("loopback to loopback is followed, loopback to remote http is not", func(t *testing.T) {
		o, target := newOrigin(t)
		o.publish(tarball, sig, "")
		hop := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, ".sig") {
				w.Write(sig)
				return
			}
			http.Redirect(w, r, target.URL+"/content/bundle.tgz", http.StatusFound)
		}))
		defer hop.Close()
		dest := filepath.Join(t.TempDir(), "bundle")
		if updated, _, err := Pull(context.Background(), PullOptions{URL: hop.URL + "/b.tgz", Pubs: trusted(), DestDir: dest}); err != nil || !updated {
			t.Fatalf("Pull through a local redirect = %v, %v", updated, err)
		}

		leave := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://updates.example.invalid/b.tgz", http.StatusFound)
		}))
		defer leave.Close()
		_, _, err := Pull(context.Background(), PullOptions{URL: leave.URL + "/b.tgz", Pubs: trusted(), DestDir: t.TempDir()})
		if !errors.Is(err, ErrURL) {
			t.Fatalf("Pull redirected to remote http = %v, want ErrURL", err)
		}
	})
}

func TestPullErrorsDoNotLeakTheURL(t *testing.T) {
	secrets := []string{"s3cr3t-password", "TOKEN-abcdef", "private-path-segment"}
	check := func(t *testing.T, err error) {
		t.Helper()
		if err == nil {
			t.Fatal("expected an error")
		}
		for _, s := range secrets {
			if strings.Contains(err.Error(), s) {
				t.Errorf("error leaks %q: %v", s, err)
			}
		}
	}
	withSecrets := func(base string) string {
		u, _ := url.Parse(base)
		u.User = url.UserPassword("deploy", secrets[0])
		u.Path = "/" + secrets[2] + "/bundle.tgz"
		u.RawQuery = "sig=" + secrets[1]
		return u.String()
	}

	t.Run("HTTP error status", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Error(w, "boom", http.StatusInternalServerError)
		}))
		defer srv.Close()
		_, _, err := Pull(context.Background(), PullOptions{URL: withSecrets(srv.URL), Pubs: trusted(), DestDir: t.TempDir()})
		check(t, err)
		if !errors.Is(err, ErrFetch) || !strings.Contains(err.Error(), "500") {
			t.Errorf("Pull = %v, want ErrFetch mentioning the status", err)
		}
	})
	t.Run("connection refused", func(t *testing.T) {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Skip(err)
		}
		addr := l.Addr().String()
		l.Close()
		_, _, err = Pull(context.Background(), PullOptions{URL: withSecrets("http://" + addr), Pubs: trusted(), DestDir: t.TempDir()})
		check(t, err)
		if !errors.Is(err, ErrFetch) {
			t.Errorf("Pull = %v, want ErrFetch", err)
		}
	})
	t.Run("redirect refused", func(t *testing.T) {
		tr := scripted{"https://updates.example.com/" + secrets[2] + "/bundle.tgz": redirectTo("http://evil.example/" + secrets[1])}
		_, _, err := Pull(context.Background(), PullOptions{URL: withSecrets("https://updates.example.com"), Pubs: trusted(), DestDir: t.TempDir(),
			Client: &http.Client{Transport: tr}})
		check(t, err)
	})
	t.Run("credentials and query reach the server", func(t *testing.T) {
		var user, pass, query, sigQuery string
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(r.URL.Path, ".sig") {
				sigQuery = r.URL.RawQuery
			} else {
				user, pass, _ = r.BasicAuth()
				query = r.URL.RawQuery
			}
			http.NotFound(w, r)
		}))
		defer srv.Close()
		_, _, err := Pull(context.Background(), PullOptions{URL: withSecrets(srv.URL), Pubs: trusted(), DestDir: t.TempDir()})
		check(t, err)
		if user != "deploy" || pass != secrets[0] || query != "sig="+secrets[1] {
			t.Errorf("server saw user=%q pass=%q query=%q", user, pass, query)
		}
		_ = sigQuery
	})
}

func TestPullSignatureURL(t *testing.T) {
	o, srv := newOrigin(t)
	tarball, sig := build(t, 5, sampleFiles("v5"))
	o.publish(tarball, sig, "")
	opts := pullOpts(srv, filepath.Join(t.TempDir(), "bundle"))
	opts.URL += "?token=abc&x=1#fragment"
	if updated, _, err := Pull(context.Background(), opts); err != nil || !updated {
		t.Fatalf("Pull = %v, %v", updated, err)
	}
	if o.lastSigURL != "/content/bundle.tgz.sig?token=abc&x=1" {
		t.Errorf("signature requested at %q; .sig belongs on the path, before the query", o.lastSigURL)
	}
}

func TestPullOverTLS(t *testing.T) {
	o := &originServer{honour: true}
	srv := httptest.NewUnstartedServer(o)
	srv.Config.ErrorLog = log.New(io.Discard, "", 0) // the refused handshake below is expected
	srv.StartTLS()
	defer srv.Close()
	tarball, sig := build(t, 5, sampleFiles("v5"))
	o.publish(tarball, sig, `"tls"`)
	dest := filepath.Join(t.TempDir(), "bundle")

	// Without the test CA the default client must refuse the certificate:
	// Pull does not weaken TLS verification.
	if _, _, err := Pull(context.Background(), pullOpts(srv, dest)); !errors.Is(err, ErrFetch) {
		t.Fatalf("Pull against an untrusted certificate = %v, want ErrFetch", err)
	}
	opts := pullOpts(srv, dest)
	opts.Client = srv.Client()
	if updated, m, err := Pull(context.Background(), opts); err != nil || !updated || m.Version != 5 {
		t.Fatalf("Pull over TLS = %v, %+v, %v", updated, m, err)
	}
	if updated, _, err := Pull(context.Background(), opts); err != nil || updated {
		t.Fatalf("second Pull over TLS = %v, %v", updated, err)
	}
}

func TestPullTransportDoesNotInflate(t *testing.T) {
	// Some hosts label .tgz files Content-Encoding: gzip. A client that let
	// the transport decode that would hash the tar stream, not the signed
	// archive.
	o, srv := newOrigin(t)
	tarball, sig := build(t, 5, sampleFiles("v5"))
	o.tweak = func(w http.ResponseWriter, r *http.Request) bool {
		if strings.HasSuffix(r.URL.Path, ".sig") {
			return false
		}
		w.Header().Set("Content-Encoding", "gzip")
		w.Write(tarball)
		return true
	}
	o.publish(tarball, sig, "")
	if updated, _, err := Pull(context.Background(), pullOpts(srv, filepath.Join(t.TempDir(), "bundle"))); err != nil || !updated {
		t.Fatalf("Pull = %v, %v", updated, err)
	}
}

func TestPullContext(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := Pull(ctx, PullOptions{URL: srv.URL + "/b.tgz", Pubs: trusted(), DestDir: t.TempDir()}); !errors.Is(err, context.Canceled) {
		t.Fatalf("Pull with a cancelled context = %v, want context.Canceled", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, _, err := Pull(ctx, PullOptions{URL: srv.URL + "/b.tgz", Pubs: trusted(), DestDir: t.TempDir()})
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 10*time.Second {
		t.Fatalf("Pull against a hanging server = %v after %v", err, time.Since(start))
	}
	//lint:ignore SA1012 a nil context must not panic
	var nilCtx context.Context
	if _, _, err := Pull(nilCtx, PullOptions{URL: "http://example.com/b.tgz", Pubs: trusted(), DestDir: t.TempDir()}); !errors.Is(err, ErrURL) {
		t.Fatalf("Pull(nil ctx) = %v", err)
	}
}

func TestPullValidate(t *testing.T) {
	o, srv := newOrigin(t)
	v5, sig5 := build(t, 5, sampleFiles("v5"))
	v6, sig6 := build(t, 6, sampleFiles("v6"))
	dest := filepath.Join(t.TempDir(), "bundle")
	o.publish(v5, sig5, `"e5"`)
	if _, _, err := Pull(context.Background(), pullOpts(srv, dest)); err != nil {
		t.Fatal(err)
	}

	o.publish(v6, sig6, `"e6"`)
	opts := pullOpts(srv, dest)
	calls := 0
	opts.Validate = func(dir string, m *Manifest) error {
		calls++
		return errors.New("rules/core.yaml: line 3: unknown operator")
	}
	for i := 0; i < 2; i++ {
		updated, m, err := Pull(context.Background(), opts)
		if !errors.Is(err, ErrRejected) || updated || m != nil {
			t.Fatalf("Pull = %v, %+v, %v; want ErrRejected", updated, m, err)
		}
	}
	// The broken bundle is offered again on every pull (its ETag was not
	// stored), so the failure stays visible until a fixed one is published.
	if calls != 2 {
		t.Errorf("validator ran %d times, want 2", calls)
	}
	if got := currentVersion(t, dest); got != 5 {
		t.Fatalf("current = v%d, want v5", got)
	}
	opts.Validate = func(string, *Manifest) error { return nil }
	if updated, m, err := Pull(context.Background(), opts); err != nil || !updated || m.Version != 6 {
		t.Fatalf("Pull with a passing validator = %v, %+v, %v", updated, m, err)
	}
}

// If the bundle directory is wiped or damaged while the ETag state stays,
// a 304 would leave the host without content. Pull must notice.
func TestPullDoesNotTrustStaleETag(t *testing.T) {
	o, srv := newOrigin(t)
	tarball, sig := build(t, 5, sampleFiles("v5"))
	o.publish(tarball, sig, `"e5"`)
	dest := filepath.Join(t.TempDir(), "bundle")
	pull := func() (bool, error) {
		updated, _, err := Pull(context.Background(), pullOpts(srv, dest))
		return updated, err
	}
	if _, err := pull(); err != nil {
		t.Fatal(err)
	}

	t.Run("pointer removed", func(t *testing.T) {
		os.Remove(filepath.Join(dest, "current"))
		updated, err := pull()
		if err != nil || !updated || o.lastINM != "" {
			t.Fatalf("Pull = %v, %v, If-None-Match %q", updated, err, o.lastINM)
		}
	})
	t.Run("version directory removed", func(t *testing.T) {
		os.RemoveAll(filepath.Join(dest, "v5"))
		updated, err := pull()
		if err != nil || !updated || o.lastINM != "" {
			t.Fatalf("Pull = %v, %v, If-None-Match %q", updated, err, o.lastINM)
		}
		if _, err := Audit(dest); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("different URL", func(t *testing.T) {
		opts := pullOpts(srv, dest)
		opts.URL = srv.URL + "/mirror/bundle.tgz"
		if updated, _, err := Pull(context.Background(), opts); err != nil || updated || o.lastINM != "" {
			t.Fatalf("Pull from another URL = %v, %v, If-None-Match %q", updated, err, o.lastINM)
		}
	})
	t.Run("another version installed by hand", func(t *testing.T) {
		if _, err := pull(); err != nil { // re-associate the state with this URL
			t.Fatal(err)
		}
		install(t, dest, 9, sampleFiles("v9"))
		// The host still serves v5: no conditional request (the ETag is
		// about v5, not v9), and v5 is refused as a downgrade.
		_, err := pull()
		if !errors.Is(err, ErrDowngrade) || o.lastINM != "" {
			t.Fatalf("Pull = %v, If-None-Match %q", err, o.lastINM)
		}
	})
	t.Run("garbage state file", func(t *testing.T) {
		os.WriteFile(filepath.Join(dest, stateName), []byte("{{{{"), 0o600)
		if _, err := pull(); !errors.Is(err, ErrDowngrade) {
			t.Fatalf("Pull with a damaged state file = %v", err)
		}
	})
}

// A damaged install is repaired by the next pull even when the host does
// not support conditional requests.
func TestPullRepairsDamagedInstall(t *testing.T) {
	o, srv := newOrigin(t)
	tarball, sig := build(t, 5, sampleFiles("v5"))
	o.publish(tarball, sig, "")
	dest := filepath.Join(t.TempDir(), "bundle")
	if _, _, err := Pull(context.Background(), pullOpts(srv, dest)); err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dest, "v5", "lists.yaml"), []byte("tampered"), 0o644)
	updated, _, err := Pull(context.Background(), pullOpts(srv, dest))
	if err != nil || !updated {
		t.Fatalf("Pull over a damaged install = %v, %v; want a repair reported as an update", updated, err)
	}
	if _, err := Audit(dest); err != nil {
		t.Fatal(err)
	}
}

func TestPullInsecureDestination(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no mode bits on Windows")
	}
	o, srv := newOrigin(t)
	tarball, sig := build(t, 5, sampleFiles("v5"))
	o.publish(tarball, sig, "")
	dest := filepath.Join(t.TempDir(), "bundle")
	os.Mkdir(dest, 0o755)
	os.Chmod(dest, 0o777)
	if _, _, err := Pull(context.Background(), pullOpts(srv, dest)); !errors.Is(err, ErrInsecure) {
		t.Fatalf("Pull into a world-writable destination = %v, want ErrInsecure", err)
	}
	if b, _, _ := o.counts(); b != 0 {
		t.Error("the bundle was downloaded although it could never be installed")
	}
}

func TestConcurrentPull(t *testing.T) {
	o, srv := newOrigin(t)
	tarball, sig := build(t, 5, sampleFiles("v5"))
	o.publish(tarball, sig, `"e5"`)
	dest := filepath.Join(t.TempDir(), "bundle")

	const n = 8
	var wg sync.WaitGroup
	results := make([]bool, n)
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			var m *Manifest
			results[i], m, errs[i] = Pull(context.Background(), pullOpts(srv, dest))
			if errs[i] == nil && (m == nil || m.Version != 5) {
				errs[i] = fmt.Errorf("manifest %+v", m)
			}
		}(i)
	}
	wg.Wait()
	updates := 0
	for i := range errs {
		if errs[i] != nil {
			t.Errorf("puller %d: %v", i, errs[i])
		}
		if results[i] {
			updates++
		}
	}
	if updates != 1 {
		t.Errorf("%d pullers reported an update, want exactly 1", updates)
	}
	if _, err := Audit(dest); err != nil {
		t.Fatal(err)
	}
	for _, p := range listTree(t, dest) {
		if strings.HasSuffix(p, ".tmp") {
			t.Errorf("temporary file left behind: %s", p)
		}
	}
}
