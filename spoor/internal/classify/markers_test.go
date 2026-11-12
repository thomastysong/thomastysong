package classify

import (
	"math/rand/v2"
	"strings"
	"testing"
)

// randAlnum returns n seeded random letters and digits, for credentials
// that must look generated (they are assembled at run time, never
// committed in a provider's format).
func randAlnum(r *rand.Rand, n int) string {
	const alnum = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = alnum[r.IntN(len(alnum))]
	}
	return string(b)
}

func TestMarkerLen(t *testing.T) {
	for in, want := range map[string]int{
		"[REDACTED:password:1a2b3c4d]":                        28,
		"[REDACTED:password:1a2b3c4d] tail":                   28,
		"[REDACTED:password:hmac=1a2b3c4d]":                   33,
		"[REDACTED:secret_flow]":                              22,
		"[REDACTED:error:00000000]":                           25,
		"[REDACTED:database_url_with_password:x":              0,
		"[REDACTED:password:1a2b3c4]":                         0, // 7 hex
		"[REDACTED:password:1a2b3c4d5]":                       0, // 9 hex
		"[REDACTED:password:1A2B3C4D]":                        0, // upper-case hex
		"[REDACTED:Password:1a2b3c4d]":                        0, // upper-case kind
		"[REDACTED::1a2b3c4d]":                                0, // empty kind
		"[REDACTED:pass word:1a2b3c4d]":                       0,
		"[REDACTED:password:hmac=1a2b]":                       0,
		"[REDACTED:" + strings.Repeat("k", 64) + ":1a2b3c4d]": 84,
		"[REDACTED:" + strings.Repeat("k", 65) + ":1a2b3c4d]": 0,
		"[REDACTED:password:[REDACTED:password:1a2b3c4d]":     0,
		"[TRUNCATED:12B]":                                     0,
		"x[REDACTED:a:1a2b3c4d]":                              0,
		"":                                                    0,
		"[REDACTED:":                                          0,
	} {
		if got := markerLen(in); got != want {
			t.Errorf("markerLen(%q) = %d, want %d", in, got, want)
		}
	}
}

func TestMarkAroundMarkers(t *testing.T) {
	m := Marker(KindPassword, "1a2b3c4d")
	for _, c := range []struct{ in, want string }{
		{"abc", markerFor(KindURLParam, "abc")},
		{m, m},
		{"abc" + m, markerFor(KindURLParam, "abc") + m},
		{m + "def", m + markerFor(KindURLParam, "def")},
		{"abc" + m + "def" + m, markerFor(KindURLParam, "abc") + m + markerFor(KindURLParam, "def") + m},
		{m + m, m + m},
		// A broken marker is ordinary text.
		{"[REDACTED:x:zz]", markerFor(KindURLParam, "[REDACTED:x:zz]")},
	} {
		if got := markAroundMarkers(KindURLParam, c.in); got != c.want {
			t.Errorf("markAroundMarkers(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// TestRedactArgsDatabaseURLNoNestedMarker is the case from the privacy
// tier's notes (flattenNested): RedactArgs wrote the userinfo marker of a
// database URL, then its own URL and assignment patterns matched across that
// marker (the kind "database_url_with_password" reads as a password-named
// key, ":<fp>]@db/x" as its value) and yielded
// "postgres://[REDACTED:database_url_with_password:[REDACTED:password:fp]",
// losing the host as well.
func TestRedactArgsDatabaseURLNoNestedMarker(t *testing.T) {
	g := newCanaryGen()
	for _, c := range []struct{ prefix, userinfo, rest string }{
		{"postgres://", "admin:", "@db.internal:5432/prod"},
		{"postgresql://", "admin:", "@db.internal:5432/prod?sslmode=require"},
		{"mysql://", "root:", "@db.internal/app"},
		{"redis://", ":", "@cache.internal:6379/0"},
		{"mongodb+srv://", "svc:", "@cluster0.internal/app"},
		{"DATABASE_URL=postgres://", "admin:", "@db.internal/prod"},
		{"--url=mysql://", "app:", "@10.0.0.7:3306/app"},
	} {
		pw := g.next()
		in := c.prefix + c.userinfo + pw + c.rest
		out := RedactArgs([]string{"tool", in})[1]
		want := c.prefix + Marker(KindDatabaseURL, fingerprint(c.userinfo+pw)) + c.rest
		if out != want {
			t.Errorf("RedactArgs(%q)\n got %q\nwant %q", in, out, want)
		}
		// Re-redaction changes nothing and keeps the host.
		if again, hits := Redact(out); again != out || len(hits) != 0 {
			t.Errorf("Redact(%q) = %q, %v", out, again, hits)
		}
		if again := RedactArgs([]string{"tool", out})[1]; again != out {
			t.Errorf("RedactArgs not idempotent: %q -> %q", out, again)
		}
	}
	// The exact input that used to nest, given to Redact directly.
	for _, s := range []string{
		"postgres://[REDACTED:database_url_with_password:9d40c010]@db.internal/prod",
		"mysql://[REDACTED:database_url_with_password:9d40c010]@localhost/db",
		"x [REDACTED:database_url_with_password:9d40c010]@db.internal/prod y",
	} {
		if got, _ := Redact(s); got != s {
			t.Errorf("Redact(%q) = %q", s, got)
		}
		if got := RedactURL(s, true); !wellFormedMarkers(got) {
			t.Errorf("RedactURL(%q) = %q", s, got)
		}
	}
	if got := RedactURL("postgres://[REDACTED:database_url_with_password:9d40c010]@db.internal/prod", true); got != "postgres://db.internal/prod" {
		t.Errorf("RedactURL kept userinfo: %q", got)
	}
}

// TestRedactNeverMatchesInsideMarkers puts every marker form of every kind
// into the contexts where a pattern used to read a marker's words as a key
// or a credential. Nothing else in these strings is secret, so Redact must
// return them unchanged, and RedactURL must keep every marker whole.
func TestRedactNeverMatchesInsideMarkers(t *testing.T) {
	kinds := append(SecretKinds(), kindRedactionFailureLabel, "secret_flow", "command")
	contexts := []func(m string) string{
		func(m string) string { return "x=" + m + "@db.internal/app" },
		func(m string) string { return "password: " + m },
		func(m string) string { return "db_password = " + m + "; host=db.internal" },
		func(m string) string { return "Authorization: Bearer " + m },
		func(m string) string { return "Cookie: session=" + m + "; theme=dark" },
		func(m string) string { return m + ":" + m + "@host.internal" },
		func(m string) string { return "--token " + m + " --verbose" },
		func(m string) string { return "postgres://" + m + "@db.internal/app" },
		func(m string) string { return "https://u:" + m + "@h.internal/x" },
		func(m string) string { return `{"api_key": "` + m + `", "region": "eu"}` },
		func(m string) string { return "https://h.internal/cb?token=" + m + "&next=" + m + "#access_token=" + m },
		func(m string) string { return m + m + m },
		func(m string) string { return "export AWS_SECRET_ACCESS_KEY=" + m },
	}
	n := 0
	for _, k := range kinds {
		for _, m := range []string{Marker(k, "9d40c010"), "[REDACTED:" + k + ":hmac=0badc0de]", "[REDACTED:" + k + "]"} {
			if !isMarker(m) {
				t.Fatalf("not a marker: %q", m)
			}
			for _, ctx := range contexts {
				s := ctx(m)
				n++
				if got, hits := Redact(s); got != s {
					t.Errorf("Redact changed %q\n-> %q (%v)", s, got, hits)
				}
				for _, keep := range []bool{true, false} {
					if got := RedactURL(s, keep); !wellFormedMarkers(got) {
						t.Errorf("RedactURL(%q, %v) = %q", s, keep, got)
					}
				}
				if got := strings.Join(RedactArgs(strings.Fields(s)), " "); !wellFormedMarkers(got) {
					t.Errorf("RedactArgs(%q) = %q", s, got)
				}
			}
		}
	}
	t.Logf("%d marker contexts checked", n)
}

// TestRedactAroundMarkers: a marker shields only itself. Secrets next to
// one are still found, including ones the old whole-string scan missed
// because the value ran into the marker and was taken for a placeholder.
func TestRedactAroundMarkers(t *testing.T) {
	r := rand.New(rand.NewPCG(3, 5))
	m := Marker(KindPassword, "9d40c010")
	pw := "Hunt3r!" + randAlnum(r, 6)
	tok := randAlnum(r, 40)
	pat := "gh" + "p_" + randAlnum(r, 36)
	for _, c := range []struct {
		in     string
		gone   string
		forged bool
	}{
		{"db_password=" + pw + " " + m, pw, false},
		{"db_password=" + pw + m, pw, false},
		{m + " api_token=" + tok, tok, false},
		{m + " " + pat + " " + m, pat, false},
		{"https://bob:" + pw + "@h.internal/" + m, pw, false},
		// A forged marker cannot hide a token: upper-case letters are not
		// a kind and a token is not a digest, so this is ordinary text and
		// is scanned. (The forged "[REDACTED:" stays, as input text.)
		{"[REDACTED:" + pat + ":9d40c010]", pat, true},
		{"[REDACTED:x:" + pat + "]", pat, true},
	} {
		got, _ := Redact(c.in)
		if strings.Contains(got, c.gone) {
			t.Errorf("Redact(%q) kept the secret: %q", c.in, got)
		}
		if !c.forged && !wellFormedMarkers(got) {
			t.Errorf("Redact(%q) = %q: marker inside a marker", c.in, got)
		}
		if strings.Contains(c.in, m) && !strings.Contains(got, m) {
			t.Errorf("Redact(%q) lost the existing marker: %q", c.in, got)
		}
	}
	// Query values that hold a marker keep it and lose the rest.
	u := "https://h.internal/cb?code=abc" + m + "def&state=ok"
	got := RedactURL(u, true)
	want := "https://h.internal/cb?code=" + markerFor(KindURLParam, "abc") + m + markerFor(KindURLParam, "def") + "&state=ok"
	if got != want {
		t.Errorf("RedactURL(%q)\n got %q\nwant %q", u, got, want)
	}
}

// TestRedactArgsIdempotent: redacting the output of RedactArgs again
// changes nothing, for every vector of the canary corpus.
func TestRedactArgsIdempotent(t *testing.T) {
	g := newCanaryGen()
	for _, tmpl := range [][]string{
		{"mysql", "-p{pw}", "db"},
		{"sshpass", "-p", "{pw}", "ssh", "u@h"},
		{"smbclient", "-Ubob%{pw}", "//h/s"},
		{"lftp", "-u", "bob,{pw}", "sftp://h"},
		{"sqlplus", "scott/{pw}@orcl"},
		{"vault", "login", "{pw}"},
		{"keytool", "-list", "-storepass:{pw}"},
		{"curl", "-H", "Authorization: Bearer {pw}xyzxyzxyz", "-d", "password={pw}&u=a", "https://bob:{pw}@h.internal/x?token={pw}"},
		{"psql", "postgres://admin:{pw}@db.internal/prod"},
		{"export", "API_TOKEN={pw}"},
		{"run.exe", "/password:{pw}", "/password", "{pw}"},
	} {
		argv, _ := g.fill(tmpl)
		once := RedactArgs(argv)
		twice := RedactArgs(once)
		if strings.Join(once, "\x00") != strings.Join(twice, "\x00") {
			t.Errorf("not idempotent:\n once %q\ntwice %q", once, twice)
		}
		for _, a := range once {
			if r, _ := Redact(a); r != a {
				t.Errorf("Redact changed RedactArgs output %q -> %q", a, r)
			}
		}
	}
}

// TestFindSecretsManyMarkersBounded: text made of markers is scanned piece
// by piece; a hostile string of many markers must stay linear.
func TestFindSecretsManyMarkersBounded(t *testing.T) {
	unit := Marker(KindPassword, "9d40c010") + "x=1 "
	s := strings.Repeat(unit, (1<<20)/len(unit))
	if hits := FindSecrets(s); len(hits) != 0 {
		t.Errorf("%d hits in marker-only text", len(hits))
	}
	if got, _ := Redact(s); got != s {
		t.Error("Redact changed marker-only text")
	}
}
