package privacy

import (
	"testing"

	"github.com/thomastysong/spoor/internal/event"
)

func TestExcluded(t *testing.T) {
	p := &Policy{Exclude: Exclusions{
		Paths: []string{"~/private/**", "/work/clients/*/secret", `C:\Users\*\Personal`, "scratch"},
		Repos: []string{"github.com/acme/*", "git@gitlab.com:team/hidden.git", "solo/repo"},
		Users: []string{"svc-*", "CORP\\alice"},
	}}
	mk := func(goos, user, cwd, remote string) *event.Event {
		e := event.New(event.KindActivity, event.TypeToolPre, event.SourceHook)
		e.Host = &event.Host{OS: goos}
		if user != "" {
			e.User = &event.User{Name: user}
		}
		if cwd != "" {
			e.Session = &event.Session{CWD: cwd}
		}
		if remote != "" {
			e.Repo = &event.Repo{Remote: remote}
		}
		return e
	}
	cases := []struct {
		name string
		e    *event.Event
		want bool
	}{
		{"home private", mk("linux", "bob", "/home/bob/private/diary", ""), true},
		{"home private root", mk("linux", "bob", "/home/bob/private", ""), true},
		{"other user's private", mk("linux", "bob", "/home/carol/private/x", ""), false},
		{"darwin home folded", mk("darwin", "bob", "/users/BOB/Private/x", ""), true},
		{"client secret tree", mk("linux", "bob", "/work/clients/acme/secret/src", ""), true},
		{"client public", mk("linux", "bob", "/work/clients/acme/public", ""), false},
		{"windows personal", mk("windows", "bob", `c:\users\bob\personal\notes`, ""), true},
		{"unanchored anywhere", mk("linux", "bob", "/srv/x/scratch/y", ""), true},
		{"unanchored no partial", mk("linux", "bob", "/srv/x/scratchpad", ""), false},
		{"dotdot normalised", mk("linux", "bob", "/home/bob/work/../private/x", ""), true},
		{"repo https", mk("linux", "bob", "/w", "https://user:tok@github.com/Acme/App.git"), true},
		{"repo scp", mk("linux", "bob", "/w", "git@github.com:acme/app.git"), true},
		{"repo other org", mk("linux", "bob", "/w", "https://github.com/other/app"), false},
		{"repo pattern scp form", mk("linux", "bob", "/w", "https://gitlab.com/team/hidden"), true},
		{"repo hostless pattern", mk("linux", "bob", "/w", "ssh://git@git.corp:2222/solo/repo.git"), true},
		{"user glob", mk("linux", "svc-build", "/w", ""), true},
		{"user domain", mk("windows", "CORP\\Alice", "/w", ""), true},
		{"user plain", mk("linux", "bob", "/w", ""), false},
		{"no identity", mk("linux", "", "", ""), false},
	}
	for _, c := range cases {
		if got := p.Excluded(c.e); got != c.want {
			t.Errorf("%s: Excluded = %v, want %v", c.name, got, c.want)
		}
		_, _, ok := p.Emit(c.e)
		if ok == c.want {
			t.Errorf("%s: Emit ok = %v, want %v", c.name, ok, !c.want)
		}
	}
}

func TestExcludedHealthAndInventory(t *testing.T) {
	p := &Policy{Exclude: Exclusions{Users: []string{"bob"}, Paths: []string{"/proj/secret"}}}
	h := event.New(event.KindHealth, event.TypeHealthHeartbeat, event.SourceSensor)
	h.User = &event.User{Name: "bob"}
	if p.Excluded(h) {
		t.Error("health records are never excluded")
	}
	inv := event.New(event.KindInventory, event.TypeInventoryAsset, event.SourceScan)
	inv.Asset = &event.Asset{Kind: event.AssetMCPServer, Owner: "bob"}
	if !p.Excluded(inv) {
		t.Error("inventory owned by an excluded user must be excluded")
	}
	proj := event.New(event.KindInventory, event.TypeInventoryAsset, event.SourceScan)
	proj.Asset = &event.Asset{Kind: event.AssetProjectConfig, Scope: event.ScopeProject, Path: "/proj/secret/.mcp.json"}
	if !p.Excluded(proj) {
		t.Error("project-scope asset inside an excluded path must be excluded")
	}
	userScope := event.New(event.KindInventory, event.TypeInventoryAsset, event.SourceScan)
	userScope.Asset = &event.Asset{Kind: event.AssetMCPServer, Scope: event.ScopeUser, Path: "/proj/secret/x"}
	if p.Excluded(userScope) {
		t.Error("only project-scope declarations are matched by path")
	}
}

func TestExcludedDoesNotReadContent(t *testing.T) {
	// A panic inside matching must fail towards excluded, and content is
	// never consulted: an event whose content would panic is still decided.
	p := &Policy{Exclude: Exclusions{Paths: []string{"/x"}}, HomeOf: func(string) string { panic("boom") }}
	e := event.New(event.KindActivity, event.TypeToolPre, event.SourceHook)
	e.User = &event.User{Name: "bob"}
	e.Session = &event.Session{CWD: "/x/y"}
	if !p.Excluded(e) {
		t.Error("expected excluded")
	}
}

func TestMatchSegsHostile(t *testing.T) {
	pat := normPath("/**/**/**/**/**/**/**/**/**/**/**/**/**/**/x", false)
	path := normPath("/"+stringsRepeat("a/", 250)+"b", false)
	if matchSegs(pat, path, true) {
		t.Error("unexpected match")
	}
	if checkGlob("[") == nil {
		t.Error("bad glob not reported")
	}
	if (&Policy{Exclude: Exclusions{Paths: []string{"["}}}).Validate() == nil {
		t.Error("Validate must report a bad glob")
	}
}

func stringsRepeat(s string, n int) string {
	out := make([]byte, 0, len(s)*n)
	for i := 0; i < n; i++ {
		out = append(out, s...)
	}
	return string(out)
}

func TestNormalizeRemote(t *testing.T) {
	for in, want := range map[string]string{
		"https://user:tok@github.com:8443/Acme/App.git": "github.com/acme/app",
		"git@github.com:acme/app.git":                   "github.com/acme/app",
		"ssh://git@github.com/acme/app":                 "github.com/acme/app",
		"github.com/acme/app/":                          "github.com/acme/app",
		"/srv/git/repo.git":                             "/srv/git/repo",
		"https://github.com/acme/app?x=1#y":             "github.com/acme/app",
	} {
		if got := normalizeRemote(in); got != want {
			t.Errorf("normalizeRemote(%q) = %q, want %q", in, got, want)
		}
	}
}
