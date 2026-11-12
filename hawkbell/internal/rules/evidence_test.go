package rules

import (
	"strings"
	"testing"

	"github.com/thomastysong/thomastysong/hawkbell/internal/event"
)

// Detections leave the host in every privacy profile, so their evidence
// must not carry credentials, including ones that have no recognisable
// shape and are secret only because of the flag they follow.
func TestEvidenceRedactsStructuralSecrets(t *testing.T) {
	s := mustPack(t, `  - id: HB-EVD-001
    title: any shell
    severity: low
    match: {tool.kind: shell}
    evidence: [target.command, shell.argv, shell.urls, target.url]`+dummyTest+`
  - id: HB-EVD-002
    title: any exec
    severity: low
    match: {type: process.exec}
    evidence: [process.args, target.command]`+dummyTest+"\n")
	e := NewEngine(s, Options{Home: "/home/u", OS: "linux", SuppressFor: 1})
	cases := []struct {
		cmd    string
		canary []string
		keep   []string
	}{
		{"mysql -uroot -pHunt3rTwo -h db.internal", []string{"Hunt3rTwo"}, []string{"mysql", "db.internal"}},
		{"curl -u admin:s3cr3tpw https://api.example/v1?token=qq81zz92yy73&page=2", []string{"s3cr3tpw", "qq81zz92yy73"}, []string{"api.example"}},
		{"deploy --token tk_live_short --region eu", []string{"tk_live_short"}, []string{"deploy", "eu"}},
		{`curl -H "Authorization: Bearer abcDEF123456ghiJKL" https://x.example`, []string{"abcDEF123456ghiJKL"}, []string{"x.example"}},
		{`sshpass -p 'pa ss' ssh u@h`, []string{"pa ss"}, []string{"sshpass"}},
		// Quotes split inside the value: not found verbatim, so the
		// evidence is rebuilt from the redacted argv.
		{`mysql -p'Hun'"t3r" db`, []string{"Hunt3r", "Hun'"}, []string{"mysql"}},
		{"redis-cli -a x -h cache", []string{" x "}, []string{"redis-cli"}},
	}
	for _, c := range cases {
		r := e.Eval(ev(event.TypeToolPre, shell(c.cmd)))
		if len(r.Detections) != 1 {
			t.Fatalf("%q: %v", c.cmd, ids(r.Detections))
		}
		all := ""
		for k, v := range r.Detections[0].Detection.Evidence {
			all += k + "=" + v + "\n"
		}
		for _, x := range c.canary {
			if strings.Contains(all, x) {
				t.Errorf("%q: evidence leaks %q:\n%s", c.cmd, x, all)
			}
		}
		for _, x := range c.keep {
			if !strings.Contains(all, x) {
				t.Errorf("%q: evidence lost %q:\n%s", c.cmd, x, all)
			}
		}
	}
	r := e.Eval(ev(event.TypeProcessExec, func(e *event.Event) {
		e.Process = &event.Process{Name: "psql", Args: []string{"psql", "--password=Zz9xWq", "-h", "db"}}
	}))
	if len(r.Detections) != 1 {
		t.Fatalf("process.exec: %v", ids(r.Detections))
	}
	for k, v := range r.Detections[0].Detection.Evidence {
		if strings.Contains(v, "Zz9xWq") {
			t.Errorf("process evidence %s leaks: %s", k, v)
		}
	}
}

func TestReplaceTokens(t *testing.T) {
	cases := []struct{ s, old, want string }{
		{"a -px b", "-px", "a R b"},
		{"x xx -p x", "x", "R xx -p R"},
		{`"x";x|y`, "x", `"R";R|y`},
		{"k=x:x", "x", "k=R:R"},
		{"axb", "x", "axb"},
	}
	for _, c := range cases {
		if got, _ := replaceTokens(c.s, c.old, "R"); got != c.want {
			t.Errorf("replaceTokens(%q, %q) = %q, want %q", c.s, c.old, got, c.want)
		}
	}
}
