package mcpconf

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

func TestJSONCToJSON(t *testing.T) {
	cases := []struct {
		name, in, want string // want is strict JSON with the same value; "" means the result must not parse
	}{
		{"plain", `{"a":1}`, `{"a":1}`},
		{"line comment", "{\n  // c\n  \"a\": 1 // tail\n}", `{"a":1}`},
		{"block comment", `{/* x */"a":/* y
		z */1}`, `{"a":1}`},
		{"trailing comma object", `{"a":1,}`, `{"a":1}`},
		{"trailing comma array", `{"a":[1,2,],}`, `{"a":[1,2]}`},
		{"trailing comma before comment", "{\"a\":[1, // one\n ], /* end */ }", `{"a":[1]}`},
		{"slashes in string", `{"u":"http://x/y","c":"/* not */","d":"a // b"}`, `{"u":"http://x/y","c":"/* not */","d":"a // b"}`},
		{"escaped quote before slashes", `{"a":"q\"//still string","b":"x\\"}//c`, `{"a":"q\"//still string","b":"x\\"}`},
		{"comma in string kept", `{"a":",}","b":[",]"]}`, `{"a":",}","b":[",]"]}`},
		{"comment with quote", "{// \"unbalanced\n\"a\":1}", `{"a":1}`},
		{"comment at eof", `{"a":1}// done`, `{"a":1}`},
		{"crlf", "{\r\n  \"a\": 1, // c\r\n}\r\n", `{"a":1}`},
		{"unterminated block comment", `{"a":1 /* never closed`, ""},
		{"only comments", "// nothing\n/* at all */", ""},
		{"lone slash is not a comment", `{"a":1}/`, ""},
		{"double trailing comma is still an error", `{"a":[1,,]}`, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out, _ := jsoncToJSON([]byte(c.in))
			if len(out) != len(c.in) {
				t.Fatalf("length changed: %d -> %d", len(c.in), len(out))
			}
			if strings.Count(string(out), "\n") != strings.Count(c.in, "\n") {
				t.Fatalf("newlines changed, line numbers would be wrong")
			}
			var got any
			err := json.Unmarshal(out, &got)
			if c.want == "" {
				if err == nil {
					t.Fatalf("expected a parse failure, got %#v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("result does not parse: %v\n%s", err, out)
			}
			var want any
			if err := json.Unmarshal([]byte(c.want), &want); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got, want) {
				t.Errorf("got %#v want %#v", got, want)
			}
		})
	}
}

func TestJSONCNodeEstimateIsUpperBound(t *testing.T) {
	_, n := jsoncToJSON([]byte(`{"a":[1,2,{"b":[]}],"c":"x,y,[z]"}`))
	// values: root, a-array, 1, 2, object, b-array, "c" string = 7; the
	// estimate counts 4 opens + 3 commas and ignores punctuation in strings.
	if n != 7 {
		t.Errorf("node estimate = %d, want 7", n)
	}
}
