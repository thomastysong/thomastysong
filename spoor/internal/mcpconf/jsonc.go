package mcpconf

// jsoncToJSON returns a copy of src with // and /* */ comments and trailing
// commas replaced by spaces, so that encoding/json can read VS Code, Zed,
// Cursor and opencode settings files.
//
// Bytes are blanked rather than removed: offsets and line numbers of the
// result match the original, which keeps SyntaxError.Line honest. Both passes
// are single forward scans; the look-ahead after a comma only crosses the
// whitespace run that follows it, so hostile input cannot make this quadratic.
func jsoncToJSON(src []byte) []byte {
	out := make([]byte, len(src))
	copy(out, src)
	n := len(out)

	inStr := false
	for i := 0; i < n; i++ {
		c := out[i]
		if inStr {
			switch c {
			case '\\':
				i++
			case '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case '/':
			if i+1 >= n {
				continue
			}
			switch out[i+1] {
			case '/':
				for i < n && out[i] != '\n' {
					out[i] = ' '
					i++
				}
				i-- // leave the newline for the outer loop
			case '*':
				out[i], out[i+1] = ' ', ' '
				i += 2
				for i < n {
					if out[i] == '*' && i+1 < n && out[i+1] == '/' {
						out[i], out[i+1] = ' ', ' '
						i++
						break
					}
					if out[i] != '\n' && out[i] != '\r' {
						out[i] = ' '
					}
					i++
				}
			}
		}
	}

	inStr = false
	for i := 0; i < n; i++ {
		c := out[i]
		if inStr {
			switch c {
			case '\\':
				i++
			case '"':
				inStr = false
			}
			continue
		}
		switch c {
		case '"':
			inStr = true
		case ',':
			j := i + 1
			for j < n && isJSONSpace(out[j]) {
				j++
			}
			if j < n && (out[j] == '}' || out[j] == ']') {
				out[i] = ' '
			}
		}
	}
	return out
}

func isJSONSpace(c byte) bool {
	return c == ' ' || c == '\t' || c == '\n' || c == '\r'
}
