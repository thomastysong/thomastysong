package main

import (
	"bytes"
	"fmt"

	"github.com/thomastysong/thomastysong/hawkbell/internal/classify"
)

// maxDiffCells bounds the LCS table (lines before x lines after, after the
// common head and tail are cut). Hook files are small; a larger change is
// shown as a whole-region replacement instead of being computed.
const maxDiffCells = 4 << 20

// redactedDiff returns the changed lines between two versions of a file,
// as "@@ -a,b +c,d @@" hunk headers followed by "-" and "+" lines with no
// context. The files are agents' settings files, which can hold API keys,
// tokens and MCP credentials, so only changed lines are shown and every
// line goes through classify.Redact first.
func redactedDiff(before, after []byte) []string {
	a, b := splitLines(before), splitLines(after)
	// Common head and tail first: an install changes a few lines in the
	// middle of a file, and this keeps the quadratic part small.
	head := 0
	for head < len(a) && head < len(b) && bytes.Equal(a[head], b[head]) {
		head++
	}
	tail := 0
	for tail < len(a)-head && tail < len(b)-head && bytes.Equal(a[len(a)-1-tail], b[len(b)-1-tail]) {
		tail++
	}
	ma, mb := a[head:len(a)-tail], b[head:len(b)-tail]
	if len(ma) == 0 && len(mb) == 0 {
		return nil
	}
	var ops []diffOp
	if len(ma)*len(mb) <= maxDiffCells {
		ops = lcsDiff(ma, mb)
	} else {
		for range ma {
			ops = append(ops, opDel)
		}
		for range mb {
			ops = append(ops, opAdd)
		}
	}
	return renderHunks(ma, mb, ops, head)
}

type diffOp byte

const (
	opKeep diffOp = iota
	opDel
	opAdd
)

// lcsDiff returns the edit script from a to b by longest common
// subsequence over lines.
func lcsDiff(a, b [][]byte) []diffOp {
	n, m := len(a), len(b)
	// dp[i][j] = LCS length of a[i:], b[j:], stored row-major.
	dp := make([]int32, (n+1)*(m+1))
	w := m + 1
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if bytes.Equal(a[i], b[j]) {
				dp[i*w+j] = dp[(i+1)*w+j+1] + 1
			} else if dp[(i+1)*w+j] >= dp[i*w+j+1] {
				dp[i*w+j] = dp[(i+1)*w+j]
			} else {
				dp[i*w+j] = dp[i*w+j+1]
			}
		}
	}
	var ops []diffOp
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case bytes.Equal(a[i], b[j]):
			ops = append(ops, opKeep)
			i++
			j++
		case dp[(i+1)*w+j] >= dp[i*w+j+1]:
			ops = append(ops, opDel)
			i++
		default:
			ops = append(ops, opAdd)
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, opDel)
	}
	for ; j < m; j++ {
		ops = append(ops, opAdd)
	}
	return ops
}

func renderHunks(a, b [][]byte, ops []diffOp, offset int) []string {
	var out []string
	ai, bi := 0, 0
	for k := 0; k < len(ops); {
		if ops[k] == opKeep {
			ai++
			bi++
			k++
			continue
		}
		startA, startB := ai, bi
		var lines []string
		for k < len(ops) && ops[k] != opKeep {
			if ops[k] == opDel {
				lines = append(lines, "-"+redactLine(a[ai]))
				ai++
			} else {
				lines = append(lines, "+"+redactLine(b[bi]))
				bi++
			}
			k++
		}
		out = append(out, fmt.Sprintf("@@ -%d,%d +%d,%d @@", offset+startA+1, ai-startA, offset+startB+1, bi-startB))
		out = append(out, lines...)
	}
	return out
}

func redactLine(l []byte) string {
	s, _ := classify.Redact(string(bytes.TrimRight(l, "\r")))
	return clipBytes(s, 400)
}

// clipBytes shortens a line for display without splitting a UTF-8 sequence.
func clipBytes(s string, n int) string {
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && s[cut]&0xC0 == 0x80 {
		cut--
	}
	return s[:cut] + fmt.Sprintf(" [... %d more bytes]", len(s)-cut)
}

func splitLines(b []byte) [][]byte {
	if len(b) == 0 {
		return nil
	}
	lines := bytes.SplitAfter(b, []byte("\n"))
	if len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	for i, l := range lines {
		lines[i] = bytes.TrimSuffix(l, []byte("\n"))
	}
	return lines
}
