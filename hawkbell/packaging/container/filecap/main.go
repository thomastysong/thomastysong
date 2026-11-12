package main

import (
	"errors"
	"fmt"
	"io"
	"os"
)

const usage = `usage:
  filecap set    <caps>=<flags> FILE...   write the capability record (like setcap)
  filecap verify <caps>=<flags> FILE...   exit 1 unless every FILE carries exactly that record
  filecap get    FILE...                  print FILE and its capabilities (like getcap)
  filecap clear  FILE...                  remove the record (like setcap -r)
`

func main() { os.Exit(run(os.Args[1:], os.Stdout, os.Stderr)) }

func run(args []string, stdout, stderr io.Writer) int {
	if len(args) < 2 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	cmd, rest := args[0], args[1:]
	switch cmd {
	case "set", "verify":
		if len(rest) < 2 {
			fmt.Fprint(stderr, usage)
			return 2
		}
		want, err := Parse(rest[0])
		if err != nil {
			fmt.Fprintln(stderr, "filecap:", err)
			return 2
		}
		code := 0
		for _, f := range rest[1:] {
			if cmd == "set" {
				if err := setCaps(f, want.Encode()); err != nil {
					fmt.Fprintf(stderr, "filecap: %s: %v\n", f, err)
					code = 1
				}
				continue
			}
			got, err := readCaps(f)
			if err != nil {
				fmt.Fprintf(stderr, "filecap: %s: %v\n", f, err)
				code = 1
				continue
			}
			if !got.Equal(want) {
				fmt.Fprintf(stderr, "filecap: %s carries %q, want %q\n", f, got.String(), want.String())
				code = 1
				continue
			}
			fmt.Fprintf(stdout, "%s %s\n", f, got)
		}
		return code
	case "get":
		code := 0
		for _, f := range rest {
			got, err := readCaps(f)
			switch {
			case errors.Is(err, errNoCaps):
				// getcap prints nothing for a file without capabilities.
			case err != nil:
				fmt.Fprintf(stderr, "filecap: %s: %v\n", f, err)
				code = 1
			default:
				fmt.Fprintf(stdout, "%s %s\n", f, got)
			}
		}
		return code
	case "clear":
		code := 0
		for _, f := range rest {
			if err := clearCaps(f); err != nil && !errors.Is(err, errNoCaps) {
				fmt.Fprintf(stderr, "filecap: %s: %v\n", f, err)
				code = 1
			}
		}
		return code
	default:
		fmt.Fprint(stderr, usage)
		return 2
	}
}

// errNoCaps: the file has no security.capability attribute.
var errNoCaps = errors.New("no file capabilities")

func readCaps(path string) (Set, error) {
	b, err := getCaps(path)
	if err != nil {
		return Set{}, err
	}
	return Decode(b)
}
