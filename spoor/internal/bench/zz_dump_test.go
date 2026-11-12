package bench

import (
	"fmt"
	"testing"

	"github.com/thomastysong/spoor/internal/features"
)

func TestZZDumpRegistry(t *testing.T) {
	for _, fi := range features.Registry() {
		fmt.Printf("%-40s %-9s %-8s %v\n", fi.Name, fi.Type, fi.Origin, fi.Vocab)
	}
}
