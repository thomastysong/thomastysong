//go:build linux

package platform

import (
	"os"
	"testing"
)

func BenchmarkProcesses(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := Processes(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkProcessByPID(b *testing.B) {
	pid := os.Getpid()
	for i := 0; i < b.N; i++ {
		if _, err := ProcessByPID(pid); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkContainerOf(b *testing.B) {
	pid := os.Getpid()
	for i := 0; i < b.N; i++ {
		ContainerOf(pid)
	}
}

func BenchmarkHostInfo(b *testing.B) {
	for i := 0; i < b.N; i++ {
		HostInfo()
	}
}
