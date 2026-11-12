//go:build !windows

package discovery

import "syscall"

func mkfifo(p string) error { return syscall.Mkfifo(p, 0o644) }
