//go:build windows

package discovery

import "errors"

func mkfifo(p string) error { return errors.New("no FIFOs on Windows") }
