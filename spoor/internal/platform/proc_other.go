//go:build !linux && !darwin && !windows

package platform

import "time"

// Processes is not implemented for this OS.
func Processes() ([]Proc, error) { return nil, ErrUnsupported }

// ProcessByPID is not implemented for this OS.
func ProcessByPID(pid int) (Proc, error) { return Proc{}, ErrUnsupported }

// ProcEnv is not implemented for this OS.
func ProcEnv(pid int) (map[string]string, error) { return nil, ErrUnsupported }

// ProcCWD is not implemented for this OS.
func ProcCWD(pid int) (string, error) { return "", ErrUnsupported }

// ProcImagePath is not implemented for this OS.
func ProcImagePath(pid int, start time.Time) (string, error) { return "", ErrUnsupported }
