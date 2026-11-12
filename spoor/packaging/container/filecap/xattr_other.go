//go:build !linux

package main

import "errors"

// File capabilities are a Linux feature; the tool exists elsewhere only so
// the module builds on every platform.
var errUnsupported = errors.New("file capabilities exist only on Linux")

func setCaps(string, []byte) error   { return errUnsupported }
func getCaps(string) ([]byte, error) { return nil, errUnsupported }
func clearCaps(string) error         { return errUnsupported }
