//go:build linux

package main

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

// regular refuses anything but a regular file: the attribute on a symlink
// target would be set through the link, which is never what a build wants.
func regular(path string) error {
	fi, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !fi.Mode().IsRegular() {
		return fmt.Errorf("not a regular file")
	}
	return nil
}

// setCaps needs CAP_SETFCAP, which a Docker or BuildKit RUN step has.
func setCaps(path string, v []byte) error {
	if err := regular(path); err != nil {
		return err
	}
	return syscall.Setxattr(path, xattrName, v, 0)
}

func getCaps(path string) ([]byte, error) {
	if err := regular(path); err != nil {
		return nil, err
	}
	buf := make([]byte, 64)
	n, err := syscall.Getxattr(path, xattrName, buf)
	if errors.Is(err, syscall.ENODATA) {
		return nil, errNoCaps
	}
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func clearCaps(path string) error {
	if err := regular(path); err != nil {
		return err
	}
	err := syscall.Removexattr(path, xattrName)
	if errors.Is(err, syscall.ENODATA) {
		return errNoCaps
	}
	return err
}
