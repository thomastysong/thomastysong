//go:build !unix

package sink

import "errors"

func mkfifo(string) error { return errors.ErrUnsupported }
