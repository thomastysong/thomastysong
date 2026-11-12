//go:build !linux

package procmon

import (
	"errors"
	"time"
)

// openCNProc: the process connector is a Linux interface.
func openCNProc() (cnConn, error) {
	return nil, errors.New("procmon: the process connector exists on Linux only")
}

func monotonicToWall(uint64) time.Time { return time.Now() }
