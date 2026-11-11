//go:build !linux && !darwin && !windows

package platform

func platformHostID() (id, src string) { return "", HostIDSourceNone }
