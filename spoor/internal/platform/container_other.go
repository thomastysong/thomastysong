//go:build !linux

package platform

// ContainerOf reports nothing outside Linux: macOS and Windows run Linux
// containers inside a virtual machine whose processes the host cannot see.
func ContainerOf(pid int) (id, runtime string) { return "", "" }

// PodOf reports nothing outside Linux.
func PodOf(pid int) (podUID string) { return "" }
