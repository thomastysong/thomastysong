//go:build unix

package rules

import (
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func readTrustedDir(dir string) (map[string][]byte, error) {
	fd, err := openDirAt(unix.AT_FDCWD, dir)
	if err != nil {
		return nil, fmt.Errorf("rules: open %s: %w", dir, err)
	}
	defer unix.Close(fd)
	if err := checkFD(fd, dir, true); err != nil {
		return nil, err
	}
	files := map[string][]byte{}
	sub, err := openDirAt(fd, "rules")
	switch {
	case err == nil:
		defer unix.Close(sub)
		if err := checkFD(sub, dir+"/rules", true); err != nil {
			return nil, err
		}
		if err := readDirFD(sub, dir+"/rules", "rules/", files, func(n string) bool { return true }); err != nil {
			return nil, err
		}
		if err := readDirFD(fd, dir, "", files, func(n string) bool { return n == "lists.yaml" || n == "suppressions.yaml" }); err != nil {
			return nil, err
		}
	case err == unix.ENOENT:
		if err := readDirFD(fd, dir, "", files, func(n string) bool { return true }); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("rules: open %s/rules: %w", dir, err)
	}
	return files, nil
}

func openDirAt(dirfd int, name string) (int, error) {
	for {
		fd, err := unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_NOFOLLOW|unix.O_CLOEXEC, 0)
		if err == unix.EINTR {
			continue
		}
		if err == unix.ELOOP || err == unix.EMLINK {
			return -1, fmt.Errorf("%s is a symbolic link", name)
		}
		return fd, err
	}
}

// checkFD verifies ownership and mode on an open descriptor.
func checkFD(fd int, name string, wantDir bool) error {
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		return fmt.Errorf("rules: stat %s: %w", name, err)
	}
	typ := uint32(st.Mode) & unix.S_IFMT
	if wantDir && typ != unix.S_IFDIR {
		return fmt.Errorf("%w: %s is not a directory", ErrInsecureDir, name)
	}
	if !wantDir && typ != unix.S_IFREG {
		return fmt.Errorf("%w: %s is not a regular file", ErrInsecureDir, name)
	}
	if uid := int(st.Uid); uid != 0 && uid != os.Geteuid() {
		return fmt.Errorf("%w: %s is owned by uid %d, not by root or the calling user", ErrInsecureDir, name, uid)
	}
	if perm := uint32(st.Mode) & 0o777; perm&0o022 != 0 {
		return fmt.Errorf("%w: %s is writable by group or others (mode %04o)", ErrInsecureDir, name, perm)
	}
	return nil
}

// readDirFD reads the wanted files of an open directory into files.
func readDirFD(dirfd int, dirName, prefix string, files map[string][]byte, want func(string) bool) error {
	dup, err := unix.Dup(dirfd)
	if err != nil {
		return fmt.Errorf("rules: %s: %w", dirName, err)
	}
	f := os.NewFile(uintptr(dup), dirName)
	entries, err := f.ReadDir(maxDirEntries + 1)
	f.Close()
	if err != nil && err != io.EOF {
		return fmt.Errorf("rules: list %s: %w", dirName, err)
	}
	if len(entries) > maxDirEntries {
		return fmt.Errorf("rules: %s has more than %d entries", dirName, maxDirEntries)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	for _, n := range sortedNames(names) {
		if !want(n) {
			continue
		}
		b, err := readFileAt(dirfd, dirName+"/"+n, n)
		if err != nil {
			return err
		}
		files[prefix+n] = b
	}
	return nil
}

func readFileAt(dirfd int, full, name string) ([]byte, error) {
	var fd int
	var err error
	for {
		// O_NONBLOCK: a FIFO planted under a rule file name must not hang
		// the loader; O_NOFOLLOW: a link must not redirect the read.
		fd, err = unix.Openat(dirfd, name, unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC|unix.O_NOCTTY, 0)
		if err != unix.EINTR {
			break
		}
	}
	if err != nil {
		if err == unix.ELOOP || err == unix.EMLINK {
			return nil, fmt.Errorf("%w: %s is a symbolic link", ErrInsecureDir, full)
		}
		return nil, fmt.Errorf("rules: open %s: %w", full, err)
	}
	if err := checkFD(fd, full, false); err != nil {
		unix.Close(fd)
		return nil, err
	}
	_ = unix.SetNonblock(fd, false)
	f := os.NewFile(uintptr(fd), full)
	defer f.Close()
	limit := fileCap(name)
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, fmt.Errorf("rules: read %s: %w", full, err)
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("rules: %s is larger than %d bytes", full, limit)
	}
	return b, nil
}
