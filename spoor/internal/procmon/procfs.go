package procmon

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/thomastysong/spoor/internal/platform"
)

// procfsSource reads a Linux procfs mount directly. It has two modes:
//
//   - viaPlatform (the sensor's own /proc): the cheap identity pass and
//     children lists come from here, full records from platform.ProcessByPID
//     and workload ids from platform.ContainerOf/PodOf;
//   - host-root mode (/proc of another pid namespace mounted somewhere
//     else): everything is read from the mount, including the user names
//     from the host's /etc/passwd.
//
// The type compiles on every OS because it only reads files; production
// uses it on Linux and the tests use it on fixture trees.
type procfsSource struct {
	dir         string
	viaPlatform bool
	passwdPath  string

	bootOnce sync.Once
	boot     int64

	pwMu      sync.Mutex
	pwNames   map[string]string
	pwMod     time.Time
	pwChecked time.Time
}

func newProcfsSource(dir, passwd string) *procfsSource {
	return &procfsSource{dir: dir, passwdPath: passwd}
}

func (s *procfsSource) kind() string {
	if s.viaPlatform {
		return "procfs"
	}
	return "procfs-hostroot"
}

func (s *procfsSource) pidDir(pid int) string { return filepath.Join(s.dir, strconv.Itoa(pid)) }

func (s *procfsSource) list() ([]ident, map[int]*platform.Proc, error) {
	d, err := os.Open(s.dir)
	if err != nil {
		return nil, nil, err
	}
	defer d.Close()
	var ids []ident
	for len(ids) < maxTable {
		names, rerr := d.Readdirnames(1024)
		for _, n := range names {
			pid, ok := parsePIDName(n)
			if !ok {
				continue
			}
			id, err := s.statIdent(pid)
			switch {
			case err == nil:
				ids = append(ids, id)
			case errors.Is(err, fs.ErrPermission):
				// /proc mounted hidepid=1 (noaccess): the pid is listed and
				// everything under it refuses the monitor. It is a live
				// process the monitor may not look at, kernel thread or
				// not (nothing tells them apart from here), and it is
				// counted as such (countReadability).
				ids = append(ids, s.deniedIdent(pid))
			}
		}
		if rerr != nil {
			if !errors.Is(rerr, io.EOF) && len(ids) == 0 {
				return nil, nil, rerr
			}
			break
		}
	}
	return ids, nil, nil
}

// identOf reads /proc/<pid>/stat only. Zombies count as gone: the process
// has exited and only waits for its parent to reap it.
func (s *procfsSource) identOf(pid int) (ident, bool) {
	id, err := s.statIdent(pid)
	return id, err == nil
}

// errGone is statIdent's answer for a zombie or an unparsable stat line.
var errGone = errors.New("procmon: process gone")

// statIdent is identOf with the reason it failed: an error satisfying
// errors.Is(err, fs.ErrPermission) when the process exists and refuses the
// monitor.
func (s *procfsSource) statIdent(pid int) (ident, error) {
	b, err := readCapped(filepath.Join(s.pidDir(pid), "stat"), maxStatBytes)
	if err != nil {
		return ident{}, err
	}
	st, ok := parseStatFields(b)
	if !ok || st.state == 'Z' || st.state == 'X' || st.state == 'x' {
		return ident{}, errGone
	}
	return ident{pid: pid, ppid: st.ppid, key: st.start + 1, comm: st.comm, kthread: st.kthread}, nil
}

// deniedIdent is the identity of a process whose stat refused the monitor:
// only the pid, and the owner the kernel still shows on /proc/<pid> under
// hidepid=1 (the process's account, root for kernel threads).
func (s *procfsSource) deniedIdent(pid int) ident {
	id := ident{pid: pid, denied: true}
	if fi, err := os.Stat(s.pidDir(pid)); err == nil {
		id.uid, _ = platform.OwnerUID(fi)
	}
	return id
}

func (s *procfsSource) read(pid int) (platform.Proc, ident, bool) {
	if !s.viaPlatform {
		return s.readOwn(pid)
	}
	before, ok := s.identOf(pid)
	if !ok {
		return platform.Proc{}, ident{}, false
	}
	p, err := platform.ProcessByPID(pid)
	if err != nil {
		return platform.Proc{}, ident{}, false
	}
	// platform reads every file through one directory handle, so the record
	// is self-consistent; the identity check on both sides makes sure it is
	// the process the caller asked about and not a successor on the same pid.
	after, ok := s.identOf(pid)
	if !ok || after.key != before.key {
		return platform.Proc{}, ident{}, false
	}
	after.ppid = p.PPID
	return p, after, true
}

// readOwn reads one process from a host-root procfs mount. Every file is
// opened relative to one handle on /proc/<pid>, so a pid recycled mid-read
// cannot mix two programs into one record.
func (s *procfsSource) readOwn(pid int) (platform.Proc, ident, bool) {
	root, err := os.OpenRoot(s.pidDir(pid))
	if err != nil {
		return platform.Proc{}, ident{}, false
	}
	defer root.Close()
	stat, err := readRootCapped(root, "stat", maxStatBytes)
	if err != nil {
		return platform.Proc{}, ident{}, false
	}
	st, ok := parseStatFields(stat)
	if !ok || st.state == 'Z' || st.state == 'X' || st.state == 'x' {
		return platform.Proc{}, ident{}, false
	}
	comm, ppid, ticks := st.comm, st.ppid, st.start
	id := ident{pid: pid, ppid: ppid, key: ticks + 1, comm: comm, kthread: st.kthread}
	p := platform.Proc{PID: pid, PPID: ppid, Name: comm, Start: s.startTime(ticks)}
	if b, err := readRootCapped(root, "cmdline", maxCmdlineBytes); err == nil {
		p.Args = splitNUL(b, maxRawArgs)
	}
	// The link text is a path inside the process's own mount namespace.
	if exe, err := root.Readlink("exe"); err == nil {
		p.Exe = trimDeleted(exe)
	}
	if b, err := readRootCapped(root, "status", maxStatusBytes); err == nil {
		if uid, ok := parseStatusUID(b); ok {
			p.UID = uid
			p.User = s.userName(uid)
		}
	}
	p.Name = refineName(comm, p.Args)
	return p, id, true
}

// startTime converts start ticks with the host's boot time. USER_HZ is 100
// on every architecture Go supports (it is part of the Linux ABI).
func (s *procfsSource) startTime(ticks uint64) time.Time {
	s.bootOnce.Do(func() {
		if b, err := readCapped(filepath.Join(s.dir, "stat"), 1<<20); err == nil {
			s.boot, _ = parseBtime(b)
		}
	})
	if s.boot == 0 || ticks > 1<<62 {
		return time.Time{}
	}
	const hz = 100
	t := int64(ticks)
	return time.Unix(s.boot+t/hz, (t%hz)*int64(time.Second)/hz)
}

func (s *procfsSource) userName(uid string) string {
	if s.passwdPath == "" {
		return ""
	}
	s.pwMu.Lock()
	defer s.pwMu.Unlock()
	now := time.Now()
	if s.pwNames == nil || now.Sub(s.pwChecked) > 30*time.Second {
		s.pwChecked = now
		if fi, err := os.Stat(s.passwdPath); err == nil && (s.pwNames == nil || !fi.ModTime().Equal(s.pwMod)) {
			if b, err := readCapped(s.passwdPath, maxPasswdBytes); err == nil {
				s.pwNames, s.pwMod = parsePasswd(b), fi.ModTime()
			}
		}
		if s.pwNames == nil {
			s.pwNames = map[string]string{}
		}
	}
	return s.pwNames[uid]
}

func (s *procfsSource) env(pid int, keep map[string]bool) (map[string]string, error) {
	// Every exec on the host passes through here; a pooled buffer keeps the
	// read from allocating once per process.
	bp := envBufs.Get().(*[]byte)
	defer envBufs.Put(bp)
	b, err := readInto(filepath.Join(s.pidDir(pid), "environ"), bp, maxEnvironBytes+1)
	if err != nil {
		return nil, err
	}
	truncated := len(b) > maxEnvironBytes
	if truncated {
		b = b[:maxEnvironBytes]
	}
	return parseEnvironKeep(b, truncated, keep), nil
}

var envBufs = sync.Pool{New: func() any { b := make([]byte, 0, 32<<10); return &b }}

// readInto reads at most max bytes into the buffer bp points to, growing it
// as needed, and returns the filled part (valid until the buffer is reused).
func readInto(path string, bp *[]byte, max int) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b := (*bp)[:0]
	for len(b) < max {
		if len(b) == cap(b) {
			n := 2 * cap(b)
			if n > max {
				n = max
			}
			nb := make([]byte, len(b), n)
			copy(nb, b)
			b = nb
		}
		n, err := f.Read(b[len(b):cap(b)])
		b = b[:len(b)+n]
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			*bp = b
			return nil, err
		}
		if n == 0 {
			break
		}
	}
	*bp = b
	return b, nil
}

// children lists direct children through /proc/<pid>/task/<tid>/children
// (one file per thread: a child belongs to the thread that forked it). The
// files exist only with CONFIG_PROC_CHILDREN; without them ok is false and
// the caller falls back to a full listing.
func (s *procfsSource) children(pid int) ([]int, bool) {
	task := filepath.Join(s.pidDir(pid), "task")
	d, err := os.Open(task)
	if err != nil {
		// The process is gone: it has no children to report.
		return nil, errors.Is(err, fs.ErrNotExist)
	}
	defer d.Close()
	tids, err := d.Readdirnames(maxThreads)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false
	}
	var kids []int
	for _, t := range tids {
		if _, ok := parsePIDName(t); !ok {
			continue
		}
		b, err := readCapped(filepath.Join(task, t, "children"), maxChildrenBytes)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				if _, serr := os.Stat(filepath.Join(task, t)); serr == nil {
					return nil, false // kernel without CONFIG_PROC_CHILDREN
				}
			}
			continue
		}
		kids = parseChildren(b, kids)
	}
	return kids, true
}

// selfImage compares the file identity (device and inode) of the image the
// process runs with spoor's. Stat follows the magic /proc/<pid>/exe link
// to the file the kernel mapped, in whatever mount namespace the process
// lives, so a path that names another file in this namespace cannot pass
// for it; a replaced or deleted binary keeps its identity while it runs.
// The process's start-time identity is read again afterwards, so a pid
// that was recycled in between does not answer for the process id names.
func (s *procfsSource) selfImage(id ident, _ *platform.Proc, self *selfSet) bool {
	p := filepath.Join(s.pidDir(id.pid), "exe")
	fi, err := os.Stat(p)
	if err != nil || !fi.Mode().IsRegular() {
		return false
	}
	fid := platform.FileID(fi, p)
	if fid == "" || !self.ids[fid] {
		return false
	}
	if id.key != 0 {
		if after, ok := s.identOf(id.pid); !ok || after.key != id.key {
			return false
		}
	}
	return true
}

func (s *procfsSource) cwd(pid int) string {
	c, err := os.Readlink(filepath.Join(s.pidDir(pid), "cwd"))
	if err != nil {
		return ""
	}
	return cleanPath(trimDeleted(c))
}

func (s *procfsSource) workload(pid int) (string, string, string) {
	if s.viaPlatform {
		id, rt := platform.ContainerOf(pid)
		return id, rt, platform.PodOf(pid)
	}
	b, err := readCapped(filepath.Join(s.pidDir(pid), "cgroup"), 64<<10)
	if err != nil {
		return "", "", ""
	}
	w := parseCgroupWorkload(b)
	return w.id, w.runtime, w.pod
}

// readCapped reads at most max bytes. procfs files report size zero, so the
// size cannot be trusted and the read itself must be capped.
func readCapped(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max))
}

func readRootCapped(root *os.Root, name string, max int64) ([]byte, error) {
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, max))
}
