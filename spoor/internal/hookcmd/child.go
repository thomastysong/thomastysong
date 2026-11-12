package hookcmd

import (
	"errors"
	"io"
	"os"
	"runtime"
	"strconv"
	"time"
)

// childResult is what became of one worker process.
type childResult struct {
	stdout   []byte // at most capOut+1 bytes
	complete bool   // stdout was read to EOF
	exited   bool   // the process exited on its own (not killed by us)
	code     int    // exit code when exited normally; -1 otherwise
	state    string // fixed-format description for health records
	timedOut bool
	startErr error
}

// selfExe is the binary the supervisor re-executes. On Linux
// /proc/self/exe names the running image even after a package upgrade
// replaced or removed the file, so the worker is always the same build as
// its supervisor. Nothing found on disk or in the payload is ever executed.
func selfExe(env Env) (string, error) {
	if env.Exe != "" {
		return env.Exe, nil
	}
	if runtime.GOOS == "linux" {
		if _, err := os.Stat("/proc/self/exe"); err == nil {
			return "/proc/self/exe", nil
		}
	}
	return os.Executable()
}

// runChild starts the worker with the payload on stdin, its stdout on a
// pipe and its stderr on the null device, and waits until deadline. It
// uses os.StartProcess directly: the only program ever started is this
// binary, so there is nothing for os/exec's path lookup to do.
func runChild(exe string, argv []string, payload []byte, capOut int, deadline time.Time) (res childResult) {
	res.code = -1
	inR, inW, err := os.Pipe()
	if err != nil {
		res.startErr = err
		return res
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		inR.Close()
		inW.Close()
		res.startErr = err
		return res
	}
	null, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		inR.Close()
		inW.Close()
		outR.Close()
		outW.Close()
		res.startErr = err
		return res
	}
	p, err := os.StartProcess(exe, argv, &os.ProcAttr{Files: []*os.File{inR, outW, null}, Sys: sysProcAttr()})
	// The child holds its own copies; ours must close so EOF and EPIPE
	// reach the right side.
	inR.Close()
	outW.Close()
	null.Close()
	if err != nil {
		inW.Close()
		outR.Close()
		res.startErr = err
		return res
	}

	go func() {
		defer func() { _ = recover() }()
		_, _ = inW.Write(payload) // EPIPE when the worker died early: nothing to do
		inW.Close()
	}()

	type readDone struct {
		b        []byte
		complete bool
	}
	readCh := make(chan readDone, 1)
	go func() {
		var d readDone
		defer func() {
			_ = recover()
			readCh <- d
		}()
		buf := make([]byte, 0, 4096)
		chunk := make([]byte, 4096)
		for {
			n, err := outR.Read(chunk)
			if n > 0 && len(buf) <= capOut {
				buf = append(buf, chunk[:min(n, capOut+1-len(buf))]...)
			}
			if err != nil {
				d.b, d.complete = buf, errors.Is(err, io.EOF)
				return
			}
		}
	}()

	waitCh := make(chan *os.ProcessState, 1)
	go func() {
		defer func() { _ = recover() }()
		st, _ := p.Wait()
		waitCh <- st
	}()

	timer := time.NewTimer(max0(time.Until(deadline)))
	defer timer.Stop()
	var st *os.ProcessState
	select {
	case st = <-waitCh:
		res.exited = true
	case <-timer.C:
		res.timedOut = true
		_ = p.Kill()
		// A process in uninterruptible sleep may not die at once; the
		// agent is not kept waiting for it.
		select {
		case st = <-waitCh:
		case <-time.After(250 * time.Millisecond):
		}
	}
	if st != nil {
		res.state = st.String()
		if res.exited {
			res.code = st.ExitCode()
		}
	} else {
		res.state = "not reaped"
	}

	// The worker's exit closes its end of the pipe, so EOF follows at once
	// unless something inherited the descriptor; do not wait long for that.
	select {
	case d := <-readCh:
		res.stdout, res.complete = d.b, d.complete
	case <-time.After(100 * time.Millisecond):
		outR.Close()
		res.stdout, res.complete = nil, false
	}
	return res
}

// workerArgs is the worker's command line. The supervisor passes its own
// parent pid (the agent, or the shell the agent started) so the worker
// records the right caller, plus its start time and hard deadline, asks
// for a framed reply, and says what it knows about stdin that the payload
// itself cannot: that the agent had not closed it in time, and the size
// and digest of what was drained past the cap.
func workerArgs(o opts, cfgPath string, ppid int, t0, deadline time.Time, in inputResult) []string {
	a := []string{"spoor", "hook", "--worker", "--framed", "--config", cfgPath,
		"--ppid", strconv.Itoa(ppid),
		"--t0", strconv.FormatInt(t0.UnixNano(), 10),
		"--deadline", strconv.FormatInt(deadline.UnixNano(), 10)}
	if in.timedOut {
		a = append(a, "--stdin-cut")
	}
	if in.sum != "" && in.total > int64(len(in.b)) {
		a = append(a, "--stdin-bytes", strconv.FormatInt(in.total, 10), "--stdin-sha256", in.sum)
	}
	if o.agent != "" {
		a = append(a, "--agent", o.agent)
	}
	if o.event != "" {
		a = append(a, "--event", o.event)
	}
	return a
}
