//go:build windows

package platform

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
	"unsafe"

	"golang.org/x/sys/windows"
)

// UNVERIFIED: this file was compiled and vetted for windows/amd64 and
// windows/arm64 but not executed in the build environment. The environment
// block parser it relies on is unit-tested with fixtures on every platform.

const ptrSize = unsafe.Sizeof(uintptr(0))

// processBasicInformation is PROCESS_BASIC_INFORMATION with the PEB address
// as an integer. Addresses in ANOTHER process must never sit in Go pointer
// types: the garbage collector would treat them as pointers into our heap and
// can abort the program when one happens to land in an unused span.
type processBasicInformation struct {
	ExitStatus                   uint32
	PebBaseAddress               uintptr
	AffinityMask                 uintptr
	BasePriority                 int32
	UniqueProcessID              uintptr
	InheritedFromUniqueProcessID uintptr
}

// Field offsets inside the target's PEB and process parameters, taken from
// the x/sys definitions for the architecture being built. Remote memory is
// read as bytes and decoded with these, for the reason given above.
var (
	offPEBParams      = unsafe.Offsetof(windows.PEB{}.ProcessParameters)
	offParamsCurDir   = unsafe.Offsetof(windows.RTL_USER_PROCESS_PARAMETERS{}.CurrentDirectory)
	offParamsCmdLine  = unsafe.Offsetof(windows.RTL_USER_PROCESS_PARAMETERS{}.CommandLine)
	offParamsEnv      = unsafe.Offsetof(windows.RTL_USER_PROCESS_PARAMETERS{}.Environment)
	offParamsEnvSize  = unsafe.Offsetof(windows.RTL_USER_PROCESS_PARAMETERS{}.EnvironmentSize)
	offUnicodeBuffer  = unsafe.Offsetof(windows.NTUnicodeString{}.Buffer)
	sizeUnicodeString = unsafe.Sizeof(windows.NTUnicodeString{})
)

var debugPrivilegeOnce sync.Once

// enableDebugPrivilege turns on SeDebugPrivilege when the token holds it
// (administrators and LocalSystem). Without it an elevated sensor still
// cannot open processes of other users, which is the whole point of running
// elevated. It is a no-op for ordinary users.
func enableDebugPrivilege() {
	debugPrivilegeOnce.Do(func() {
		if !IsPrivileged() {
			return
		}
		var tok windows.Token
		if err := windows.OpenProcessToken(windows.CurrentProcess(), windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
			return
		}
		defer tok.Close()
		name, err := windows.UTF16PtrFromString("SeDebugPrivilege")
		if err != nil {
			return
		}
		var luid windows.LUID
		if err := windows.LookupPrivilegeValue(nil, name, &luid); err != nil {
			return
		}
		tp := windows.Tokenprivileges{PrivilegeCount: 1}
		tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
		_ = windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil)
	})
}

// Processes lists every process from a Toolhelp32 snapshot. Image path,
// start time, owner and command line are added for each process the caller
// may open; system and protected processes keep only pid, parent and name.
func Processes() (procs []Proc, err error) {
	defer guard(&err)
	enableDebugPrivilege()
	names := newSIDNames()
	err = eachSnapshotEntry(func(pe *windows.ProcessEntry32) bool {
		p := procFromEntry(pe)
		fillProc(&p, names)
		procs = append(procs, p)
		return len(procs) < maxProcs
	})
	if err != nil {
		return nil, err
	}
	sort.Slice(procs, func(i, j int) bool { return procs[i].PID < procs[j].PID })
	return procs, nil
}

// ProcessByPID returns one process, or an error wrapping os.ErrNotExist when
// it is gone.
func ProcessByPID(pid int) (p Proc, err error) {
	defer guard(&err)
	if pid < 0 {
		return Proc{}, fmt.Errorf("platform: invalid pid %d", pid)
	}
	enableDebugPrivilege()
	found := false
	err = eachSnapshotEntry(func(pe *windows.ProcessEntry32) bool {
		if int(pe.ProcessID) != pid {
			return true
		}
		p, found = procFromEntry(pe), true
		return false
	})
	if err != nil {
		return Proc{}, err
	}
	if !found {
		return Proc{}, fmt.Errorf("platform: pid %d: %w", pid, os.ErrNotExist)
	}
	fillProc(&p, newSIDNames())
	return p, nil
}

func eachSnapshotEntry(fn func(*windows.ProcessEntry32) bool) error {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPPROCESS, 0)
	if err != nil {
		return fmt.Errorf("platform: process snapshot: %w", err)
	}
	defer windows.CloseHandle(snap)
	var pe windows.ProcessEntry32
	pe.Size = uint32(unsafe.Sizeof(pe))
	if err := windows.Process32First(snap, &pe); err != nil {
		return fmt.Errorf("platform: process snapshot: %w", err)
	}
	for {
		if !fn(&pe) {
			return nil
		}
		// ERROR_NO_MORE_FILES ends the walk; any other error ends it too,
		// with whatever was collected.
		if err := windows.Process32Next(snap, &pe); err != nil {
			return nil
		}
	}
}

func procFromEntry(pe *windows.ProcessEntry32) Proc {
	return Proc{
		PID:  int(pe.ProcessID),
		PPID: int(pe.ParentProcessID),
		Name: windows.UTF16ToString(pe.ExeFile[:]),
	}
}

// fillProc adds what needs a process handle. Each lookup fails on its own.
func fillProc(p *Proc, names *sidNames) {
	if p.PID == 0 {
		return // the idle pseudo-process cannot be opened
	}
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(p.PID))
	if err != nil {
		return
	}
	defer windows.CloseHandle(h)
	p.Exe = imagePath(h)
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err == nil {
		p.Start = time.Unix(0, created.Nanoseconds())
	}
	p.UID, p.User = tokenOwner(h, names)
	if cl, err := queryCommandLine(h); err == nil {
		p.Args = splitCommandLine(cl)
	} else if cl, err := pebCommandLine(p.PID); err == nil {
		p.Args = splitCommandLine(cl)
	}
}

func imagePath(h windows.Handle) string {
	for size := uint32(windows.MAX_PATH); size <= 1<<15; size *= 4 {
		buf := make([]uint16, size)
		n := size
		err := windows.QueryFullProcessImageName(h, 0, &buf[0], &n)
		if err == nil {
			return windows.UTF16ToString(buf[:n])
		}
		if !errors.Is(err, windows.ERROR_INSUFFICIENT_BUFFER) {
			return ""
		}
	}
	return ""
}

// sidNames memoizes SID-to-account lookups for one scan.
type sidNames struct{ memo map[string]string }

func newSIDNames() *sidNames { return &sidNames{memo: make(map[string]string)} }

func tokenOwner(h windows.Handle, names *sidNames) (sid, name string) {
	var tok windows.Token
	if err := windows.OpenProcessToken(h, windows.TOKEN_QUERY, &tok); err != nil {
		return "", ""
	}
	defer tok.Close()
	tu, err := tok.GetTokenUser()
	if err != nil || tu.User.Sid == nil {
		return "", ""
	}
	sid = tu.User.Sid.String()
	if cached, ok := names.memo[sid]; ok {
		return sid, cached
	}
	if account, _, _, err := tu.User.Sid.LookupAccount(""); err == nil {
		name = account
	}
	names.memo[sid] = name
	return sid, name
}

// queryCommandLine asks the kernel for the command line
// (ProcessCommandLineInformation, Windows 8.1+). It needs only
// PROCESS_QUERY_LIMITED_INFORMATION, so it also works for processes whose
// memory the caller may not read.
func queryCommandLine(h windows.Handle) (string, error) {
	size := uint32(2048)
	for attempt := 0; attempt < 4; attempt++ {
		buf := make([]byte, size)
		var ret uint32
		err := windows.NtQueryInformationProcess(h, windows.ProcessCommandLineInformation, unsafe.Pointer(&buf[0]), size, &ret)
		if err == nil {
			return unicodeStringInBuffer(buf)
		}
		tooSmall := err == windows.STATUS_INFO_LENGTH_MISMATCH || err == windows.STATUS_BUFFER_TOO_SMALL || err == windows.STATUS_BUFFER_OVERFLOW
		if !tooSmall || ret <= size || ret > maxCmdlineBytes {
			return "", err
		}
		size = ret
	}
	return "", errors.New("platform: command line kept growing")
}

// unicodeStringInBuffer decodes a UNICODE_STRING whose characters the kernel
// placed in the same buffer. The embedded pointer is only compared, never
// dereferenced, so a surprising value cannot make us read outside buf.
func unicodeStringInBuffer(buf []byte) (string, error) {
	hdr := int(sizeUnicodeString)
	if len(buf) < hdr {
		return "", errors.New("platform: short UNICODE_STRING")
	}
	length := int(binary.LittleEndian.Uint16(buf[0:2])) &^ 1
	if length == 0 {
		return "", nil
	}
	off := hdr
	base := uintptr(unsafe.Pointer(&buf[0]))
	if ptr := readPtr(buf[offUnicodeBuffer:]); ptr >= base+uintptr(hdr) && ptr < base+uintptr(len(buf)) {
		off = int(ptr - base)
	}
	if off+length > len(buf) {
		return "", errors.New("platform: UNICODE_STRING overruns its buffer")
	}
	return string(utf16.Decode(bytesToUTF16(buf[off : off+length]))), nil
}

// splitCommandLine applies the system's own argument rules
// (CommandLineToArgvW). Windows passes one string; how it splits is decided
// by the program, so this is the conventional reading, not a certainty.
func splitCommandLine(cl string) []string {
	if cl == "" {
		return nil
	}
	args, err := windows.DecomposeCommandLine(cl)
	if err != nil || len(args) == 0 {
		return []string{cl}
	}
	if len(args) > maxArgs {
		args = args[:maxArgs]
	}
	return args
}

func readPtr(b []byte) uintptr {
	if ptrSize == 8 {
		return uintptr(binary.LittleEndian.Uint64(b))
	}
	return uintptr(binary.LittleEndian.Uint32(b))
}

// readRemote copies size bytes at addr from the target process.
func readRemote(h windows.Handle, addr uintptr, size int) ([]byte, error) {
	if addr == 0 || size <= 0 {
		return nil, errors.New("platform: nothing to read in target process")
	}
	buf := make([]byte, size)
	var n uintptr
	err := windows.ReadProcessMemory(h, addr, &buf[0], uintptr(size), &n)
	if err != nil {
		// The range crossed into unmapped memory; keep what was copied.
		if errors.Is(err, windows.ERROR_PARTIAL_COPY) && n > 0 && n <= uintptr(size) {
			return buf[:n], nil
		}
		return nil, err
	}
	if n < uintptr(size) {
		buf = buf[:n]
	}
	return buf, nil
}

// openForRead opens a process for reading its PEB.
func openForRead(pid int) (windows.Handle, error) {
	if pid <= 0 {
		return 0, fmt.Errorf("platform: invalid pid %d", pid)
	}
	if ptrSize != 8 {
		// A 32-bit sensor cannot read a 64-bit target's PEB.
		return 0, ErrUnsupported
	}
	enableDebugPrivilege()
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.PROCESS_VM_READ, false, uint32(pid))
	if err != nil {
		if errors.Is(err, windows.ERROR_INVALID_PARAMETER) {
			return 0, fmt.Errorf("platform: pid %d: %w", pid, os.ErrNotExist)
		}
		return 0, fmt.Errorf("platform: open pid %d: %w", pid, err)
	}
	return h, nil
}

// readProcessParameters returns the leading part of the target's
// RTL_USER_PROCESS_PARAMETERS (through EnvironmentSize), found via the
// native PEB. A 32-bit (WOW64) target also has a native PEB whose parameters
// carry the same strings, so one code path serves both.
func readProcessParameters(h windows.Handle) ([]byte, error) {
	var pbi processBasicInformation
	var ret uint32
	if err := windows.NtQueryInformationProcess(h, windows.ProcessBasicInformation, unsafe.Pointer(&pbi), uint32(unsafe.Sizeof(pbi)), &ret); err != nil {
		return nil, err
	}
	need := int(offPEBParams + ptrSize)
	peb, err := readRemote(h, pbi.PebBaseAddress, need)
	if err != nil {
		return nil, err
	}
	if len(peb) < need {
		return nil, errors.New("platform: short PEB read")
	}
	need = int(offParamsEnvSize + ptrSize)
	params, err := readRemote(h, readPtr(peb[offPEBParams:]), need)
	if err != nil {
		return nil, err
	}
	if len(params) < need {
		return nil, errors.New("platform: short process parameters read")
	}
	return params, nil
}

// remoteUnicodeString reads the UNICODE_STRING stored at off in params.
func remoteUnicodeString(h windows.Handle, params []byte, off uintptr, max int) (string, error) {
	length := int(binary.LittleEndian.Uint16(params[off:])) &^ 1
	if length == 0 {
		return "", nil
	}
	if length > max {
		length = max &^ 1
	}
	data, err := readRemote(h, readPtr(params[off+offUnicodeBuffer:]), length)
	if err != nil {
		return "", err
	}
	return string(utf16.Decode(bytesToUTF16(data))), nil
}

// pebCommandLine is the fallback when the kernel query is refused.
func pebCommandLine(pid int) (string, error) {
	h, err := openForRead(pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	params, err := readProcessParameters(h)
	if err != nil {
		return "", err
	}
	return remoteUnicodeString(h, params, offParamsCmdLine, maxCmdlineBytes)
}

// ProcEnv returns the environment block the process currently holds in its
// PEB. It needs PROCESS_VM_READ on the target: the caller's own processes, or
// any unprotected process when elevated. Variable names keep the case they
// have in the block. Access failures satisfy errors.Is(err, os.ErrPermission).
func ProcEnv(pid int) (env map[string]string, err error) {
	defer guard(&err)
	h, err := openForRead(pid)
	if err != nil {
		return nil, err
	}
	defer windows.CloseHandle(h)
	params, err := readProcessParameters(h)
	if err != nil {
		return nil, fmt.Errorf("platform: pid %d: %w", pid, err)
	}
	addr := readPtr(params[offParamsEnv:])
	if addr == 0 {
		return map[string]string{}, nil
	}
	size := int(readPtr(params[offParamsEnvSize:]))
	if size <= 0 || size > maxEnvBytes {
		// The size field is the target's own word for it; never trust it
		// past the cap. The parser stops at the terminating empty string.
		size = maxEnvBytes
	}
	raw, err := readRemote(h, addr, size)
	if err != nil {
		return nil, fmt.Errorf("platform: pid %d: %w", pid, err)
	}
	return parseEnvBlock16(bytesToUTF16(raw)), nil
}

// ProcCWD returns the current directory recorded in the process's PEB, with
// the same access requirements as ProcEnv.
func ProcCWD(pid int) (cwd string, err error) {
	defer guard(&err)
	h, err := openForRead(pid)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(h)
	params, err := readProcessParameters(h)
	if err != nil {
		return "", fmt.Errorf("platform: pid %d: %w", pid, err)
	}
	cwd, err = remoteUnicodeString(h, params, offParamsCurDir, 1<<16)
	if err != nil {
		return "", fmt.Errorf("platform: pid %d: %w", pid, err)
	}
	if cwd == "" {
		return "", fmt.Errorf("platform: pid %d: no current directory", pid)
	}
	// The PEB stores "C:\dir\"; keep the separator only for a drive root.
	if trimmed := strings.TrimRight(cwd, `\`); len(trimmed) > 2 || !strings.HasSuffix(trimmed, ":") {
		if trimmed != "" {
			cwd = trimmed
		}
	}
	return cwd, nil
}
