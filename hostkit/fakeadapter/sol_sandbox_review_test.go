// SPDX-License-Identifier: MIT

package fakeadapter

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unsafe"

	"github.com/lmctl-ai/lmcloud/hostkit"
)

// The denial filter exists only in a disposable test subprocess and its children.
func TestSolR3SeccompUnavailableFailsClosed(t *testing.T) {
	if os.Getenv("SOL_R3_DENY_SECCOMP") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestSolR3SeccompUnavailableFailsClosed$", "-test.v", "-test.timeout=30s")
		cmd.Env = append(os.Environ(), "SOL_R3_DENY_SECCOMP=1")
		out, e := cmd.CombinedOutput()
		t.Logf("helper: %s", out)
		if e != nil {
			t.Fatal(e)
		}
		return
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var nr uint32
	switch runtime.GOARCH {
	case "amd64":
		nr = 317
	case "arm64":
		nr = 277
	default:
		t.Skip("probe supports native Linux amd64/arm64")
	}
	fs := []syscall.SockFilter{
		{Code: 0x20, K: 0},
		{Code: 0x15, Jf: 1, K: nr},
		{Code: 0x06, K: 0x50000 | uint32(syscall.EPERM)},
		{Code: 0x06, K: 0x7fff0000},
	}
	prog := syscall.SockFprog{Len: uint16(len(fs)), Filter: &fs[0]}
	if _, _, e := syscall.Syscall6(syscall.SYS_PRCTL, 38, 1, 0, 0, 0, 0); e != 0 {
		t.Fatal(e)
	}
	if _, _, e := syscall.Syscall6(syscall.SYS_PRCTL, 22, 2, uintptr(unsafe.Pointer(&prog)), 0, 0, 0); e != 0 {
		t.Fatal(e)
	}
	if _, _, e := syscall.Syscall(uintptr(nr), 99999, 0, 0); e != syscall.EPERM {
		t.Fatal("denial injection inactive", e)
	}
	f := New(Options{})
	ce := f.ensureSandboxReady()
	if ce == nil || ce.Code != hostkit.Internal {
		t.Fatalf("required seccomp listener did not fail closed: %+v", ce)
	}
	t.Logf("CONTROL_UNAVAILABLE_REFUSED: %+v", ce)
}

func solR4Mount(t *testing.T) *scratchFuseFS {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "quota")
	if e := os.Mkdir(dir, 0o700); e != nil {
		t.Fatal(e)
	}
	fs, e := mountScratchFuseFS(dir, 16*1024*1024, 4096)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(fs.Close)
	return fs
}

func TestSolR4FuseTruncateRetainsUnchargedMemory(t *testing.T) {
	fs := solR4Mount(t)
	chunk := bytes.Repeat([]byte{'x'}, 4*1024*1024)
	for i := 0; i < 6; i++ {
		f, e := os.Create(filepath.Join(fs.mountDir, fmt.Sprintf("file%d", i)))
		if e != nil {
			t.Fatal(e)
		}
		if _, e = f.Write(chunk); e != nil {
			f.Close()
			t.Fatal(e)
		}
		if e = f.Truncate(0); e != nil {
			f.Close()
			t.Fatal(e)
		}
		f.Close()
	}
	fs.mu.Lock()
	var logical, retained int
	for _, n := range fs.inodes {
		logical += len(n.data)
		retained += cap(n.data)
	}
	fs.mu.Unlock()
	t.Logf("logical_bytes=%d retained_backing_bytes=%d limit=%d", logical, retained, fs.maxBytes)
	if int64(retained) > fs.maxBytes || retained != logical {
		t.Fatalf("truncation leaves host FUSE daemon retaining uncharged memory: logical=%d retained=%d limit=%d", logical, retained, fs.maxBytes)
	}
}

func TestSolR4FuseRepeatedGrowShrinkManyInodes(t *testing.T) {
	fs := solR4Mount(t)
	bigChunk := bytes.Repeat([]byte{'g'}, 1024*1024)
	const inodeCount = 64
	for cycle := 0; cycle < 3; cycle++ {
		for i := 0; i < inodeCount; i++ {
			p := filepath.Join(fs.mountDir, fmt.Sprintf("node-%d", i))
			f, err := os.OpenFile(p, os.O_CREATE|os.O_RDWR, 0o600)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := f.WriteAt(bigChunk, 0); err != nil {
				f.Close()
				t.Fatal(err)
			}
			keep := int64((i % 8) * 512)
			if err := f.Truncate(keep); err != nil {
				f.Close()
				t.Fatal(err)
			}
			if err := f.Close(); err != nil {
				t.Fatal(err)
			}
		}
	}
	fs.mu.Lock()
	var logical, retained int
	for _, n := range fs.inodes {
		logical += len(n.data)
		retained += cap(n.data)
	}
	fs.mu.Unlock()
	expected := 0
	for i := 0; i < inodeCount; i++ {
		expected += (i % 8) * 512
	}
	if logical != expected || retained != expected || fs.UsedBytes() != int64(expected) {
		t.Fatalf("unexpected memory after repeated grow/shrink: logical=%d retained=%d used=%d expected=%d", logical, retained, fs.UsedBytes(), expected)
	}
}

func TestSolR4FuseRenameLinkQuota(t *testing.T) {
	fs := solR4Mount(t)
	a, e := os.Create(filepath.Join(fs.mountDir, "a"))
	if e != nil {
		t.Fatal(e)
	}
	defer a.Close()
	if e = a.Truncate(8 * 1024 * 1024); e != nil {
		t.Fatal(e)
	}
	if e = os.Link(a.Name(), filepath.Join(fs.mountDir, "alias")); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(filepath.Join(fs.mountDir, "alias"), filepath.Join(fs.mountDir, "renamed")); e != nil {
		t.Fatal(e)
	}
	_ = os.Remove(a.Name())
	b, e := os.Create(filepath.Join(fs.mountDir, "b"))
	if e != nil {
		t.Fatal(e)
	}
	defer b.Close()
	if e = b.Truncate(8 * 1024 * 1024); e != nil {
		t.Fatal(e)
	}
	if e = os.Rename(filepath.Join(fs.mountDir, "renamed"), b.Name()); e != nil {
		t.Fatal(e)
	}
	if used := fs.UsedBytes(); used != 16*1024*1024 {
		t.Fatal("link/rename accounting", used)
	}
	e = os.WriteFile(filepath.Join(fs.mountDir, "extra"), []byte("x"), 0o600)
	if !errors.Is(e, syscall.ENOSPC) {
		t.Fatal("open replaced inode not charged", e)
	}
	b.Close()
	if used := fs.UsedBytes(); used != 8*1024*1024 {
		t.Fatal("replaced inode not reclaimed", used)
	}
}

func TestSolR4FuseInodeQuota(t *testing.T) {
	fs := solR4Mount(t)
	made := 0
	for i := 0; i < 4100; i++ {
		e := os.WriteFile(filepath.Join(fs.mountDir, fmt.Sprintf("i%d", i)), nil, 0o600)
		if e != nil {
			if !errors.Is(e, syscall.ENOSPC) {
				t.Fatal(e)
			}
			break
		}
		made++
	}
	t.Logf("created=%d total inode limit=%d", made, fs.maxInodes)
	if made != 4095 {
		t.Fatal("inode quota mismatch", made)
	}
	_ = os.Remove(filepath.Join(fs.mountDir, "i0"))
	if e := os.WriteFile(filepath.Join(fs.mountDir, "reclaimed"), nil, 0o600); e != nil {
		t.Fatal("deleted inode not reclaimed", e)
	}
}

func TestSolR4NoMountControlFailsClosed(t *testing.T) {
	if os.Getenv("SOL_R4_DENY_MOUNT") != "1" {
		cmd := exec.Command(os.Args[0], "-test.run=^TestSolR4NoMountControlFailsClosed$", "-test.v", "-test.timeout=30s")
		cmd.Env = append(os.Environ(), "SOL_R4_DENY_MOUNT=1")
		out, e := cmd.CombinedOutput()
		t.Logf("helper: %s", out)
		if e != nil {
			t.Fatal(e)
		}
		return
	}
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	var nr uint32
	switch runtime.GOARCH {
	case "amd64":
		nr = 165
	case "arm64":
		nr = 40
	default:
		t.Skip("unsupported probe architecture")
	}
	filters := []syscall.SockFilter{
		{Code: 0x20, K: 0},
		{Code: 0x15, Jf: 1, K: nr},
		{Code: 0x06, K: 0x50000 | uint32(syscall.EPERM)},
		{Code: 0x06, K: 0x7fff0000},
	}
	prog := syscall.SockFprog{Len: uint16(len(filters)), Filter: &filters[0]}
	if _, _, e := syscall.Syscall6(syscall.SYS_PRCTL, 38, 1, 0, 0, 0, 0); e != 0 {
		t.Fatal(e)
	}
	if _, _, e := syscall.Syscall6(syscall.SYS_PRCTL, 22, 2, uintptr(unsafe.Pointer(&prog)), 0, 0, 0); e != 0 {
		t.Fatal(e)
	}
	if _, _, e := syscall.Syscall6(uintptr(nr), 0, 0, 0, 0, 0, 0); e != syscall.EPERM {
		t.Fatal("denial injection inactive", e)
	}
	ce := New(Options{}).ensureSandboxReady()
	t.Logf("MOUNT_CONTROL_UNAVAILABLE: %+v", ce)
	if ce == nil || ce.Code != hostkit.Internal {
		t.Fatal("no hard scratch backing must fail closed", ce)
	}
}

func TestSolR4DevFuseMissingFailsClosed(t *testing.T) {
	if os.Getenv("SOL_R4_NO_DEV_FUSE") == "1" {
		ce := New(Options{}).ensureSandboxReady()
		t.Logf("NO_DEV_FUSE: %+v", ce)
		if ce == nil || ce.Code != hostkit.Internal {
			t.Fatal("missing FUSE and unavailable tmpfs must refuse execution", ce)
		}
		return
	}
	tracer, e := exec.LookPath("strace")
	if e != nil {
		t.Skip("strace unavailable")
	}
	trace := filepath.Join(t.TempDir(), "missing-fuse.log")
	cmd := exec.Command(tracer, "-f", "-P", "/dev/fuse", "-e", "trace=openat", "-e", "inject=openat:error=ENOENT", "-o", trace, os.Args[0], "-test.run=^TestSolR4DevFuseMissingFailsClosed$", "-test.v", "-test.timeout=45s")
	cmd.Env = append(os.Environ(), "SOL_R4_NO_DEV_FUSE=1")
	out, e := cmd.CombinedOutput()
	t.Logf("helper: %s", out)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := os.ReadFile(trace)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(string(raw), "INJECTED") {
		t.Fatal("/dev/fuse ENOENT injection did not fire", string(raw))
	}
	t.Logf("device injection trace: %s", raw)
}

func TestSolR4FuseKillCleanup(t *testing.T) {
	if os.Getenv("SOL_R4_FUSE_HELPER") == "1" {
		fs, e := mountScratchFuseFS(os.Getenv("SOL_R4_FUSE_PATH"), 16*1024*1024, 4096)
		if e != nil {
			t.Fatal(e)
		}
		_ = fs
		fmt.Println("SOL_R4_READY")
		time.Sleep(time.Minute)
		return
	}
	dir := filepath.Join(t.TempDir(), "killed")
	if e := os.Mkdir(dir, 0o700); e != nil {
		t.Fatal(e)
	}
	fm, e := resolveFusermountBin()
	if e != nil {
		t.Fatal(e)
	}
	defer exec.Command(fm, "-u", "-z", "--", dir).Run()
	cmd := exec.Command(os.Args[0], "-test.run=^TestSolR4FuseKillCleanup$", "-test.timeout=75s")
	cmd.Env = append(os.Environ(), "SOL_R4_FUSE_HELPER=1", "SOL_R4_FUSE_PATH="+dir)
	pipe, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	cmd.Stderr = cmd.Stdout
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	ready := make(chan bool, 1)
	go func() {
		s := bufio.NewScanner(pipe)
		for s.Scan() {
			if s.Text() == "SOL_R4_READY" {
				ready <- true
				return
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		if !ok {
			cmd.Process.Kill()
			cmd.Wait()
			t.Fatal("mount helper did not become ready")
		}
	case <-time.After(10 * time.Second):
		cmd.Process.Kill()
		cmd.Wait()
		t.Fatal("mount readiness timed out")
	}
	cmd.Process.Kill()
	cmd.Wait()
	raw, e := os.ReadFile("/proc/self/mountinfo")
	if e != nil {
		t.Fatal(e)
	}
	mounted := false
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) > 4 && f[4] == dir {
			t.Logf("mount after host kill: %s", line)
			mounted = true
		}
	}
	if mounted {
		t.Fatal("invocation FUSE mount survives abrupt host-process death")
	}
}

// Exercise the real LINK/UNLINK handlers directly so kernel caches and syscall
// latency do not obscure retained server memory. Every operation is valid and
// the number of simultaneously live entries stays below the public quota.
func TestSolR5DirectoryBackingMemory(t *testing.T) {
	fs := solR4Mount(t)
	if e := os.WriteFile(filepath.Join(fs.mountDir, "base"), nil, 0o600); e != nil {
		t.Fatal(e)
	}
	fs.mu.Lock()
	base := fs.inodes[1].children["base"]
	fs.mu.Unlock()
	dirs := make([]uint64, 128)
	for i := range dirs {
		name := fmt.Sprintf("d%d", i)
		if e := os.Mkdir(filepath.Join(fs.mountDir, name), 0o700); e != nil {
			t.Fatal(e)
		}
		fs.mu.Lock()
		dirs[i] = fs.inodes[1].children[name]
		fs.mu.Unlock()
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for _, d := range dirs {
		for i := 0; i < 3800; i++ {
			body := make([]byte, 8)
			binary.LittleEndian.PutUint64(body, base)
			body = append(body, []byte(fmt.Sprintf("%04d", i)+strings.Repeat("x", 240))...)
			body = append(body, 0)
			fs.handleRequest(-1, fuseOpLink, 1, d, body)
		}
		fs.mu.Lock()
		got := len(fs.inodes[d].children)
		fs.mu.Unlock()
		if got != 3800 {
			t.Fatalf("fixture not filled: %d", got)
		}
		for i := 0; i < 3800; i++ {
			fs.handleRequest(-1, fuseOpUnlink, 1, d, append([]byte(fmt.Sprintf("%04d", i)+strings.Repeat("x", 240)), 0))
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	fs.mu.Lock()
	used := fs.usedBytesLocked()
	entries := fs.totalDirEntriesLocked()
	fs.mu.Unlock()
	delta := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("retained server heap delta=%d charged bytes=%d live entries=%d inodes=%d", delta, used, entries, len(dirs)+2)
	if dest := os.Getenv("SOL_R5_HEAP"); dest != "" {
		file, e := os.Create(dest)
		if e != nil {
			t.Fatal(e)
		}
		pprof.WriteHeapProfile(file)
		file.Close()
	}
	runtime.KeepAlive(fs)
	if delta > 16*1024*1024 {
		t.Fatalf("empty directories retain %d bytes outside scratch accounting", delta)
	}
}

func TestSolR5NonEmptyDirectoryBackingMemory(t *testing.T) {
	fs := solR4Mount(t)
	if e := os.WriteFile(filepath.Join(fs.mountDir, "base"), nil, 0o600); e != nil {
		t.Fatal(e)
	}
	fs.mu.Lock()
	base := fs.inodes[1].children["base"]
	fs.mu.Unlock()
	dirs := make([]uint64, 128)
	for i := range dirs {
		name := fmt.Sprintf("d%d", i)
		if e := os.Mkdir(filepath.Join(fs.mountDir, name), 0o700); e != nil {
			t.Fatal(e)
		}
		fs.mu.Lock()
		dirs[i] = fs.inodes[1].children[name]
		fs.mu.Unlock()
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	for _, d := range dirs {
		for i := 0; i < 3800; i++ {
			body := make([]byte, 8)
			binary.LittleEndian.PutUint64(body, base)
			body = append(body, []byte(fmt.Sprintf("%04d", i)+strings.Repeat("x", 240))...)
			body = append(body, 0)
			fs.handleRequest(-1, fuseOpLink, 1, d, body)
		}
		// Leave 1 entry in each directory (non-empty shrink).
		for i := 1; i < 3800; i++ {
			fs.handleRequest(-1, fuseOpUnlink, 1, d, append([]byte(fmt.Sprintf("%04d", i)+strings.Repeat("x", 240)), 0))
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	fs.mu.Lock()
	used := fs.usedBytesLocked()
	entries := fs.totalDirEntriesLocked()
	fs.mu.Unlock()
	delta := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("nonempty retained server heap delta=%d charged bytes=%d live entries=%d", delta, used, entries)
	runtime.KeepAlive(fs)
	if delta > 16*1024*1024 {
		t.Fatalf("nonempty directories retain %d bytes outside scratch accounting", delta)
	}
}

func TestSolR5XattrsAndWatchdogKilled(t *testing.T) {
	fs := solR4Mount(t)
	p := filepath.Join(fs.mountDir, "base")
	if e := os.WriteFile(p, nil, 0o600); e != nil {
		t.Fatal(e)
	}
	if e := syscall.Setxattr(p, "user.blob", make([]byte, 65536), 0); e != syscall.EOPNOTSUPP {
		t.Fatalf("xattrs not refused: %v", e)
	}
	if e := fs.watchCmd.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	// A dead watchdog must neither kill the active filesystem nor block Close.
	if e := os.WriteFile(filepath.Join(fs.mountDir, "alive"), []byte("ok"), 0o600); e != nil {
		t.Fatal(e)
	}
	start := time.Now()
	fs.Close()
	if time.Since(start) > 6*time.Second {
		t.Fatal("Close blocked after watchdog death")
	}
	raw, e := os.ReadFile("/proc/self/mountinfo")
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(string(raw), " "+fs.mountDir+" ") {
		t.Fatal("normal close left mount after watchdog death")
	}
}

func solR5ForeignMount(t *testing.T, dir, source, subtype string) {
	t.Helper()
	fm, e := resolveFusermountBin()
	if e != nil {
		t.Fatal(e)
	}
	pair, e := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
	if e != nil {
		t.Fatal(e)
	}
	syscall.CloseOnExec(pair[0])
	defer syscall.Close(pair[0])
	child := os.NewFile(uintptr(pair[1]), "comm")
	cmd := exec.Command(fm, "-o", "rw,nosuid,nodev,fsname="+source+",subtype="+subtype, "--", dir)
	cmd.ExtraFiles = []*os.File{child}
	cmd.Env = []string{"PATH=/usr/bin:/bin", "_FUSE_COMMFD=3"}
	if e = cmd.Start(); e != nil {
		child.Close()
		t.Fatal(e)
	}
	child.Close()
	syscall.SetsockoptTimeval(pair[0], syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 5})
	buf := make([]byte, 64)
	oob := make([]byte, syscall.CmsgSpace(4))
	_, n, _, _, e := syscall.Recvmsg(pair[0], buf, oob, 0)
	we := cmd.Wait()
	if e != nil || we != nil {
		t.Fatalf("foreign mount: %v %v", e, we)
	}
	msgs, e := syscall.ParseSocketControlMessage(oob[:n])
	if e != nil || len(msgs) == 0 {
		t.Fatal("no rights", e)
	}
	fds, e := syscall.ParseUnixRights(&msgs[0])
	if e != nil {
		t.Fatal(e)
	}
	for _, fd := range fds {
		syscall.Close(fd) // Deliberately disconnected foreign filesystem.
	}
	t.Cleanup(func() { exec.Command(fm, "-u", "-z", "--", dir).Run() })
}

func solR5Mounted(path string) bool {
	b, _ := os.ReadFile("/proc/self/mountinfo")
	return strings.Contains(string(b), " "+path+" ")
}

func TestSolR5HostAndHelperKilled(t *testing.T) {
	if os.Getenv("SOL_R5_KILL_CHILD") == "1" {
		fs, e := mountScratchFuseFS(os.Getenv("SOL_R5_KILL_PATH"), 16*1024*1024, 4096)
		if e != nil {
			t.Fatal(e)
		}
		if e = fs.watchCmd.Process.Kill(); e != nil {
			t.Fatal(e)
		}
		fmt.Println("SOL_R5_READY")
		time.Sleep(time.Minute)
		runtime.KeepAlive(fs)
		return
	}
	root := t.TempDir()
	fm, e := resolveFusermountBin()
	if e != nil {
		t.Fatal(e)
	}
	foreign := []string{}
	for i, sig := range [][2]string{{"sol_foreign", "tmpfs"}, {"lmcloud_scratch", "sol_foreign"}} {
		d := filepath.Join(root, fmt.Sprintf("foreign%d", i))
		os.Mkdir(d, 0o700)
		solR5ForeignMount(t, d, sig[0], sig[1])
		foreign = append(foreign, d)
	}
	connected := solR4Mount(t)
	d := filepath.Join(root, "owned-orphan")
	os.Mkdir(d, 0o700)
	defer exec.Command(fm, "-u", "-z", "--", d).Run()
	cmd := exec.Command(os.Args[0], "-test.run=^TestSolR5HostAndHelperKilled$", "-test.timeout=75s")
	cmd.Env = append(os.Environ(), "SOL_R5_KILL_CHILD=1", "SOL_R5_KILL_PATH="+d)
	pipe, e := cmd.StdoutPipe()
	if e != nil {
		t.Fatal(e)
	}
	cmd.Stderr = cmd.Stdout
	if e = cmd.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { cmd.Process.Kill(); cmd.Wait() }()
	ready := make(chan bool, 1)
	go func() {
		s := bufio.NewScanner(pipe)
		for s.Scan() {
			if s.Text() == "SOL_R5_READY" {
				ready <- true
				return
			}
		}
		ready <- false
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("child not ready")
		}
	case <-time.After(10 * time.Second):
		t.Fatal("readiness timeout")
	}
	cmd.Process.Kill()
	cmd.Wait()
	if !solR5Mounted(d) {
		t.Fatal("double-kill orphan fixture missing")
	}
	sweepDisconnectedScratchMounts(fm)
	if solR5Mounted(d) {
		t.Fatal("owned disconnected mount not recovered")
	}
	if !solR5Mounted(connected.mountDir) {
		t.Fatal("sweeper unmounted connected filesystem")
	}
	for _, p := range foreign {
		if !solR5Mounted(p) {
			t.Fatalf("sweeper unmounted foreign filesystem %s", p)
		}
	}
	t.Log("SIGKILL of watchdog then owner: recovery detached orphan, retained both foreign signatures and connected mount")
}

func TestSolR5DirectoryBackingMemoryViaKernel(t *testing.T) {
	fs := solR4Mount(t)
	base := filepath.Join(fs.mountDir, "base")
	if e := os.WriteFile(base, nil, 0o600); e != nil {
		t.Fatal(e)
	}
	dirs := make([]string, 128)
	names := make([]string, 3800)
	for i := range dirs {
		dirs[i] = filepath.Join(fs.mountDir, fmt.Sprintf("dir%d", i))
		if e := os.Mkdir(dirs[i], 0o700); e != nil {
			t.Fatal(e)
		}
	}
	for i := range names {
		names[i] = fmt.Sprintf("%04d", i) + strings.Repeat("x", 240)
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	start := time.Now()
	for _, dir := range dirs {
		for _, name := range names {
			if e := os.Link(base, filepath.Join(dir, name)); e != nil {
				t.Fatal(e)
			}
		}
		for _, name := range names {
			if e := os.Remove(filepath.Join(dir, name)); e != nil {
				t.Fatal(e)
			}
		}
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	fs.mu.Lock()
	used := fs.usedBytesLocked()
	entries := fs.totalDirEntriesLocked()
	fs.mu.Unlock()
	delta := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("KERNEL PATH: retained heap=%d charged bytes=%d entries=%d elapsed=%s", delta, used, entries, time.Since(start))
	runtime.KeepAlive(fs)
	if delta > 16*1024*1024 {
		t.Fatalf("kernel filesystem operations retain %d bytes of uncharged directory storage", delta)
	}
}

func TestSolR5IsolatedFuseHelperCgroupAndClose(t *testing.T) {
	cgParent, cgErr := resolveCgroupParent()
	if cgErr != nil {
		t.Fatalf("resolveCgroupParent: %v", cgErr)
	}
	dir := filepath.Join(t.TempDir(), "helper-fuse")
	if e := os.Mkdir(dir, 0o700); e != nil {
		t.Fatal(e)
	}
	h, err := mountScratchFuseHelper(dir, 16*1024*1024, 4096, cgParent)
	if err != nil {
		t.Fatalf("mountScratchFuseHelper: %v", err)
	}
	defer h.Close()

	if h.cgDir == "" {
		t.Fatal("expected helper cgroup directory")
	}
	memMax, e := os.ReadFile(filepath.Join(h.cgDir, "memory.max"))
	if e != nil {
		t.Fatalf("read memory.max: %v", e)
	}
	swapMax, e := os.ReadFile(filepath.Join(h.cgDir, "memory.swap.max"))
	if e != nil {
		t.Fatalf("read memory.swap.max: %v", e)
	}
	pidsMax, e := os.ReadFile(filepath.Join(h.cgDir, "pids.max"))
	if e != nil {
		t.Fatalf("read pids.max: %v", e)
	}
	memEvents, _ := os.ReadFile(filepath.Join(h.cgDir, "memory.events"))
	t.Logf("race=%v helper cgroup=%s memory.max=%s memory.swap.max=%s pids.max=%s events=%q",
		isRaceEnabledProcess(), h.cgDir, strings.TrimSpace(string(memMax)), strings.TrimSpace(string(swapMax)), strings.TrimSpace(string(pidsMax)), string(memEvents))
	if strings.TrimSpace(string(swapMax)) != "0" {
		t.Fatalf("expected memory.swap.max=0, got %q", string(swapMax))
	}

	if e := os.WriteFile(filepath.Join(dir, "probe"), bytes.Repeat([]byte{'a'}, 1024*1024), 0o600); e != nil {
		memEventsAfter, _ := os.ReadFile(filepath.Join(h.cgDir, "memory.events"))
		t.Fatalf("write in helper FUSE mount: %v (used=%d events=%q)", e, h.UsedBytes(), string(memEventsAfter))
	}
	t.Logf("after 1MiB write: used=%d", h.UsedBytes())
	cgPath := h.cgDir
	h.Close()
	if solR5Mounted(dir) {
		t.Fatal("helper FUSE mount still mounted after Close")
	}
	if cgPath != "" {
		if _, e := os.Stat(cgPath); !os.IsNotExist(e) {
			t.Fatalf("helper cgroup directory %s still exists after Close: %v", cgPath, e)
		}
	}
}

func solR6Helper(t *testing.T) *scratchFuseHelper {
	t.Helper()
	cg, e := resolveCgroupParent()
	if e != nil {
		t.Fatal(e)
	}
	d := filepath.Join(t.TempDir(), "mnt")
	if e = os.Mkdir(d, 0o700); e != nil {
		t.Fatal(e)
	}
	h, e := mountScratchFuseHelper(d, 16<<20, 4096, cg)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(h.Close)
	return h
}

func solR6ReadInt(t *testing.T, p string) int64 {
	t.Helper()
	b, e := os.ReadFile(p)
	if e != nil {
		t.Fatal(e)
	}
	v, e := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
	if e != nil {
		t.Fatal(e)
	}
	return v
}

func TestSolR6HelperMemoryAndOOM(t *testing.T) {
	h := solR6Helper(t)
	pid := h.cmd.Process.Pid
	procs, e := os.ReadFile(filepath.Join(h.cgDir, "cgroup.procs"))
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains("\n"+string(procs), fmt.Sprintf("\n%d\n", pid)) {
		t.Fatal("server not in bounded cgroup", string(procs), pid)
	}
	max := solR6ReadInt(t, filepath.Join(h.cgDir, "memory.max"))
	before := solR6ReadInt(t, filepath.Join(h.cgDir, "memory.current"))
	if max <= 0 || max > 600<<20 {
		t.Fatal("no plausible finite cap", max)
	}
	if e = os.WriteFile(filepath.Join(h.mountDir, "data"), bytes.Repeat([]byte("x"), 8<<20), 0o600); e != nil {
		t.Fatal(e)
	}
	after := solR6ReadInt(t, filepath.Join(h.cgDir, "memory.current"))
	used := h.UsedBytes()
	t.Logf("server=%d max=%d current-before=%d current-after=%d used=%d", pid, max, before, after, used)
	if after-before < 4<<20 {
		t.Fatal("server data allocation not charged to bounded cgroup")
	}
	if used != 8<<20 {
		t.Fatal("incorrect control response", used)
	}
	if e = os.WriteFile(filepath.Join(h.cgDir, "memory.max"), []byte("1048576"), 0o600); e != nil {
		t.Fatal(e)
	}
	t.Logf("effective lowered memory.max=%d", solR6ReadInt(t, filepath.Join(h.cgDir, "memory.max")))
	pressure := make(chan error, 1)
	go func() {
		pressure <- os.WriteFile(filepath.Join(h.mountDir, "pressure"), bytes.Repeat([]byte("y"), 8<<20), 0o600)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for !cgroupHadOOM(h.cgDir) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	events, _ := os.ReadFile(filepath.Join(h.cgDir, "memory.events"))
	t.Logf("forced OOM events: %s", events)
	if !cgroupHadOOM(h.cgDir) {
		t.Fatal("lowered real memory.max did not constrain helper")
	}
	select {
	case e := <-pressure:
		t.Logf("pressure syscall released: %v", e)
	case <-time.After(5 * time.Second):
		t.Fatal("pressure write blocked after helper OOM")
	}
	if got := h.UsedBytes(); got <= 16<<20 {
		t.Fatal("helper OOM not signaled to invocation monitor", got)
	}
	deadline = time.Now().Add(5 * time.Second)
	for solR5Mounted(h.mountDir) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if solR5Mounted(h.mountDir) {
		t.Fatal("helper OOM left mount connected")
	}
}

func TestSolR6UnavailableAndParentFence(t *testing.T) {
	for _, cg := range []string{"", filepath.Join(t.TempDir(), "missing")} {
		dir := t.TempDir()
		h, e := mountScratchFuseHelper(dir, 16<<20, 4096, cg)
		if h != nil {
			h.Close()
			t.Fatal("unavailable cgroup accepted")
		}
		if e == nil {
			t.Fatal("unavailable cgroup succeeded")
		}
		if solR5Mounted(dir) {
			t.Fatal("failed startup left mount")
		}
	}
	cmd := exec.Command(os.Args[0])
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LMCLOUD_SCRATCH_FUSE_HELPER=1", "LMCLOUD_SCRATCH_FUSE_PPID=2147483647"}
	start := time.Now()
	out, e := cmd.CombinedOutput()
	if e == nil || time.Since(start) > 2*time.Second {
		t.Fatal("mismatched parent accepted or hung", e, string(out))
	}
}

func TestSolR6OwnerKill(t *testing.T) {
	if os.Getenv("SOL_R6_OWNER") == "1" {
		cg, e := resolveCgroupParent()
		if e != nil {
			t.Fatal(e)
		}
		h, e := mountScratchFuseHelper(os.Getenv("SOL_R6_MOUNT"), 16<<20, 4096, cg)
		if e != nil {
			t.Fatal(e)
		}
		if os.Getenv("SOL_R6_BOTH") == "1" {
			_ = h.cmd.Process.Kill()
		}
		b, _ := json.Marshal([]string{h.cgDir, strconv.Itoa(h.cmd.Process.Pid)})
		fmt.Println("SOL_R6_READY " + string(b))
		time.Sleep(time.Minute)
		return
	}
	for _, both := range []bool{false, true} {
		t.Run(fmt.Sprint(both), func(t *testing.T) {
			dir := t.TempDir()
			fm, _ := resolveFusermountBin()
			defer exec.Command(fm, "-u", "-z", "--", dir).Run()
			cmd := exec.Command(os.Args[0], "-test.run=^TestSolR6OwnerKill$", "-test.timeout=75s")
			cmd.Env = append(os.Environ(), "SOL_R6_OWNER=1", "SOL_R6_MOUNT="+dir)
			if both {
				cmd.Env = append(cmd.Env, "SOL_R6_BOTH=1")
			}
			pipe, e := cmd.StdoutPipe()
			if e != nil {
				t.Fatal(e)
			}
			cmd.Stderr = cmd.Stdout
			if e = cmd.Start(); e != nil {
				t.Fatal(e)
			}
			defer func() {
				_ = cmd.Process.Kill()
				_ = cmd.Wait()
			}()
			ready := make(chan []string, 1)
			go func() {
				s := bufio.NewScanner(pipe)
				for s.Scan() {
					if strings.HasPrefix(s.Text(), "SOL_R6_READY ") {
						var v []string
						_ = json.Unmarshal([]byte(strings.TrimPrefix(s.Text(), "SOL_R6_READY ")), &v)
						ready <- v
						return
					}
				}
				ready <- nil
			}()
			var v []string
			select {
			case v = <-ready:
			case <-time.After(10 * time.Second):
				t.Fatal("owner start timeout")
			}
			if len(v) != 2 {
				t.Fatal("owner startup failed")
			}
			defer func() {
				_ = os.WriteFile(filepath.Join(v[0], "cgroup.kill"), []byte("1"), 0o600)
				_ = os.Remove(v[0])
			}()
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			deadline := time.Now().Add(5 * time.Second)
			for time.Now().Before(deadline) {
				_, statErr := os.Stat(v[0])
				if !solR5Mounted(dir) && os.IsNotExist(statErr) {
					break
				}
				time.Sleep(10 * time.Millisecond)
			}
			if solR5Mounted(dir) {
				t.Fatal("owner/helper death left mounted filesystem")
			}
			procs, _ := os.ReadFile(filepath.Join(v[0], "cgroup.procs"))
			if strings.TrimSpace(string(procs)) != "" {
				t.Fatal("helper survived owner death", string(procs))
			}
			_, e = os.Stat(v[0])
			t.Logf("both=%v: mount detached, helper cgroup empty; directory remains=%v", both, e == nil)
			if !os.IsNotExist(e) {
				t.Fatalf("owner/helper death left empty cgroup directory %s: %v", v[0], e)
			}
		})
	}
}

func TestSolR6InvocationHelperOOM(t *testing.T) {
	f := New(Options{})
	if ce := f.ensureSandboxReady(); ce != nil {
		t.Fatal(ce)
	}
	old, _ := filepath.Glob(filepath.Join(cachedCgroupParent, "lmcloud-fuse-*.scope"))
	known := map[string]bool{}
	for _, p := range old {
		known[p] = true
	}
	code := "import os,time\ndef handler(e,c):\n time.sleep(1)\n try: open('/tmp/data','wb').write(b'x'*(8*1024*1024))\n except OSError: pass\n time.sleep(20)\n return {}\n"
	zip, _, ce := hostkit.BuildDeterministicInlineZip(hostkit.RuntimePython312, "index.handler", code)
	if ce != nil {
		t.Fatal(ce)
	}
	type result struct {
		out hostkit.FunctionInvokeOutput
		err *hostkit.CloudError
	}
	done := make(chan result, 1)
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	start := time.Now()
	go func() {
		out, _, err := executeInNamespaceJail(ctx, cachedPythonBin, cachedNodeBin, cachedNodeRoot, sandboxExecSpec{
			Runtime:        hostkit.RuntimePython312,
			Handler:        "index.handler",
			BundleZip:      zip,
			TimeoutSeconds: 25,
			MemoryMB:       128,
			PayloadJSON:    "{}",
		})
		done <- result{out, err}
	}()
	var target string
	deadline := time.Now().Add(4 * time.Second)
	for target == "" && time.Now().Before(deadline) {
		paths, _ := filepath.Glob(filepath.Join(cachedCgroupParent, "lmcloud-fuse-*.scope"))
		for _, p := range paths {
			if !known[p] {
				b, _ := os.ReadFile(filepath.Join(p, "memory.max"))
				n, _ := strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
				procs, _ := os.ReadFile(filepath.Join(p, "cgroup.procs"))
				if n > 0 && n < 600<<20 && n != 268435456 && n != 536870912 && len(procs) > 0 {
					pid, _ := strconv.Atoi(strings.TrimSpace(string(procs)))
					raw, _ := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
					isOurs := false
					for _, line := range strings.Split(string(raw), "\n") {
						if strings.HasPrefix(line, "PPid:") {
							fields := strings.Fields(line)
							isOurs = len(fields) == 2 && fields[1] == strconv.Itoa(os.Getpid())
						}
					}
					if isOurs {
						target = p
						break
					}
				}
			}
		}
		time.Sleep(time.Millisecond)
	}
	if target == "" {
		cancel()
		r := <-done
		t.Fatal("invocation helper did not become ready", r.err, r.out.FunctionError, r.out.Payload)
	}
	t.Logf("invocation helper cgroup=%s", target)
	time.Sleep(50 * time.Millisecond)
	procs, _ := os.ReadFile(filepath.Join(target, "cgroup.procs"))
	pid, _ := strconv.Atoi(strings.TrimSpace(string(procs)))
	env, _ := os.ReadFile(fmt.Sprintf("/proc/%d/environ", pid))
	mount := ""
	for _, part := range strings.Split(string(env), "\x00") {
		if strings.HasPrefix(part, "LMCLOUD_SCRATCH_FUSE_MOUNT_DIR=") {
			mount = strings.TrimPrefix(part, "LMCLOUD_SCRATCH_FUSE_MOUNT_DIR=")
		}
	}
	if mount == "" {
		t.Fatal("owned helper mount unknown")
	}
	if e := os.WriteFile(filepath.Join(mount, "oom-fixture"), bytes.Repeat([]byte("x"), 8<<20), 0o600); e != nil {
		t.Fatal(e)
	}
	t.Logf("before forced OOM current=%d", solR6ReadInt(t, filepath.Join(target, "memory.current")))
	if e := os.WriteFile(filepath.Join(target, "memory.max"), []byte("1048576"), 0o600); e != nil {
		t.Fatal(e)
	}
	select {
	case r := <-done:
		t.Logf("helper OOM invocation elapsed=%s error=%+v function-error=%s payload=%s", time.Since(start), r.err, r.out.FunctionError, r.out.Payload)
		if r.err != nil || r.out.FunctionError != "Unhandled" || !strings.Contains(r.out.Payload, "DiskQuotaExceeded") {
			t.Fatal("helper OOM was not a clean invocation failure")
		}
		if time.Since(start) > 8*time.Second {
			t.Fatal("helper OOM handler hung until timeout")
		}
	case <-time.After(10 * time.Second):
		events, _ := os.ReadFile(filepath.Join(target, "memory.events"))
		procs, _ := os.ReadFile(filepath.Join(target, "cgroup.procs"))
		t.Logf("late events=%s procs=%s", events, procs)
		cancel()
		select {
		case r := <-done:
			t.Logf("after cancel: err=%+v out=%+v", r.err, r.out)
		case <-time.After(7 * time.Second):
			t.Log("still blocked after cancellation")
		}
		t.Fatal("helper OOM hung invocation")
	}
}

func TestSolR6HelperKilledWhileHostAlive(t *testing.T) {
	h := solR6Helper(t)
	f, e := os.Create(filepath.Join(h.mountDir, "open"))
	if e != nil {
		t.Fatal(e)
	}
	defer f.Close()
	if e = h.cmd.Process.Kill(); e != nil {
		t.Fatal(e)
	}
	deadline := time.Now().Add(5 * time.Second)
	for solR5Mounted(h.mountDir) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if solR5Mounted(h.mountDir) {
		t.Fatal("SIGKILLed helper left mount")
	}
	done := make(chan error, 1)
	go func() {
		_, e := f.Write([]byte("after-kill"))
		done <- e
	}()
	select {
	case e := <-done:
		if e == nil {
			t.Fatal("write on disconnected mount succeeded")
		}
		t.Logf("post-helper-kill write promptly failed: %v", e)
	case <-time.After(time.Second):
		t.Fatal("helper death blocked handler filesystem syscall")
	}
	start := time.Now()
	_ = h.UsedBytes()
	if time.Since(start) > time.Second {
		t.Fatal("control read blocked after helper death")
	}
	cg := h.cgDir
	h.Close()
	if _, e = os.Stat(cg); !os.IsNotExist(e) {
		t.Fatal("normal Close after helper kill retained cgroup", e)
	}
}
