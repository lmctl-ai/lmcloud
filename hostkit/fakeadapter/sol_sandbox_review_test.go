// SPDX-License-Identifier: MIT

package fakeadapter

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/pprof"
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
