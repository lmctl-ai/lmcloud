// SPDX-License-Identifier: MIT

package fakeadapter

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
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
