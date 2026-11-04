// SPDX-License-Identifier: MIT

package fakeadapter

import (
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"testing"
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
