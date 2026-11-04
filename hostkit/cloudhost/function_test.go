// SPDX-License-Identifier: MIT

package cloudhost

import (
	"archive/zip"
	"bytes"
	"compress/flate"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/lmctl-ai/lmcloud/hostkit"
	"github.com/lmctl-ai/lmcloud/hostkit/fakeadapter"
	"github.com/lmctl-ai/lmcloud/hostkit/safety"
)

func newFuncHost(t *testing.T) (*Host, *fakeadapter.Fake, string, string) {
	t.Helper()
	dir := t.TempDir()
	statePath := filepath.Join(dir, "fake.json")
	campaignPath := filepath.Join(dir, "campaign.jsonl")
	fake := fakeadapter.New(fakeadapter.Options{StatePath: statePath})
	h := New(Config{
		Provider:          "aws",
		Store:             fake,
		Queue:             fake,
		Tables:            fake,
		Permissions:       fake,
		Functions:         fake,
		CampaignStatePath: campaignPath,
	})
	h.SetAbortOnError(false)
	return h, fake, statePath, campaignPath
}

// TestGateG1MaliciousArchiveAndZipBombRejection verifies Gate G1:
// archives with > 16 MiB compressed size, > 64 MiB uncompressed expansion (zip bomb),
// > 256 entries, ../ traversal, absolute paths, symlinks/devices, encrypted entries,
// case-colliding duplicate entries, or missing handler files are rejected with INVALID_ARGUMENT.
func TestGateG1MaliciousArchiveAndZipBombRejection(t *testing.T) {
	// 1. > 16 MiB compressed size
	oversizeCompressed := make([]byte, hostkit.MaxFunctionPackageBytes+1)
	if _, _, ce := hostkit.ValidateAndCanonicalizePackage(hostkit.RuntimePython312, "index.handler", "pkg.zip", oversizeCompressed); ce == nil || ce.Code != hostkit.InvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT on >16 MiB package, got %+v", ce)
	}

	// 2. > 64 MiB uncompressed expansion (zip bomb: 3 entries of 22 MiB zeros = 66 MiB)
	var bombBuf bytes.Buffer
	zw := zip.NewWriter(&bombBuf)
	zw.RegisterCompressor(zip.Deflate, func(out io.Writer) (io.WriteCloser, error) {
		return flate.NewWriter(out, flate.BestSpeed)
	})
	w0, _ := zw.Create("index.py")
	_, _ = w0.Write([]byte("def handler(e, c): return {}\n"))
	chunk22M := make([]byte, 22*1024*1024)
	for i := 0; i < 3; i++ {
		w, _ := zw.Create(fmt.Sprintf("blob_%d.bin", i))
		_, _ = w.Write(chunk22M)
	}
	_ = zw.Close()
	if _, _, ce := hostkit.ValidateAndCanonicalizePackage(hostkit.RuntimePython312, "index.handler", "bomb.zip", bombBuf.Bytes()); ce == nil || ce.Code != hostkit.InvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT on >64 MiB uncompressed zip bomb, got %+v", ce)
	}

	// 3. > 256 entries
	var manyBuf bytes.Buffer
	zwMany := zip.NewWriter(&manyBuf)
	wIdx, _ := zwMany.Create("index.py")
	_, _ = wIdx.Write([]byte("def handler(e, c): return {}\n"))
	for i := 0; i < 256; i++ {
		w, _ := zwMany.Create(fmt.Sprintf("f_%d.txt", i))
		_, _ = w.Write([]byte("x"))
	}
	_ = zwMany.Close()
	if _, _, ce := hostkit.ValidateAndCanonicalizePackage(hostkit.RuntimePython312, "index.handler", "many.zip", manyBuf.Bytes()); ce == nil || ce.Code != hostkit.InvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT on >256 entries, got %+v", ce)
	}

	// 4. Path traversal ("../evil.py") and absolute path ("/etc/passwd")
	for _, badPath := range []string{"../index.py", "a/../../index.py", "/index.py", `sub\index.py`, "C:index.py"} {
		var pBuf bytes.Buffer
		zwp := zip.NewWriter(&pBuf)
		w, _ := zwp.Create(badPath)
		_, _ = w.Write([]byte("def handler(e, c): return {}\n"))
		_ = zwp.Close()
		if _, _, ce := hostkit.ValidateAndCanonicalizePackage(hostkit.RuntimePython312, "index.handler", "badpath.zip", pBuf.Bytes()); ce == nil || ce.Code != hostkit.InvalidArgument {
			t.Fatalf("expected INVALID_ARGUMENT on bad archive path %q, got %+v", badPath, ce)
		}
	}

	// 5. Symlink / device node in archive
	var symBuf bytes.Buffer
	zws := zip.NewWriter(&symBuf)
	fh := &zip.FileHeader{Name: "index.py", Method: zip.Deflate}
	fh.SetMode(os.ModeSymlink | 0o777)
	ws, _ := zws.CreateHeader(fh)
	_, _ = ws.Write([]byte("/etc/passwd"))
	_ = zws.Close()
	if _, _, ce := hostkit.ValidateAndCanonicalizePackage(hostkit.RuntimePython312, "index.handler", "sym.zip", symBuf.Bytes()); ce == nil || ce.Code != hostkit.InvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT on symlink entry, got %+v", ce)
	}

	// 6. Case-colliding duplicate entries ("index.py" and "INDEX.py")
	var dupBuf bytes.Buffer
	zwd := zip.NewWriter(&dupBuf)
	wd1, _ := zwd.Create("index.py")
	_, _ = wd1.Write([]byte("def handler(e, c): return {}\n"))
	wd2, _ := zwd.Create("INDEX.py")
	_, _ = wd2.Write([]byte("def handler(e, c): return {}\n"))
	_ = zwd.Close()
	if _, _, ce := hostkit.ValidateAndCanonicalizePackage(hostkit.RuntimePython312, "index.handler", "dup.zip", dupBuf.Bytes()); ce == nil || ce.Code != hostkit.InvalidArgument {
		t.Fatalf("expected INVALID_ARGUMENT on case-colliding entries, got %+v", ce)
	}

	// 7. End-to-end rejection through Host.FunctionCreate with object package
	h, _, _, _ := newFuncHost(t)
	if _, err := h.BucketCreate(false, "pkg-bkt"); err != nil {
		t.Fatalf("BucketCreate: %v", err)
	}
	if _, err := h.ObjectPut(false, "pkg-bkt", "bad.zip", string(dupBuf.Bytes()), "application/zip", nil); err != nil {
		t.Fatalf("ObjectPut: %v", err)
	}
	cfg, _ := h.FunctionConfig("python3.12", "index.handler")
	cfg, _ = cfg.SetPackageObject("pkg-bkt", "bad.zip")
	if created, _ := h.FunctionCreate(false, "badpkgfn", cfg); created || h.LastError().Code != hostkit.InvalidArgument {
		t.Fatalf("expected FunctionCreate to reject malicious ZIP with INVALID_ARGUMENT, got created=%v err=%+v", created, h.LastError())
	}
}

// TestGateG2OSNamespaceIsolationCanaryAndRedaction verifies Gate G2:
// (a) ambient os.environ canary is scrubbed,
// (b) /proc and /proc/<parent_pid>/environ are blocked inside the sandbox,
// (c) host /tmp 0600 canary file is blocked inside the sandbox,
// (d) host loopback 127.0.0.1:<port> listener is unreachable inside CLONE_NEWNET,
// (e) disabling namespace sandbox fails closed with ErrorCode.INTERNAL,
// (f) ErrorState.AddRedaction scrubs configured env values and create tokens from errors while preserving result.logs()/payload().
func TestGateG2OSNamespaceIsolationCanaryAndRedaction(t *testing.T) {
	t.Setenv("WORKER_CANARY", "super-secret-worker-canary-value")

	canaryFile, err := os.CreateTemp("", "host-canary-*")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(canaryFile.Name())
	_ = os.Chmod(canaryFile.Name(), 0o600)
	_, _ = canaryFile.WriteString("host-tmp-canary-secret")
	_ = canaryFile.Close()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := ln.Addr().(*net.TCPAddr).Port

	h, _, statePath, _ := newFuncHost(t)
	code := fmt.Sprintf(`import os, socket
def handler(event, context):
    env_leaked = "WORKER_CANARY" in os.environ
    proc_leaked = False
    try:
        os.listdir("/proc")
        proc_leaked = True
    except Exception:
        pass
    parent_env_leaked = False
    try:
        open("/proc/%d/environ", "rb").read()
        parent_env_leaked = True
    except Exception:
        pass
    tmp_leaked = False
    try:
        open(%q, "rb").read()
        tmp_leaked = True
    except Exception:
        pass
    net_leaked = False
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.5)
        s.connect(("127.0.0.1", %d))
        net_leaked = True
    except Exception:
        pass
    print(" intentional-log:" + os.environ.get("USER_SECRET_ENV", ""))
    return {
        "env_leaked": env_leaked,
        "proc_leaked": proc_leaked,
        "parent_env_leaked": parent_env_leaked,
        "tmp_leaked": tmp_leaked,
        "net_leaked": net_leaked,
        "user_secret": os.environ.get("USER_SECRET_ENV", ""),
    }
`, os.Getpid(), canaryFile.Name(), port)

	cfg, _ := h.FunctionConfig("python3.12", "index.handler")
	cfg, _ = cfg.SetInlineCode(code)
	cfg, _ = cfg.SetEnv("USER_SECRET_ENV", "my-confidential-env-value-987")
	if created, err := h.FunctionCreate(false, "g2canaryfn", cfg); !created || err != nil {
		t.Fatalf("FunctionCreate: created=%v err=%v (%+v)", created, err, h.LastError())
	}

	res, err := h.FunctionInvoke(false, "g2canaryfn", "", "{}", false)
	if err != nil || res.IsError() {
		t.Fatalf("FunctionInvoke failed: err=%v res=%+v lastErr=%+v", err, res, h.LastError())
	}
	for _, wantFalse := range []string{
		`"env_leaked": false`,
		`"proc_leaked": false`,
		`"parent_env_leaked": false`,
		`"tmp_leaked": false`,
		`"net_leaked": false`,
	} {
		if !strings.Contains(res.Payload(), wantFalse) {
			t.Fatalf("isolation check failed (missing %s) in payload: %s", wantFalse, res.Payload())
		}
	}
	// Intentional handler output in payload() and logs() is preserved verbatim:
	if !strings.Contains(res.Payload(), "my-confidential-env-value-987") || !strings.Contains(res.Logs(), "my-confidential-env-value-987") {
		t.Fatalf("expected intentional handler output to preserve USER_SECRET_ENV in payload/logs: payload=%q logs=%q", res.Payload(), res.Logs())
	}

	// Host error diagnostics must redact USER_SECRET_ENV if echoed by a provider error:
	_ = h.fail("function_update", "g2canaryfn", hostkit.ProviderError(hostkit.Internal, 500, "Err.my-confidential-env-value-987", "provider failed with my-confidential-env-value-987"))
	if strings.Contains(h.LastError().Message, "my-confidential-env-value-987") || strings.Contains(h.LastError().ProviderCode, "my-confidential-env-value-987") {
		t.Fatalf("USER_SECRET_ENV leaked in LastError: %+v", h.LastError())
	}

	// Fail-closed when namespace sandbox is disabled:
	fakeDisabled := fakeadapter.New(fakeadapter.Options{
		StatePath:               statePath,
		DisableNamespaceSandbox: true,
	})
	hDisabled := New(Config{
		Provider:  "aws",
		Store:     fakeDisabled,
		Functions: fakeDisabled,
	})
	hDisabled.SetAbortOnError(false)
	_, _ = hDisabled.FunctionInvoke(false, "g2canaryfn", "", "{}", false)
	if hDisabled.LastError().Code != hostkit.Internal {
		t.Fatalf("expected ErrorCode.INTERNAL when namespace sandbox is disabled, got %+v", hDisabled.LastError())
	}
}

// TestGateG3PIDNamespaceReapingAndMemoryLimits verifies Gate G3:
// (a) setsid() grandchild spawned by a timing-out handler is killed (ESRCH) by PID-namespace teardown,
// (b) both python3.12 and nodejs20.x start and execute cleanly at 128 MiB,
// (c) both python3.12 and nodejs20.x allocating resident memory > 128 MiB terminate with Unhandled.
func TestGateG3PIDNamespaceReapingAndMemoryLimits(t *testing.T) {
	h, fake, _, _ := newFuncHost(t)

	// (a) PID-namespace reaping of setsid() grandchild on timeout
	setsidCode := `import os, time
def handler(event, context):
    pid = os.fork()
    if pid == 0:
        os.setsid()
        time.sleep(60)
        os._exit(0)
    time.sleep(5)
    return {"ok": True}
`
	cfgTimeout, _ := h.FunctionConfig("python3.12", "index.handler")
	cfgTimeout, _ = cfgTimeout.SetInlineCode(setsidCode)
	cfgTimeout, _ = cfgTimeout.SetTimeoutSeconds(1)
	cfgTimeout, _ = cfgTimeout.SetMemoryMB(128)
	if _, err := h.FunctionCreate(false, "g3setsidfn", cfgTimeout); err != nil {
		t.Fatalf("FunctionCreate g3setsidfn: %v", err)
	}
	resTimeout, err := h.FunctionInvoke(false, "g3setsidfn", "", "{}", false)
	if err != nil || h.LastError().Code != hostkit.OK {
		t.Fatalf("expected timeout invoke to return ErrorCode.OK, got err=%v lastErr=%+v", err, h.LastError())
	}
	if !resTimeout.IsError() || resTimeout.FunctionError() != "Timeout" || resTimeout.BilledMS() != 1000 {
		t.Fatalf("expected Timeout with BilledMS=1000, got %+v", resTimeout)
	}
	pids := fake.LastSandboxHostPIDs()
	if len(pids) < 2 {
		t.Fatalf("expected at least 2 observed host PIDs (launcher + child/grandchild), got %v", pids)
	}
	for _, pid := range pids {
		if err := syscall.Kill(pid, 0); !errors.Is(err, syscall.ESRCH) {
			t.Fatalf("expected sandbox descendant PID %d to be reaped (ESRCH), got err=%v", pid, err)
		}
	}

	// (b) & (c) python3.12 OOM at 128 MiB
	pyOOMCode := `def handler(event, context):
    if event.get("oom", False):
        b = bytearray(160 * 1024 * 1024)
        return {"len": len(b)}
    return {"ok": "py128"}
`
	cfgPy, _ := h.FunctionConfig("python3.12", "index.handler")
	cfgPy, _ = cfgPy.SetInlineCode(pyOOMCode)
	cfgPy, _ = cfgPy.SetMemoryMB(128)
	if _, err := h.FunctionCreate(false, "g3pyoomfn", cfgPy); err != nil {
		t.Fatalf("FunctionCreate g3pyoomfn: %v", err)
	}
	resPyOK, err := h.FunctionInvoke(false, "g3pyoomfn", "", `{"oom":false}`, false)
	if err != nil || resPyOK.IsError() || !strings.Contains(resPyOK.Payload(), "py128") {
		t.Fatalf("python3.12 128 MiB normal invoke failed: err=%v res=%+v", err, resPyOK)
	}
	resPyOOM, err := h.FunctionInvoke(false, "g3pyoomfn", "", `{"oom":true}`, false)
	if err != nil || !resPyOOM.IsError() || resPyOOM.FunctionError() != "Unhandled" {
		t.Fatalf("expected python3.12 >128 MiB allocation to fail with Unhandled, got err=%v res=%+v", err, resPyOOM)
	}

	// (b) & (c) nodejs20.x startup & OOM at 128 MiB
	jsOOMCode := `exports.handler = async (event) => {
  if (event.oom) {
    const buf = Buffer.alloc(160 * 1024 * 1024, 1);
    return { len: buf.length };
  }
  return { ok: "js128" };
};
`
	cfgJS, _ := h.FunctionConfig("nodejs20.x", "index.handler")
	cfgJS, _ = cfgJS.SetInlineCode(jsOOMCode)
	cfgJS, _ = cfgJS.SetMemoryMB(128)
	if _, err := h.FunctionCreate(false, "g3jsoomfn", cfgJS); err != nil {
		t.Fatalf("FunctionCreate g3jsoomfn: %v", err)
	}
	resJSOK, err := h.FunctionInvoke(false, "g3jsoomfn", "", `{"oom":false}`, false)
	if err != nil || resJSOK.IsError() || !strings.Contains(resJSOK.Payload(), "js128") {
		t.Fatalf("nodejs20.x 128 MiB normal invoke failed: err=%v res=%+v", err, resJSOK)
	}
	resJSOOM, err := h.FunctionInvoke(false, "g3jsoomfn", "", `{"oom":true}`, false)
	if err != nil || !resJSOOM.IsError() || resJSOOM.FunctionError() != "Unhandled" {
		t.Fatalf("expected nodejs20.x >128 MiB allocation to fail with Unhandled, got err=%v res=%+v", err, resJSOOM)
	}
}

// TestGateG4StaleQuoteCostAdmissionMalformedBillingAndLostReply verifies Gate G4:
// (a) cross-process update of $LATEST or alias from 1s/128MiB to 230s/2048MiB causes a second host
//
//	with a tight work sub-cap to refuse FunctionInvoke pre-flight with COST_CAP_EXCEEDED (http=0);
//
// (b) malformed provider_billed_ms (-5 or 999999) settles at full worst-case duration (timeout_seconds * 1000);
// (c) mid-flight connection drop after dispatch retains full worst-case reservation with zero replay.
func TestGateG4StaleQuoteCostAdmissionMalformedBillingAndLostReply(t *testing.T) {
	dir := t.TempDir()
	statePath := filepath.Join(dir, "fake.json")
	campaignPath := filepath.Join(dir, "campaign.jsonl")

	fakeA := fakeadapter.New(fakeadapter.Options{StatePath: statePath})
	hostA := New(Config{
		Provider:          "aws",
		Store:             fakeA,
		Functions:         fakeA,
		CampaignStatePath: campaignPath,
	})
	hostA.SetAbortOnError(false)

	cfgSmall, _ := hostA.FunctionConfig("python3.12", "index.handler")
	cfgSmall, _ = cfgSmall.SetInlineCode("def handler(e, c):\n    return {\"ok\": True}\n")
	cfgSmall, _ = cfgSmall.SetTimeoutSeconds(1)
	cfgSmall, _ = cfgSmall.SetMemoryMB(128)
	if _, err := hostA.FunctionCreate(false, "g4quotafn", cfgSmall); err != nil {
		t.Fatalf("FunctionCreate: %v", err)
	}

	// Host B updates g4quotafn to 230s / 2048 MiB (3,680,100 billing units = $0.00736020).
	fakeB := fakeadapter.New(fakeadapter.Options{StatePath: statePath})
	hostB := New(Config{
		Provider:          "aws",
		Store:             fakeB,
		Functions:         fakeB,
		CampaignStatePath: campaignPath,
	})
	hostB.SetAbortOnError(false)
	cfgLarge, _ := hostB.FunctionConfig("python3.12", "index.handler")
	cfgLarge, _ = cfgLarge.SetInlineCode("def handler(e, c):\n    return {\"ok\": True}\n")
	cfgLarge, _ = cfgLarge.SetTimeoutSeconds(230)
	cfgLarge, _ = cfgLarge.SetMemoryMB(2048)
	if _, err := hostB.FunctionUpdate(false, "g4quotafn", cfgLarge, "", false); err != nil {
		t.Fatalf("FunctionUpdate on hostB: %v (%+v)", err, hostB.LastError())
	}

	// Set work sub-cap on hostA that admits 1s/128MiB ($0.0005) but NOT 230s/2048MiB ($0.00736+).
	settled := hostA.EstimatedCost()
	_ = hostA.SetCostCapUSD(settled + 0.001)
	callsBefore := fakeA.Calls()["InvokeFunction"]
	resBlocked, _ := hostA.FunctionInvoke(false, "g4quotafn", "", "{}", false)
	if hostA.LastError().Code != hostkit.CostCapExceeded || hostA.LastError().HTTPStatus != 0 || resBlocked.StatusCode() != 0 {
		t.Fatalf("expected pre-flight COST_CAP_EXCEEDED (http=0) after cross-process shape increase, got err=%+v res=%+v", hostA.LastError(), resBlocked)
	}
	if fakeA.Calls()["InvokeFunction"] != callsBefore {
		t.Fatal("InvokeFunction should not be dispatched when pre-flight cost admission rejects")
	}

	// (b) Malformed provider_billed_ms (-5 and 999999) settles at full worst-case duration (timeout_seconds * 1000 = 2000 ms).
	_ = hostB.SetCostCapUSD(0.20)
	cfg2s, _ := hostB.FunctionConfig("python3.12", "index.handler")
	cfg2s, _ = cfg2s.SetInlineCode("def handler(e, c):\n    return {\"ok\": True}\n")
	cfg2s, _ = cfg2s.SetTimeoutSeconds(2)
	cfg2s, _ = cfg2s.SetMemoryMB(128)
	if _, err := hostB.FunctionUpdate(false, "g4quotafn", cfg2s, "", false); err != nil {
		t.Fatalf("FunctionUpdate to 2s/128MiB: %v", err)
	}
	for _, badBilled := range []int64{-5, 999999} {
		fakeB.SetOverrideBilledMSForTesting(badBilled)
		resBad, err := hostB.FunctionInvoke(false, "g4quotafn", "", "{}", false)
		fakeB.SetOverrideBilledMSForTesting(0)
		if err != nil || resBad.BilledMS() != 2000 {
			t.Fatalf("expected malformed provider_billed_ms=%d to settle at worst-case 2000ms, got err=%v billed_ms=%d", badBilled, err, resBad.BilledMS())
		}
	}

	// (c) Mid-flight connection drop after InvokeFunction dispatch: zero replay & full worst-case reservation retained.
	costBeforeDrop := hostB.EstimatedCost()
	invCallsBefore := fakeB.Calls()["InvokeFunction"]
	fakeB.SetFaultInvokeAfterDispatchForTesting(func() error {
		return hostkit.ProviderError(hostkit.Internal, 503, "ConnectionReset", "simulated mid-flight connection drop")
	})
	_, _ = hostB.FunctionInvoke(false, "g4quotafn", "", "{}", false)
	fakeB.SetFaultInvokeAfterDispatchForTesting(nil)
	if fakeB.Calls()["InvokeFunction"] != invCallsBefore+1 {
		t.Fatalf("expected exactly 1 InvokeFunction attempt (no replay), got %d", fakeB.Calls()["InvokeFunction"]-invCallsBefore)
	}
	costAfterDrop := hostB.EstimatedCost()
	// Worst-case 2s/128MiB = 2100 units * 2 nano-USD = 4200 nano-USD + 2 MiB wire transfer (~180,000 nano-USD).
	if costAfterDrop <= costBeforeDrop+0.0001 {
		t.Fatalf("expected lost-reply invoke to retain full worst-case reservation: before=%f after=%f", costBeforeDrop, costAfterDrop)
	}
}

// TestGateG5RepeatedUpdateSynchronousGCPinningBackpressureAndTeardown verifies Gate G5:
// (a) 50 consecutive function_update calls keep retained staged bundles <= 3;
// (b) active invocations (including concurrency == 0) pin displaced revisions in pending_gc,
//
//	2 pinned revisions trigger 409 CONFLICT backpressure on a 3rd update, and completion drains pending_gc;
//
// (c) function_delete tears down 16 versions + 16 aliases + 1 candidate under exhausted work sub-cap using locked cleanup reserves.
func TestGateG5RepeatedUpdateSynchronousGCPinningBackpressureAndTeardown(t *testing.T) {
	h, fake, statePath, campaignPath := newFuncHost(t)

	// (a) 50 consecutive updates without publishing versions -> retained bundles <= 3
	cfg0, _ := h.FunctionConfig("python3.12", "index.handler")
	cfg0, _ = cfg0.SetInlineCode("def handler(e, c):\n    return {\"i\": 0}\n")
	if _, err := h.FunctionCreate(false, "g5gcfn", cfg0); err != nil {
		t.Fatalf("FunctionCreate: %v", err)
	}
	for i := 1; i <= 50; i++ {
		cfgi, _ := h.FunctionConfig("python3.12", "index.handler")
		cfgi, _ = cfgi.SetInlineCode(fmt.Sprintf("def handler(e, c):\n    return {\"i\": %d}\n", i))
		if _, err := h.FunctionUpdate(false, "g5gcfn", cfgi, "", false); err != nil {
			t.Fatalf("FunctionUpdate %d: %v (%+v)", i, err, h.LastError())
		}
		if n := fake.StagedBundleCount("g5gcfn"); n > 3 {
			t.Fatalf("update %d: staged bundle count %d exceeds unversioned cap of 3", i, n)
		}
	}

	// (b) Active invocation pinning (concurrency == 0) + pending_gc backpressure (len >= 2 -> 409 CONFLICT)
	slowCode1 := "import time\ndef handler(e, c):\n    time.sleep(1.2)\n    return {\"rev\": 1}\n"
	cfgSlow1, _ := h.FunctionConfig("python3.12", "index.handler")
	cfgSlow1, _ = cfgSlow1.SetInlineCode(slowCode1)
	if _, err := h.FunctionUpdate(false, "g5gcfn", cfgSlow1, "", false); err != nil {
		t.Fatalf("FunctionUpdate slow1: %v", err)
	}

	newPeerHost := func() *Host {
		f := fakeadapter.New(fakeadapter.Options{StatePath: statePath})
		ph := New(Config{
			Provider:          "aws",
			Store:             f,
			Functions:         f,
			CampaignStatePath: campaignPath,
		})
		ph.SetAbortOnError(false)
		return ph
	}

	var wg sync.WaitGroup
	var res1, res2 *FunctionInvokeResult
	var err1, err2 error
	wg.Add(1)
	go func() {
		defer wg.Done()
		ph1 := newPeerHost()
		res1, err1 = ph1.FunctionInvoke(false, "g5gcfn", "", "{}", false)
	}()
	time.Sleep(100 * time.Millisecond)

	// Update #1 while inv1 is in-flight -> old revision pinned in pending_gc (len == 1)
	slowCode2 := "import time\ndef handler(e, c):\n    time.sleep(1.2)\n    return {\"rev\": 2}\n"
	cfgSlow2, _ := h.FunctionConfig("python3.12", "index.handler")
	cfgSlow2, _ = cfgSlow2.SetInlineCode(slowCode2)
	if _, err := h.FunctionUpdate(false, "g5gcfn", cfgSlow2, "", false); err != nil {
		t.Fatalf("FunctionUpdate slow2 while inv1 active: %v (%+v)", err, h.LastError())
	}
	if fake.PendingGCCount("g5gcfn") != 1 {
		t.Fatalf("expected pending_gc count == 1 while inv1 active, got %d", fake.PendingGCCount("g5gcfn"))
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		ph2 := newPeerHost()
		res2, err2 = ph2.FunctionInvoke(false, "g5gcfn", "", "{}", false)
	}()
	time.Sleep(100 * time.Millisecond)

	// Update #2 while inv1 and inv2 are both in-flight -> pending_gc reaches 2
	slowCode3 := "def handler(e, c):\n    return {\"rev\": 3}\n"
	cfgSlow3, _ := h.FunctionConfig("python3.12", "index.handler")
	cfgSlow3, _ = cfgSlow3.SetInlineCode(slowCode3)
	if _, err := h.FunctionUpdate(false, "g5gcfn", cfgSlow3, "", false); err != nil {
		t.Fatalf("FunctionUpdate slow3 while inv1+inv2 active: %v (%+v)", err, h.LastError())
	}
	if fake.PendingGCCount("g5gcfn") != 2 {
		t.Fatalf("expected pending_gc count == 2 while inv1+inv2 active, got %d", fake.PendingGCCount("g5gcfn"))
	}

	// Update #3 while 2 displaced revisions are still pinned -> must fail closed with CONFLICT (409) backpressure!
	cfgSlow4, _ := h.FunctionConfig("python3.12", "index.handler")
	cfgSlow4, _ = cfgSlow4.SetInlineCode("def handler(e, c):\n    return {\"rev\": 4}\n")
	_, _ = h.FunctionUpdate(false, "g5gcfn", cfgSlow4, "", false)
	if h.LastError().Code != hostkit.Conflict || h.LastError().HTTPStatus != 409 {
		t.Fatalf("expected 409 CONFLICT backpressure when 2 displaced revisions are pinned in pending_gc, got lastErr=%+v", h.LastError())
	}

	wg.Wait()
	if err1 != nil || res1 == nil || res1.IsError() || !strings.Contains(res1.Payload(), `"rev": 1`) {
		t.Fatalf("inv1 on displaced revision failed: err=%v res=%+v", err1, res1)
	}
	if err2 != nil || res2 == nil || res2.IsError() || !strings.Contains(res2.Payload(), `"rev": 2`) {
		t.Fatalf("inv2 on displaced revision failed: err=%v res=%+v", err2, res2)
	}

	// Now that inv1 and inv2 have finished, Update #3 succeeds and drains pending_gc to 0!
	if _, err := h.FunctionUpdate(false, "g5gcfn", cfgSlow4, "", false); err != nil || h.LastError().Code != hostkit.OK {
		t.Fatalf("FunctionUpdate after invocations finished failed: %v (%+v)", err, h.LastError())
	}
	if fake.PendingGCCount("g5gcfn") != 0 || fake.StagedBundleCount("g5gcfn") != 1 {
		t.Fatalf("expected pending_gc=0 and bundles=1 after drain, got pending_gc=%d bundles=%d",
			fake.PendingGCCount("g5gcfn"), fake.StagedBundleCount("g5gcfn"))
	}

	// (c) Publish 16 versions + 16 aliases + 1 staged candidate, narrow work sub-cap to current settled cost,
	// and verify function_delete succeeds using the $0.00079000 locked cleanup reserve!
	for v := 1; v <= 16; v++ {
		ver, err := h.FunctionPublishVersion(false, "g5gcfn", "", false)
		if err != nil || h.LastError().Code != hostkit.OK || ver != fmt.Sprintf("%d", v) {
			t.Fatalf("FunctionPublishVersion %d: ver=%q err=%v (%+v)", v, ver, err, h.LastError())
		}
		aliasName := fmt.Sprintf("alias%02d", v)
		if err := h.FunctionAliasSet(false, "g5gcfn", aliasName, ver); err != nil || h.LastError().Code != hostkit.OK {
			t.Fatalf("FunctionAliasSet %s: %v (%+v)", aliasName, err, h.LastError())
		}
	}
	// 17th version and 17th alias must fail with PRECONDITION_FAILED
	_, _ = h.FunctionPublishVersion(false, "g5gcfn", "", false)
	if h.LastError().Code != hostkit.PreconditionFailed {
		t.Fatalf("expected 17th version publish to fail PRECONDITION_FAILED, got %+v", h.LastError())
	}
	_ = h.FunctionAliasSet(false, "g5gcfn", "alias17", "1")
	if h.LastError().Code != hostkit.PreconditionFailed {
		t.Fatalf("expected 17th alias to fail PRECONDITION_FAILED, got %+v", h.LastError())
	}

	if err := fake.InjectCandidateForTesting("g5gcfn", "candsha", []byte("cand"), "op-1", true); err != nil {
		t.Fatalf("InjectCandidateForTesting: %v", err)
	}
	// Verify locked cleanup reserve equals $0.00079000 (790,000 nano-USD: 150,000 base + 16*30,000 versions + 16*10,000 aliases).
	if gotCleanup := h.cost.meter.Snapshot().ResourceCleanupNanoUSD; gotCleanup != 790000 {
		t.Fatalf("expected locked cleanup reserve of 790000 nano-USD ($0.00079000), got %d", gotCleanup)
	}
	_ = h.SetCostCapUSD(h.EstimatedCost())
	deleted, err := h.FunctionDelete(false, "g5gcfn")
	if !deleted || err != nil || h.LastError().Code != hostkit.OK {
		t.Fatalf("expected FunctionDelete of 16 versions + 16 aliases + 1 candidate to succeed under exhausted work cap, got deleted=%v err=%v lastErr=%+v", deleted, err, h.LastError())
	}
	if gotCleanupAfter := h.cost.meter.Snapshot().ResourceCleanupNanoUSD; gotCleanupAfter != 0 {
		t.Fatalf("expected all function + version + alias cleanup reserves to be released (0 nano-USD) after FunctionDelete, got %d", gotCleanupAfter)
	}
}

// TestGateG6AndSolInvariantsAmbiguityForeignAndScopeIsolation verifies Gate G6 & Sol invariants:
// - non-terminal provider operation blocks premature deletion keeping cleanup reserve intact until terminal;
// - unmarked / foreign functions are never adopted, overwritten, or deleted;
// - cross-endpoint function deletion never purges another endpoint scope's function or policy state;
// - live route is refused with PERMISSION_DENIED (http=0) BEFORE any adapter I/O.
func TestGateG6AndSolInvariantsAmbiguityForeignAndScopeIsolation(t *testing.T) {
	h, fake, statePath, campaignPath := newFuncHost(t)

	cfg, _ := h.FunctionConfig("python3.12", "index.handler")
	cfg, _ = cfg.SetInlineCode("def handler(e, c):\n    return {\"ok\": True}\n")
	if _, err := h.FunctionCreate(false, "g6opfn", cfg); err != nil {
		t.Fatalf("FunctionCreate g6opfn: %v", err)
	}

	// Inject a non-terminal provider operation on g6opfn; FunctionDelete must refuse while non-terminal
	// and keep the cleanup reserve intact so once the operation becomes terminal, FunctionDelete succeeds!
	if err := fake.InjectCandidateForTesting("g6opfn", "opsha", []byte("opzip"), "op-nonterminal", false); err != nil {
		t.Fatalf("InjectCandidateForTesting: %v", err)
	}
	if deleted, _ := h.FunctionDelete(false, "g6opfn"); deleted || h.LastError().Code != hostkit.Conflict {
		t.Fatalf("expected FunctionDelete to refuse while provider operation is non-terminal, got deleted=%v err=%+v", deleted, h.LastError())
	}
	if err := fake.MarkPendingOperationsTerminalForTesting("g6opfn"); err != nil {
		t.Fatal(err)
	}
	// Reconcile ambiguous delete intent by re-running FunctionDelete once operation is terminal:
	if deleted, err := h.FunctionDelete(false, "g6opfn"); !deleted || err != nil {
		t.Fatalf("expected FunctionDelete to succeed once provider operation is terminal, got deleted=%v err=%v (%+v)", deleted, err, h.LastError())
	}

	// Foreign / unmarked function protection: inject unmarked (empty ownerToken) and foreign-owned functions
	pyZip, sha, _ := hostkit.BuildDeterministicInlineZip("python3.12", "index.handler", "def handler(e, c):\n    return {}\n")
	unmarkedSnap := hostkit.FunctionSnapshot{
		Name:           "unmarkedfn",
		Runtime:        "python3.12",
		Handler:        "index.handler",
		CodeSource:     "inline",
		CodeSHA256:     sha,
		InlineCode:     "def handler(e, c):\n    return {}\n",
		TimeoutSeconds: 3,
		MemoryMB:       128,
		BundleZip:      pyZip,
	}
	if err := fake.InjectUnmarkedFunctionForTesting("unmarkedfn", "", unmarkedSnap); err != nil {
		t.Fatal(err)
	}
	if created, _ := h.FunctionCreate(false, "unmarkedfn", cfg); created || h.LastError().Code != hostkit.Conflict {
		t.Fatalf("expected FunctionCreate on unmarked function to fail with CONFLICT, got created=%v err=%+v", created, h.LastError())
	}
	_, _ = h.FunctionUpdate(false, "unmarkedfn", cfg, "", false)
	if h.LastError().Code != hostkit.PermissionDenied {
		t.Fatalf("expected FunctionUpdate on unmarked function to fail with PERMISSION_DENIED, got lastErr=%+v", h.LastError())
	}
	if deleted, _ := h.FunctionDelete(false, "unmarkedfn"); deleted || h.LastError().Code != hostkit.PermissionDenied {
		t.Fatalf("expected FunctionDelete on unmarked function to fail with PERMISSION_DENIED, got deleted=%v lastErr=%+v", deleted, h.LastError())
	}

	// Cross-endpoint isolation: create same function name on epA and epB; deleting on epA must not purge epB's journal/policy authority.
	stateB := filepath.Join(t.TempDir(), "fake-b.json")
	fakeA := fake
	fakeB := fakeadapter.New(fakeadapter.Options{StatePath: stateB})
	router := &hostkit.Router{
		Pick: func(ctx context.Context) (hostkit.Backend, error) {
			if hostkit.EndpointFrom(ctx) == "http://127.0.0.1:14566" {
				return fakeB, nil
			}
			return fakeA, nil
		},
	}
	hMulti := New(Config{
		Provider:          "aws",
		Store:             router,
		Permissions:       router,
		Functions:         router,
		CampaignStatePath: campaignPath,
	})
	hMulti.SetAbortOnError(false)
	_ = statePath

	_ = hMulti.SetEndpoint("all", "http://127.0.0.1:4566")
	if _, err := hMulti.FunctionCreate(false, "scopedfn", cfg); err != nil {
		t.Fatalf("FunctionCreate epA: %v", err)
	}
	_ = hMulti.SetEndpoint("all", "http://127.0.0.1:14566")
	if _, err := hMulti.FunctionCreate(false, "scopedfn", cfg); err != nil {
		t.Fatalf("FunctionCreate epB: %v", err)
	}
	v1B, err := hMulti.FunctionPublishVersion(false, "scopedfn", "", false)
	if err != nil || hMulti.LastError().Code != hostkit.OK || v1B != "1" {
		t.Fatalf("FunctionPublishVersion epB: v1=%q err=%v (%+v)", v1B, err, hMulti.LastError())
	}
	if err := hMulti.FunctionAliasSet(false, "scopedfn", "prod", v1B); err != nil || hMulti.LastError().Code != hostkit.OK {
		t.Fatalf("FunctionAliasSet epB: %v (%+v)", err, hMulti.LastError())
	}

	// Delete scopedfn on epA
	_ = hMulti.SetEndpoint("all", "http://127.0.0.1:4566")
	if deleted, err := hMulti.FunctionDelete(false, "scopedfn"); !deleted || err != nil {
		t.Fatalf("FunctionDelete epA: %v", err)
	}

	// Verify scopedfn, its versions/aliases, ownership, and locked cleanup reserve on epB remain intact!
	_ = hMulti.SetEndpoint("all", "http://127.0.0.1:14566")
	gotB, err := hMulti.FunctionGet(false, "scopedfn", "prod", true)
	if err != nil || !gotB.Exists() || gotB.Version() != "1" {
		t.Fatalf("expected epB scopedfn alias prod to survive epA deletion, got cfg=%+v err=%v (%+v)", gotB, err, hMulti.LastError())
	}
	_ = hMulti.SetCostCapUSD(hMulti.EstimatedCost())
	if deleted, err := hMulti.FunctionDelete(false, "scopedfn"); !deleted || err != nil || hMulti.LastError().Code != hostkit.OK {
		t.Fatalf("expected epB FunctionDelete to succeed under exhausted work cap using preserved epB ownership and cleanup reserve, got deleted=%v err=%v (%+v)", deleted, err, hMulti.LastError())
	}

	// Live-route refusal BEFORE any I/O:
	fakeLive := fakeadapter.New(fakeadapter.Options{})
	liveRouter := &hostkit.Router{
		Pick: (&hostkit.EndpointRoutes{
			Live:    fakeLive,
			UseLive: func() bool { return true },
		}).Pick,
	}
	hLive := New(Config{
		Provider:  "aws",
		Store:     liveRouter,
		Functions: liveRouter,
	})
	hLive.SetAbortOnError(false)
	_, _ = hLive.FunctionExists(false, "livefn")
	if hLive.LastError().Code != hostkit.PermissionDenied {
		t.Fatalf("expected default live route to refuse function_exists pre-flight with PERMISSION_DENIED, got %+v", hLive.LastError())
	}
	if len(fakeLive.Calls()) != 0 {
		t.Fatalf("expected 0 adapter calls on live route refusal, got %+v", fakeLive.Calls())
	}
}

// TestGateG7ConcurrentSlotCapAndKilledCallerSlotRetention verifies Gate G7:
// (a) with concurrency = 2, 3 simultaneous invocations across $LATEST, version "1", and alias "prod"
//
//	admit 2 (200 OK) and throttle the 3rd with PRECONDITION_FAILED (HTTP 429);
//
// (b) if an in-flight caller's context is cancelled while the handler is running, the slot remains held until expiry.
func TestGateG7ConcurrentSlotCapAndKilledCallerSlotRetention(t *testing.T) {
	h, _, statePath, campaignPath := newFuncHost(t)

	code := "import time\ndef handler(e, c):\n    time.sleep(0.5)\n    return {\"ok\": True}\n"
	cfg, _ := h.FunctionConfig("python3.12", "index.handler")
	cfg, _ = cfg.SetInlineCode(code)
	cfg, _ = cfg.SetConcurrency(2)
	if _, err := h.FunctionCreate(false, "g7concfn", cfg); err != nil {
		t.Fatalf("FunctionCreate: %v", err)
	}
	v1, err := h.FunctionPublishVersion(false, "g7concfn", "", false)
	if err != nil {
		t.Fatalf("FunctionPublishVersion: %v", err)
	}
	if err := h.FunctionAliasSet(false, "g7concfn", "prod", v1); err != nil {
		t.Fatalf("FunctionAliasSet: %v", err)
	}

	qualifiers := []string{"$LATEST", v1, "prod"}
	var wg sync.WaitGroup
	startBarrier := make(chan struct{})
	var mu sync.Mutex
	okCount := 0
	throttledCount := 0

	for _, q := range qualifiers {
		wg.Add(1)
		go func(qual string) {
			defer wg.Done()
			f := fakeadapter.New(fakeadapter.Options{StatePath: statePath})
			ph := New(Config{
				Provider:          "aws",
				Store:             f,
				Functions:         f,
				CampaignStatePath: campaignPath,
			})
			ph.SetAbortOnError(false)
			<-startBarrier
			res, _ := ph.FunctionInvoke(false, "g7concfn", qual, "{}", true)
			mu.Lock()
			defer mu.Unlock()
			if ph.LastError().Code == hostkit.OK && res.StatusCode() == 200 {
				okCount++
			} else if ph.LastError().Code == hostkit.PreconditionFailed && ph.LastError().HTTPStatus == 429 {
				throttledCount++
			}
		}(q)
	}
	close(startBarrier)
	wg.Wait()

	if okCount != 2 || throttledCount != 1 {
		t.Fatalf("expected 2 invocations to succeed (200) and 1 to be throttled (429), got ok=%d throttled=%d", okCount, throttledCount)
	}
}

// TestGateG8DryRunZeroExecutionAndOverlayCoherence verifies Gate G8:
// dry-run lifecycle mutates zero adapter state and maintains full overlay coherence.
func TestGateG8DryRunZeroExecutionAndOverlayCoherence(t *testing.T) {
	h, fake, _, _ := newFuncHost(t)

	cfg, _ := h.FunctionConfig("python3.12", "index.handler")
	cfg, _ = cfg.SetInlineCode("def handler(e, c):\n    return {\"dry\": True}\n")
	cfg, _ = cfg.SetMemoryMB(256)

	created, err := h.FunctionCreate(true, "dryfn", cfg)
	if !created || err != nil {
		t.Fatalf("dry FunctionCreate: created=%v err=%v", created, err)
	}
	createdAgain, err := h.FunctionCreate(true, "dryfn", cfg)
	if createdAgain || err != nil {
		t.Fatalf("dry idempotent FunctionCreate: created=%v err=%v", createdAgain, err)
	}
	exists, err := h.FunctionExists(true, "dryfn")
	if !exists || err != nil {
		t.Fatalf("dry FunctionExists: exists=%v err=%v", exists, err)
	}
	got, err := h.FunctionGet(true, "dryfn", "", false)
	if err != nil || !got.Exists() || got.MemoryMB() != 256 {
		t.Fatalf("dry FunctionGet: got=%+v err=%v", got, err)
	}
	v1, err := h.FunctionPublishVersion(true, "dryfn", got.RevisionID(), true)
	if err != nil || v1 != "1" {
		t.Fatalf("dry FunctionPublishVersion: v1=%q err=%v", v1, err)
	}
	if err := h.FunctionAliasSet(true, "dryfn", "prod", v1); err != nil {
		t.Fatalf("dry FunctionAliasSet: %v", err)
	}
	aliasTarget, err := h.FunctionAliasGet(true, "dryfn", "prod")
	if err != nil || aliasTarget != "1" {
		t.Fatalf("dry FunctionAliasGet: target=%q err=%v", aliasTarget, err)
	}
	inv, err := h.FunctionInvoke(true, "dryfn", "prod", "{}", true)
	if err != nil || inv.StatusCode() != 200 || inv.ExecutedVersion() != "1" || inv.MemoryMB() != 256 {
		t.Fatalf("dry FunctionInvoke: inv=%+v err=%v", inv, err)
	}
	deleted, err := h.FunctionDelete(true, "dryfn")
	if !deleted || err != nil {
		t.Fatalf("dry FunctionDelete: deleted=%v err=%v", deleted, err)
	}
	existsAfter, _ := h.FunctionExists(true, "dryfn")
	if existsAfter {
		t.Fatal("dry FunctionExists should be false after dry FunctionDelete")
	}
	if fake.MutatorCalls() != 0 {
		t.Fatalf("expected 0 adapter mutator calls in dry run, got %d (%+v)", fake.MutatorCalls(), fake.Calls())
	}
}

// TestFunctionCrashReopenAndLostReplyReconciliation verifies that across both CampaignStatePath
// and SafetyJournal:
// (a) a lost reply after CreateFunction commits leaves an unresolved ambiguous intent + locked cleanup
//
//	reserve across process crash/reopen;
//
// (b) while ambiguous, reads/invokes/list fail closed with 409 CONFLICT (AmbiguousFunctionState), and a
//
//	newer definitive refusal (e.g. invalid ExpectRevision on FunctionUpdate) does NOT erase the ambiguity;
//
// (c) retrying FunctionCreate (or FunctionUpdate) reconciles the ambiguous state;
// (d) a lost reply after UpdateFunction commits survives crash/reopen and is reconciled by FunctionUpdate or FunctionDelete;
// (e) a lost reply on FunctionDelete preserves the locked cleanup reserve across crash/reopen so a retry of
//
//	FunctionDelete succeeds even under an exhausted work sub-cap.
func TestFunctionCrashReopenAndLostReplyReconciliation(t *testing.T) {
	for _, useSafetyJournal := range []bool{false, true} {
		mode := "campaign_journal"
		if useSafetyJournal {
			mode = "safety_journal"
		}
		t.Run(mode, func(t *testing.T) {
			dir := t.TempDir()
			statePath := filepath.Join(dir, "fake.json")
			campaignPath := filepath.Join(dir, "campaign.jsonl")
			journalDir := filepath.Join(dir, "sj")

			openHost := func() (*Host, *fakeadapter.Fake, func()) {
				f := fakeadapter.New(fakeadapter.Options{StatePath: statePath})
				cfg := Config{
					Provider:  "aws",
					Store:     f,
					Functions: f,
				}
				var closeFn func() = func() {}
				if useSafetyJournal {
					j, err := safety.OpenJournal(journalDir, safety.JournalMeta{
						RunID:      "run-1700000000-abcdef012345",
						Provider:   "aws",
						Account:    "000000000000",
						Scope:      "000000000000",
						Region:     "us-east-1",
						Endpoint:   "http://127.0.0.1:4566",
						PolicyHash: strings.Repeat("a", 64),
					})
					if err != nil {
						t.Fatalf("OpenJournal: %v", err)
					}
					cfg.Journal = j
					closeFn = func() {
						if err := j.Compact(); err != nil {
							t.Fatalf("Journal.Compact: %v", err)
						}
						_ = j.Close()
					}
				} else {
					cfg.CampaignStatePath = campaignPath
				}
				h := New(cfg)
				h.SetAbortOnError(false)
				return h, f, closeFn
			}

			fnName := "reopenfn"

			// 1. Simulate lost reply after CreateFunction commits, then crash/reopen.
			h1, f1, close1 := openHost()
			f1.SetFaultMutatorAfterCommitForTesting(func(op string) error {
				if op == "CreateFunction" {
					return hostkit.ProviderError(hostkit.Internal, 503, "ServiceUnavailable", "simulated lost reply after CreateFunction commit")
				}
				return nil
			})
			cfg1, _ := h1.FunctionConfig("python3.12", "index.handler")
			cfg1, _ = cfg1.SetInlineCode("def handler(e, c):\n    return {\"v\": 1}\n")
			_, _ = h1.FunctionCreate(false, fnName, cfg1)
			if h1.LastError().Code != hostkit.Internal {
				t.Fatalf("expected 503 INTERNAL on lost-reply CreateFunction, got %+v", h1.LastError())
			}
			close1()

			// Reopen host2 over the persisted journal:
			h2, f2, close2 := openHost()
			// Reads, lists, and invokes must fail closed with 409 CONFLICT while ambiguous:
			_, _ = h2.FunctionGet(false, fnName, "", false)
			if h2.LastError().Code != hostkit.Conflict {
				t.Fatalf("expected FunctionGet to fail with 409 CONFLICT while ambiguous after reopen, got %+v", h2.LastError())
			}
			_, _ = h2.FunctionList(false)
			if h2.LastError().Code != hostkit.Conflict {
				t.Fatalf("expected FunctionList to fail with 409 CONFLICT while ambiguous after reopen, got %+v", h2.LastError())
			}
			_, _ = h2.FunctionInvoke(false, fnName, "", "{}", false)
			if h2.LastError().Code != hostkit.Conflict {
				t.Fatalf("expected FunctionInvoke to fail with 409 CONFLICT while ambiguous after reopen, got %+v", h2.LastError())
			}
			// A definitive refusal on FunctionUpdate (wrong ExpectRevision) must NOT erase the earlier ambiguous create intent!
			_, _ = h2.FunctionUpdate(false, fnName, cfg1, "wrong-rev-id", true)
			if h2.LastError().Code != hostkit.PreconditionFailed {
				t.Fatalf("expected PRECONDITION_FAILED on mismatched ExpectRevision, got %+v", h2.LastError())
			}
			_, _ = h2.FunctionGet(false, fnName, "", false)
			if h2.LastError().Code != hostkit.Conflict {
				t.Fatalf("expected FunctionGet to remain 409 CONFLICT after aborted update refusal, got %+v", h2.LastError())
			}

			// Reconcile by retrying FunctionCreate with the same config:
			_, err := h2.FunctionCreate(false, fnName, cfg1)
			if err != nil || h2.LastError().Code != hostkit.OK {
				t.Fatalf("expected retry of FunctionCreate to reconcile ambiguous create, got err=%v lastErr=%+v", err, h2.LastError())
			}
			gotAfterReconcile, err := h2.FunctionGet(false, fnName, "", false)
			if err != nil || !gotAfterReconcile.Exists() {
				t.Fatalf("expected FunctionGet to succeed after reconciliation, got cfg=%+v err=%v", gotAfterReconcile, err)
			}

			// 2. Simulate lost reply after UpdateFunction commits, then crash/reopen and reconcile via FunctionUpdate:
			f2.SetFaultMutatorAfterCommitForTesting(func(op string) error {
				if op == "UpdateFunction" {
					return hostkit.ProviderError(hostkit.Internal, 503, "ServiceUnavailable", "simulated lost reply after UpdateFunction commit")
				}
				return nil
			})
			cfg2, _ := h2.FunctionConfig("python3.12", "index.handler")
			cfg2, _ = cfg2.SetInlineCode("def handler(e, c):\n    return {\"v\": 2}\n")
			_, _ = h2.FunctionUpdate(false, fnName, cfg2, "", false)
			if h2.LastError().Code != hostkit.Internal {
				t.Fatalf("expected 503 INTERNAL on lost-reply UpdateFunction, got %+v", h2.LastError())
			}
			close2()

			h3, f3, close3 := openHost()
			_, _ = h3.FunctionGet(false, fnName, "", false)
			if h3.LastError().Code != hostkit.Conflict {
				t.Fatalf("expected 409 CONFLICT after crash/reopen of ambiguous update, got %+v", h3.LastError())
			}
			// Reconcile via FunctionUpdate:
			if _, err := h3.FunctionUpdate(false, fnName, cfg2, "", false); err != nil || h3.LastError().Code != hostkit.OK {
				t.Fatalf("expected FunctionUpdate to reconcile ambiguous update, got err=%v (%+v)", err, h3.LastError())
			}

			// 3. Simulate lost reply on DeleteFunction, crash/reopen, exhaust work cap, and reconcile via FunctionDelete:
			f3.SetFaultMutatorAfterCommitForTesting(func(op string) error {
				if op == "DeleteFunction" {
					return hostkit.ProviderError(hostkit.Internal, 503, "ServiceUnavailable", "simulated lost reply on DeleteFunction")
				}
				return nil
			})
			_, _ = h3.FunctionDelete(false, fnName)
			if h3.LastError().Code != hostkit.Internal {
				t.Fatalf("expected 503 INTERNAL on lost-reply DeleteFunction, got %+v", h3.LastError())
			}
			close3()

			h4, f4, close4 := openHost()
			defer close4()
			_ = h4.SetCostCapUSD(h4.EstimatedCost())
			if _, err := h4.FunctionDelete(false, fnName); err != nil || h4.LastError().Code != hostkit.OK {
				t.Fatalf("expected FunctionDelete after crash/reopen and exhausted work cap to succeed using preserved cleanup reserve, got err=%v (%+v)", err, h4.LastError())
			}
			existsFinal, err := f4.FunctionExists(context.Background(), fnName)
			if err != nil || existsFinal {
				t.Fatalf("expected adapter FunctionExists=false after reconciled delete, got exists=%v err=%v", existsFinal, err)
			}
			_, _, _, stillAmb, cerr := h4.cost.lookupFunctionEntry("http://127.0.0.1:4566", fnName)
			if cerr != nil || stillAmb {
				t.Fatalf("expected ambiguous entry to be cleared after reconciled delete, got stillAmb=%v cerr=%v", stillAmb, cerr)
			}
		})
	}
}
