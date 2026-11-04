// SPDX-License-Identifier: MIT

package fakeadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/lmctl-ai/lmcloud/hostkit"
)

var (
	sandboxSelfTestMu   sync.Mutex
	sandboxSelfTestDone bool
	sandboxSelfTestErr  error
	cachedPythonBin     string
	cachedNodeBin       string
	cachedNodeRoot      string
	cachedCgroupParent  string
)

const maxScratchTmpBytes = 16 * 1024 * 1024 // 16 MiB

func resolveCgroupParent() (string, error) {
	var candidates []string
	if raw, err := os.ReadFile("/proc/self/cgroup"); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(string(raw)), "\n") {
			parts := strings.SplitN(line, ":", 3)
			if len(parts) == 3 && parts[0] == "0" {
				rel := strings.TrimSpace(parts[2])
				cur := filepath.Clean(filepath.Join("/sys/fs/cgroup", rel))
				for cur != "/sys/fs/cgroup" && cur != "/" && cur != "." {
					candidates = append(candidates, cur)
					cur = filepath.Dir(cur)
				}
			}
		}
	}
	uid := os.Getuid()
	candidates = append(candidates,
		fmt.Sprintf("/sys/fs/cgroup/user.slice/user-%d.slice/user@%d.service", uid, uid),
		fmt.Sprintf("/sys/fs/cgroup/user.slice/user-%d.slice", uid),
	)
	seen := map[string]bool{}
	for _, dir := range candidates {
		if seen[dir] {
			continue
		}
		seen[dir] = true
		subRaw, err := os.ReadFile(filepath.Join(dir, "cgroup.subtree_control"))
		if err != nil {
			continue
		}
		sub := string(subRaw)
		if !strings.Contains(sub, "memory") || !strings.Contains(sub, "pids") {
			continue
		}
		probe, err := os.MkdirTemp(dir, "lmcloud-cgprobe-*.scope")
		if err != nil {
			continue
		}
		err1 := os.WriteFile(filepath.Join(probe, "memory.max"), []byte("134217728"), 0o600)
		err2 := os.WriteFile(filepath.Join(probe, "memory.swap.max"), []byte("0"), 0o600)
		err3 := os.WriteFile(filepath.Join(probe, "pids.max"), []byte("32"), 0o600)
		_ = os.Remove(probe)
		if err1 == nil && err2 == nil && err3 == nil {
			return dir, nil
		}
	}
	return "", fmt.Errorf("no writable cgroup v2 parent with memory and pids controllers found")
}

// Resolve runtime binaries once.
func resolveRuntimeBins() (pyBin, nodeBin, nodeRoot string, err error) {
	pyBin, err = exec.LookPath("python3")
	if err != nil {
		pyBin = "/usr/bin/python3"
	}
	if resolved, lerr := filepath.EvalSymlinks(pyBin); lerr == nil {
		pyBin = resolved
	}
	nodeBin, err = exec.LookPath("node")
	if err != nil {
		// Fallback to common nvm or system locations.
		candidates := []string{
			"/usr/bin/node",
			"/usr/local/bin/node",
		}
		if home, herr := os.UserHomeDir(); herr == nil {
			matches, _ := filepath.Glob(filepath.Join(home, ".nvm/versions/node/*/bin/node"))
			candidates = append(matches, candidates...)
		}
		for _, c := range candidates {
			if st, serr := os.Stat(c); serr == nil && !st.IsDir() {
				nodeBin = c
				err = nil
				break
			}
		}
		if nodeBin == "" {
			return "", "", "", fmt.Errorf("node binary not found in PATH")
		}
	}
	if resolved, lerr := filepath.EvalSymlinks(nodeBin); lerr == nil {
		nodeBin = resolved
	}
	nodeRoot = filepath.Dir(filepath.Dir(nodeBin))
	return pyBin, nodeBin, nodeRoot, nil
}

// ResetSandboxSelfTestForTesting resets the cached startup self-test state.
func ResetSandboxSelfTestForTesting() {
	sandboxSelfTestMu.Lock()
	defer sandboxSelfTestMu.Unlock()
	sandboxSelfTestDone = false
	sandboxSelfTestErr = nil
}

func (f *Fake) ensureSandboxReady() *hostkit.CloudError {
	if f.opts.DisableNamespaceSandbox {
		return hostkit.ProviderError(hostkit.Internal, 0, "SandboxUnavailable",
			"Linux namespace sandbox isolation is disabled or unavailable; failing closed")
	}
	sandboxSelfTestMu.Lock()
	defer sandboxSelfTestMu.Unlock()
	if sandboxSelfTestDone {
		if sandboxSelfTestErr != nil {
			return hostkit.ProviderError(hostkit.Internal, 0, "SandboxSelfTestFailed", sandboxSelfTestErr.Error())
		}
		return nil
	}
	pyBin, nodeBin, nodeRoot, err := resolveRuntimeBins()
	if err != nil {
		sandboxSelfTestDone = true
		sandboxSelfTestErr = err
		return hostkit.ProviderError(hostkit.Internal, 0, "SandboxSelfTestFailed", err.Error())
	}
	cgParent, err := resolveCgroupParent()
	if err != nil {
		sandboxSelfTestDone = true
		sandboxSelfTestErr = err
		return hostkit.ProviderError(hostkit.Internal, 0, "SandboxSelfTestFailed", err.Error())
	}
	cachedPythonBin = pyBin
	cachedNodeBin = nodeBin
	cachedNodeRoot = nodeRoot
	cachedCgroupParent = cgParent

	// Self-test both python3.12 and nodejs20.x at 128 MiB in the namespace + cgroupv2 + Landlock jail,
	// verifying PID 1, rlimits (NOFILE=64, NPROC=32, FSIZE=16MiB), and /etc isolation.
	pyZip, _, cerr := hostkit.BuildDeterministicInlineZip(hostkit.RuntimePython312, "index.handler", `import os, resource
def handler(event, context):
    assert os.getpid() == 1, f"expected pid 1, got {os.getpid()}"
    assert resource.getrlimit(resource.RLIMIT_NOFILE) == (64, 64), f"nofile={resource.getrlimit(resource.RLIMIT_NOFILE)}"
    assert resource.getrlimit(resource.RLIMIT_NPROC) == (32, 32), f"nproc={resource.getrlimit(resource.RLIMIT_NPROC)}"
    assert resource.getrlimit(resource.RLIMIT_FSIZE) == (16777216, 16777216), f"fsize={resource.getrlimit(resource.RLIMIT_FSIZE)}"
    if os.path.isfile("/etc/machine-id"):
        try:
            open("/etc/machine-id").read()
            raise AssertionError("/etc/machine-id should be blocked by Landlock")
        except PermissionError:
            pass
    return {"selftest": True}
`)
	if cerr != nil {
		sandboxSelfTestDone = true
		sandboxSelfTestErr = cerr
		return cerr
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pyOut, _, pyErr := executeInNamespaceJail(ctx, pyBin, nodeBin, nodeRoot, sandboxExecSpec{
		Runtime:        hostkit.RuntimePython312,
		Handler:        "index.handler",
		BundleZip:      pyZip,
		TimeoutSeconds: 5,
		MemoryMB:       128,
		PayloadJSON:    "{}",
	})
	if pyErr != nil || pyOut.FunctionError != "" || !strings.Contains(pyOut.Payload, "true") {
		sandboxSelfTestDone = true
		if pyErr != nil {
			sandboxSelfTestErr = fmt.Errorf("python3.12 sandbox self-test failed: %w", pyErr)
		} else {
			sandboxSelfTestErr = fmt.Errorf("python3.12 sandbox self-test returned error=%q payload=%q", pyOut.FunctionError, pyOut.Payload)
		}
		return hostkit.ProviderError(hostkit.Internal, 0, "SandboxSelfTestFailed", sandboxSelfTestErr.Error())
	}

	jsZip, _, cerr := hostkit.BuildDeterministicInlineZip(hostkit.RuntimeNodeJS20x, "index.handler", `const fs = require("fs");
exports.handler = async (event, context) => {
  try {
    fs.readFileSync("/etc/machine-id");
    throw new Error("/etc/machine-id should be blocked by Landlock");
  } catch (e) {
    if (e.code !== "EACCES" && e.code !== "ENOENT") throw e;
  }
  return { selftest: true };
};
`)
	if cerr != nil {
		sandboxSelfTestDone = true
		sandboxSelfTestErr = cerr
		return cerr
	}
	jsOut, _, jsErr := executeInNamespaceJail(ctx, pyBin, nodeBin, nodeRoot, sandboxExecSpec{
		Runtime:        hostkit.RuntimeNodeJS20x,
		Handler:        "index.handler",
		BundleZip:      jsZip,
		TimeoutSeconds: 5,
		MemoryMB:       128,
		PayloadJSON:    "{}",
	})
	if jsErr != nil || jsOut.FunctionError != "" || !strings.Contains(jsOut.Payload, "true") {
		sandboxSelfTestDone = true
		if jsErr != nil {
			sandboxSelfTestErr = fmt.Errorf("nodejs20.x sandbox self-test failed: %w (logs=%q)", jsErr, jsOut.Logs)
		} else {
			sandboxSelfTestErr = fmt.Errorf("nodejs20.x sandbox self-test returned error=%q payload=%q logs=%q", jsOut.FunctionError, jsOut.Payload, jsOut.Logs)
		}
		return hostkit.ProviderError(hostkit.Internal, 0, "SandboxSelfTestFailed", sandboxSelfTestErr.Error())
	}

	sandboxSelfTestDone = true
	sandboxSelfTestErr = nil
	return nil
}

type sandboxExecSpec struct {
	FunctionName    string
	ExecutedVersion string
	Runtime         string
	Handler         string
	BundleZip       []byte
	TimeoutSeconds  int64
	MemoryMB        int64
	Env             map[string]string
	PayloadJSON     string
}

type boundedLogBuffer struct {
	mu       sync.Mutex
	buf      []byte
	totalCap int
	tailCap  int
	seen     int
}

func newBoundedLogBuffer(totalCap, tailCap int) *boundedLogBuffer {
	return &boundedLogBuffer{
		totalCap: totalCap,
		tailCap:  tailCap,
	}
}

func (b *boundedLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	origLen := len(p)
	if origLen == 0 {
		return 0, nil
	}
	b.seen += origLen
	keepCap := b.tailCap + 16
	if origLen >= keepCap {
		b.buf = append(b.buf[:0], p[origLen-keepCap:]...)
		return origLen, nil
	}
	b.buf = append(b.buf, p...)
	if len(b.buf) > b.tailCap*2 {
		b.buf = append([]byte(nil), b.buf[len(b.buf)-keepCap:]...)
	}
	return origLen, nil
}

func (b *boundedLogBuffer) TailString() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return hostkit.TruncateUTF8LogTail(string(b.buf), b.tailCap)
}

// sandboxLauncherPy runs in a fresh subprocess, unshares CLONE_NEWUSER | CLONE_NEWNS |
// CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC, forks PID 1 in the new PID namespace,
// applies Landlock LSM so only /usr, /lib, /lib64, /bin, /etc, /dev/{null,zero,urandom,random},
// the read-only bundle directory, the ephemeral scratch tmp directory, and (for nodejs20.x)
// the read-only node runtime prefix are accessible (blocking /proc, host /tmp, and /home),
// scrubs os.environ to only the configured user env vars, enforces RLIMIT_NOFILE and memory
// bounds, executes the handler, and writes the structured JSON outcome to fd 3.
const sandboxLauncherPy = `
import ctypes, json, os, resource, signal, subprocess, sys, traceback

libc = ctypes.CDLL("libc.so.6", use_errno=True)
CLONE_NEWNS   = 0x00020000
CLONE_NEWIPC  = 0x08000000
CLONE_NEWUSER = 0x10000000
CLONE_NEWPID  = 0x20000000
CLONE_NEWNET  = 0x40000000

SYS_landlock_create_ruleset = 444
SYS_landlock_add_rule       = 445
SYS_landlock_restrict_self  = 446
PR_SET_PDEATHSIG            = 1
PR_SET_NO_NEW_PRIVS         = 38
O_PATH                      = 0o10000000
O_CLOEXEC                   = 0o2000000
LANDLOCK_RULE_PATH_BENEATH  = 1

class RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]

class PathBeneathAttr(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]

def write_outcome(fd, obj):
    raw = json.dumps(obj, ensure_ascii=False).encode("utf-8")
    view = memoryview(raw)
    while len(view) > 0:
        n = os.write(fd, view)
        view = view[n:]

def apply_landlock(bundle_dir, scratch_tmp, extra_ro):
    abi = libc.syscall(SYS_landlock_create_ruleset, None, 0, 1)
    if abi < 1:
        raise RuntimeError(f"Landlock ABI unavailable: {abi} errno={ctypes.get_errno()}")
    mask = (1 << 13) - 1
    if abi >= 2:
        mask |= (1 << 13)
    if abi >= 3:
        mask |= (1 << 14)
    attr = RulesetAttr(handled_access_fs=mask)
    rfd = libc.syscall(SYS_landlock_create_ruleset, ctypes.byref(attr), ctypes.sizeof(attr), 0)
    if rfd < 0:
        raise RuntimeError(f"landlock_create_ruleset failed: errno={ctypes.get_errno()}")
    def allow(path, writable=False):
        if not path or not os.path.exists(path):
            return
        fd = os.open(path, O_PATH | O_CLOEXEC)
        try:
            ro = (1 << 0) | (1 << 2) | (1 << 3)
            acc = mask if writable else ro
            if not os.path.isdir(path):
                fmask = (1 << 0) | (1 << 1) | (1 << 2) | ((1 << 14) if abi >= 3 else 0)
                acc &= fmask
            pb = PathBeneathAttr(allowed_access=acc, parent_fd=fd)
            rc = libc.syscall(SYS_landlock_add_rule, rfd, LANDLOCK_RULE_PATH_BENEATH, ctypes.byref(pb), 0)
            if rc != 0:
                raise RuntimeError(f"landlock_add_rule({path}) failed: errno={ctypes.get_errno()}")
        finally:
            os.close(fd)
    for p in ["/usr", "/lib", "/lib64", "/bin", "/dev/null", "/dev/zero", "/dev/urandom", "/dev/random", bundle_dir]:
        allow(p, False)
    if extra_ro:
        allow(extra_ro, False)
    allow(scratch_tmp, True)
    if libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise RuntimeError("prctl(PR_SET_NO_NEW_PRIVS) failed")
    if libc.syscall(SYS_landlock_restrict_self, rfd, 0) != 0:
        raise RuntimeError(f"landlock_restrict_self failed: errno={ctypes.get_errno()}")
    os.close(rfd)

def main():
    out_fd = os.dup(3)
    os.close(3)
    os.set_inheritable(out_fd, True)
    spec_raw = sys.stdin.buffer.read()
    spec = json.loads(spec_raw.decode("utf-8"))

    rc = libc.unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC)
    if rc != 0:
        write_outcome(out_fd, {"internalError": f"unshare failed: errno={ctypes.get_errno()}"})
        os._exit(2)

    pid = os.fork()
    if pid > 0:
        os.close(out_fd)
        def forward_kill(signum, _frame):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        signal.signal(signal.SIGTERM, forward_kill)
        signal.signal(signal.SIGINT, forward_kill)
        _, status = os.waitpid(pid, 0)
        os._exit(0)

    # Inside child: PID 1 of the isolated PID namespace!
    libc.prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0)
    if os.getpid() != 1:
        write_outcome(out_fd, {"internalError": f"expected PID 1 in PID namespace, got {os.getpid()}"})
        os._exit(2)

    cg_procs = spec.get("cgroup_procs_path", "")
    if cg_procs:
        try:
            with open(cg_procs, "w") as f:
                f.write("0")
        except Exception as e:
            write_outcome(out_fd, {"internalError": f"cgroup join failed: {e}"})
            os._exit(2)

    bundle_dir = spec["bundle_dir"]
    scratch_tmp = spec["scratch_tmp"]
    runtime = spec["runtime"]
    handler = spec["handler"]
    mem_mb = int(spec["memory_mb"])
    user_env = spec.get("env") or {}
    payload_json = spec["payload_json"]
    node_bin = spec.get("node_bin", "")
    node_root = spec.get("node_root", "")

    in_fd = -1
    if runtime == "nodejs20.x":
        try:
            in_fd = os.memfd_create("lmcloud_payload", 0)
            raw_pay = payload_json.encode("utf-8")
            view = memoryview(raw_pay)
            while len(view) > 0:
                n = os.write(in_fd, view)
                view = view[n:]
            os.lseek(in_fd, 0, os.SEEK_SET)
            os.set_inheritable(in_fd, True)
        except Exception as e:
            write_outcome(out_fd, {"internalError": f"payload memfd setup failed: {e}"})
            os._exit(2)

    try:
        apply_landlock(bundle_dir, scratch_tmp, node_root if runtime == "nodejs20.x" else "")
    except Exception as e:
        write_outcome(out_fd, {"internalError": f"sandbox setup failed: {e}"})
        os._exit(2)

    try:
        signal.signal(signal.SIGXFSZ, signal.SIG_IGN)
        resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        resource.setrlimit(resource.RLIMIT_FSIZE, (16 * 1024 * 1024, 16 * 1024 * 1024))
    except Exception as e:
        write_outcome(out_fd, {"internalError": f"rlimit setup failed: {e}"})
        os._exit(2)

    clean_env = {
        "PATH": "/usr/bin:/bin",
        "HOME": scratch_tmp,
        "TMPDIR": scratch_tmp,
        "LANG": "C.UTF-8",
        "PYTHONDONTWRITEBYTECODE": "1",
    }
    for k, v in user_env.items():
        clean_env[str(k)] = str(v)

    os.chdir(bundle_dir)
    mod_name, func_name = handler.split(".", 1)

    if runtime == "python3.12":
        os.environ.clear()
        os.environ.update(clean_env)
        sys.path[:] = [bundle_dir] + [p for p in sys.path if p.startswith("/usr") or p.startswith("/lib")]
        mem_bytes = mem_mb * 1024 * 1024
        try:
            resource.setrlimit(resource.RLIMIT_NPROC, (32, 32))
            resource.setrlimit(resource.RLIMIT_DATA, (mem_bytes, mem_bytes))
        except Exception as e:
            write_outcome(out_fd, {"internalError": f"python rlimit setup failed: {e}"})
            os._exit(2)
        try:
            event_val = json.loads(payload_json)
            import importlib
            mod = importlib.import_module(mod_name)
            fn = getattr(mod, func_name)
            res = fn(event_val, {"function_name": spec.get("function_name", ""), "memory_limit_in_mb": mem_mb})
            sys.stdout.flush()
            sys.stderr.flush()
            ru_kb = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
            if ru_kb * 1024 > mem_bytes:
                write_outcome(out_fd, {
                    "ok": False,
                    "functionError": "Unhandled",
                    "payload": json.dumps({"errorType": "OutOfMemory", "errorMessage": "function execution exceeded memory_mb limit"}),
                })
                os._exit(0)
            res_json = json.dumps(res, ensure_ascii=False)
            res_bytes = res_json.encode("utf-8")
            if len(res_bytes) > 1048576:
                write_outcome(out_fd, {
                    "ok": False,
                    "functionError": "Unhandled",
                    "payload": json.dumps({"errorType": "ResponseSizeExceeded", "errorMessage": "function response payload exceeded 1048576 bytes"}),
                })
                os._exit(0)
            write_outcome(out_fd, {"ok": True, "payload": res_json})
        except MemoryError as me:
            sys.stdout.flush()
            sys.stderr.flush()
            write_outcome(out_fd, {
                "ok": False,
                "functionError": "Unhandled",
                "payload": json.dumps({"errorType": "MemoryError", "errorMessage": str(me) or "out of memory"}),
            })
        except BaseException as ex:
            sys.stdout.flush()
            sys.stderr.flush()
            traceback.print_exc(file=sys.stderr)
            sys.stderr.flush()
            write_outcome(out_fd, {
                "ok": False,
                "functionError": "Handled",
                "payload": json.dumps({"errorType": type(ex).__name__, "errorMessage": str(ex)}),
            })
        os._exit(0)
    elif runtime == "nodejs20.x":
        heap_mb = max(48, mem_mb - 32)
        node_runner = """
const fs = require("fs");
const path = require("path");
const v8 = require("v8");
(async () => {
  const outFd = parseInt(process.env.__LMCLOUD_OUT_FD, 10);
  const inFd = parseInt(process.env.__LMCLOUD_IN_FD, 10);
  const memMB = parseInt(process.env.__LMCLOUD_MEM_MB, 10);
  const modName = process.env.__LMCLOUD_MOD;
  const fnName = process.env.__LMCLOUD_FN;
  if (process.env.__LMCLOUD_DROP_OPENSSL_CONF === "1") {
    delete process.env.OPENSSL_CONF;
  }
  delete process.env.__LMCLOUD_DROP_OPENSSL_CONF;
  delete process.env.__LMCLOUD_OUT_FD;
  delete process.env.__LMCLOUD_IN_FD;
  delete process.env.__LMCLOUD_MEM_MB;
  delete process.env.__LMCLOUD_MOD;
  delete process.env.__LMCLOUD_FN;
  const payloadRaw = fs.readFileSync(inFd, "utf8");
  try { fs.closeSync(inFd); } catch (_) {}
  const writeOut = (obj) => {
    fs.writeFileSync(outFd, Buffer.from(JSON.stringify(obj), "utf8"));
  };
  const memLimitBytes = memMB * 1024 * 1024;
  const checkMemExceeded = () => {
    const hs = v8.getHeapStatistics();
    return (hs.total_physical_size + hs.external_memory + hs.malloced_memory) > memLimitBytes;
  };
  const memTimer = setInterval(() => {
    if (checkMemExceeded()) {
      try {
        writeOut({
          ok: false,
          functionError: "Unhandled",
          payload: JSON.stringify({ errorType: "OutOfMemory", errorMessage: "function execution exceeded memory_mb limit" })
        });
      } catch (_) {}
      process.exit(0);
    }
  }, 5);
  memTimer.unref();
  try {
    const event = JSON.parse(payloadRaw);
    const modPath = path.resolve(process.cwd(), modName);
    const mod = require(modPath);
    const fn = mod[fnName];
    if (typeof fn !== "function") {
      throw new Error("Handler " + modName + "." + fnName + " is not a function");
    }
    const res = await fn(event, { functionName: "", memoryLimitInMB: String(memMB) });
    if (checkMemExceeded()) {
      writeOut({
        ok: false,
        functionError: "Unhandled",
        payload: JSON.stringify({ errorType: "OutOfMemory", errorMessage: "function execution exceeded memory_mb limit" })
      });
      process.exit(0);
    }
    const resJson = JSON.stringify(res === undefined ? null : res);
    if (Buffer.byteLength(resJson, "utf8") > 1048576) {
      writeOut({
        ok: false,
        functionError: "Unhandled",
        payload: JSON.stringify({ errorType: "ResponseSizeExceeded", errorMessage: "function response payload exceeded 1048576 bytes" })
      });
      process.exit(0);
    }
    writeOut({ ok: true, payload: resJson });
  } catch (err) {
    const errType = (err && err.name) ? String(err.name) : "Error";
    const errMsg = (err && err.message) ? String(err.message) : String(err);
    console.error(err && err.stack ? err.stack : errMsg);
    writeOut({
      ok: false,
      functionError: "Handled",
      payload: JSON.stringify({ errorType: errType, errorMessage: errMsg })
    });
  }
})();
"""
        if "OPENSSL_CONF" not in user_env:
            clean_env["OPENSSL_CONF"] = "/dev/null"
            clean_env["__LMCLOUD_DROP_OPENSSL_CONF"] = "1"
        clean_env["__LMCLOUD_OUT_FD"] = str(out_fd)
        clean_env["__LMCLOUD_IN_FD"] = str(in_fd)
        clean_env["__LMCLOUD_MEM_MB"] = str(mem_mb)
        clean_env["__LMCLOUD_MOD"] = mod_name
        clean_env["__LMCLOUD_FN"] = func_name
        os.execve(node_bin, [node_bin, f"--max-old-space-size={heap_mb}", "-e", node_runner], clean_env)
    else:
        write_outcome(out_fd, {"internalError": f"unsupported runtime {runtime}"})
        os._exit(2)

if __name__ == "__main__":
    main()
`

type sandboxOutcome struct {
	OK            bool   `json:"ok"`
	FunctionError string `json:"functionError"`
	Payload       string `json:"payload"`
	InternalError string `json:"internalError"`
}

func scratchDirBytes(dir string) int64 {
	var total int64
	_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d == nil || d.IsDir() {
			return nil
		}
		if info, ierr := d.Info(); ierr == nil {
			total += info.Size()
		}
		return nil
	})
	return total
}

func cgroupHadOOM(cgDir string) bool {
	if cgDir == "" {
		return false
	}
	raw, err := os.ReadFile(filepath.Join(cgDir, "memory.events"))
	if err != nil {
		return false
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && (fields[0] == "oom" || fields[0] == "oom_kill" || fields[0] == "oom_group_kill") {
			if n, perr := strconv.ParseInt(fields[1], 10, 64); perr == nil && n > 0 {
				return true
			}
		}
	}
	return false
}

func cleanupCgroupDir(cgDir string) {
	if cgDir == "" {
		return
	}
	_ = os.WriteFile(filepath.Join(cgDir, "cgroup.kill"), []byte("1"), 0o600)
	deadline := time.Now().Add(200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if os.Remove(cgDir) == nil {
			return
		}
		_ = os.WriteFile(filepath.Join(cgDir, "cgroup.kill"), []byte("1"), 0o600)
		time.Sleep(2 * time.Millisecond)
	}
	_ = os.Remove(cgDir)
}

// collectDescendantPIDs returns all host PIDs in the process tree rooted at rootPID
// alongside the cumulative resident set size (VmRSS) in bytes across the tree.
func collectProcessTreeAndRSS(rootPID int) (pids []int, totalRSSBytes int64) {
	queue := []int{rootPID}
	seen := map[int]bool{rootPID: true}
	pageSize := int64(os.Getpagesize())
	for len(queue) > 0 {
		curr := queue[0]
		queue = queue[1:]
		pids = append(pids, curr)

		statmPath := fmt.Sprintf("/proc/%d/statm", curr)
		if raw, err := os.ReadFile(statmPath); err == nil {
			fields := strings.Fields(string(raw))
			if len(fields) >= 2 {
				if rssPages, perr := strconv.ParseInt(fields[1], 10, 64); perr == nil && rssPages > 0 {
					totalRSSBytes += rssPages * pageSize
				}
			}
		}

		childrenGlob := fmt.Sprintf("/proc/%d/task/*/children", curr)
		matches, _ := filepath.Glob(childrenGlob)
		for _, m := range matches {
			raw, err := os.ReadFile(m)
			if err != nil {
				continue
			}
			for _, tok := range strings.Fields(string(raw)) {
				if childPID, cerr := strconv.Atoi(tok); cerr == nil && childPID > 0 && !seen[childPID] {
					seen[childPID] = true
					queue = append(queue, childPID)
				}
			}
		}
	}
	return pids, totalRSSBytes
}

func waitForPIDsGone(pids []int, maxWait time.Duration) {
	deadline := time.Now().Add(maxWait)
	for time.Now().Before(deadline) {
		alive := false
		for _, pid := range pids {
			if pid <= 1 {
				continue
			}
			err := syscall.Kill(pid, 0)
			if err == nil || errors.Is(err, syscall.EPERM) {
				// Also check if zombie in /proc/<pid>/stat
				if raw, rerr := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid)); rerr == nil {
					if !strings.Contains(string(raw), ") Z ") {
						alive = true
						break
					}
				}
			}
		}
		if !alive {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func executeInNamespaceJail(ctx context.Context, pyBin, nodeBin, nodeRoot string, spec sandboxExecSpec) (hostkit.FunctionInvokeOutput, []int, *hostkit.CloudError) {
	cgParent := cachedCgroupParent
	if cgParent == "" {
		var cgErr error
		cgParent, cgErr = resolveCgroupParent()
		if cgErr != nil {
			return hostkit.FunctionInvokeOutput{}, nil, hostkit.ProviderError(hostkit.Internal, 0, "SandboxCgroupUnavailable", cgErr.Error())
		}
	}
	cgDir, err := os.MkdirTemp(cgParent, "lmcloud-fn-*.scope")
	if err != nil {
		return hostkit.FunctionInvokeOutput{}, nil, hostkit.ProviderError(hostkit.Internal, 0, "SandboxCgroupFailed", err.Error())
	}
	defer cleanupCgroupDir(cgDir)

	memLimitBytes := spec.MemoryMB * 1024 * 1024
	if memLimitBytes <= 0 {
		memLimitBytes = 128 * 1024 * 1024
	}
	if err := os.WriteFile(filepath.Join(cgDir, "memory.max"), []byte(strconv.FormatInt(memLimitBytes, 10)), 0o600); err != nil {
		return hostkit.FunctionInvokeOutput{}, nil, hostkit.ProviderError(hostkit.Internal, 0, "SandboxCgroupFailed", err.Error())
	}
	if err := os.WriteFile(filepath.Join(cgDir, "memory.swap.max"), []byte("0"), 0o600); err != nil {
		return hostkit.FunctionInvokeOutput{}, nil, hostkit.ProviderError(hostkit.Internal, 0, "SandboxCgroupFailed", err.Error())
	}
	_ = os.WriteFile(filepath.Join(cgDir, "memory.oom.group"), []byte("1"), 0o600)
	if err := os.WriteFile(filepath.Join(cgDir, "pids.max"), []byte("32"), 0o600); err != nil {
		return hostkit.FunctionInvokeOutput{}, nil, hostkit.ProviderError(hostkit.Internal, 0, "SandboxCgroupFailed", err.Error())
	}

	sandboxRoot, err := os.MkdirTemp("", "lmcloud-fn-*")
	if err != nil {
		return hostkit.FunctionInvokeOutput{}, nil, hostkit.ProviderError(hostkit.Internal, 0, "SandboxTempDirFailed", err.Error())
	}
	defer os.RemoveAll(sandboxRoot)
	_ = os.Chmod(sandboxRoot, 0o700)

	bundleDir := filepath.Join(sandboxRoot, "task")
	scratchTmp := filepath.Join(sandboxRoot, "tmp")
	if err := os.MkdirAll(bundleDir, 0o700); err != nil {
		return hostkit.FunctionInvokeOutput{}, nil, hostkit.ProviderError(hostkit.Internal, 0, "SandboxTempDirFailed", err.Error())
	}
	if err := os.MkdirAll(scratchTmp, 0o700); err != nil {
		return hostkit.FunctionInvokeOutput{}, nil, hostkit.ProviderError(hostkit.Internal, 0, "SandboxTempDirFailed", err.Error())
	}
	if cerr := hostkit.ExtractCanonicalZip(spec.BundleZip, bundleDir); cerr != nil {
		return hostkit.FunctionInvokeOutput{}, nil, cerr
	}

	resR, resW, err := os.Pipe()
	if err != nil {
		return hostkit.FunctionInvokeOutput{}, nil, hostkit.ProviderError(hostkit.Internal, 0, "SandboxPipeFailed", err.Error())
	}
	defer resR.Close()

	launcherInput := map[string]any{
		"function_name":     spec.FunctionName,
		"runtime":           spec.Runtime,
		"handler":           spec.Handler,
		"bundle_dir":        bundleDir,
		"scratch_tmp":       scratchTmp,
		"memory_mb":         spec.MemoryMB,
		"env":               spec.Env,
		"payload_json":      spec.PayloadJSON,
		"node_bin":          nodeBin,
		"node_root":         nodeRoot,
		"cgroup_procs_path": filepath.Join(cgDir, "cgroup.procs"),
	}
	inputBytes, _ := json.Marshal(launcherInput)

	timeoutDur := time.Duration(spec.TimeoutSeconds) * time.Second
	if timeoutDur <= 0 {
		timeoutDur = 3 * time.Second
	}
	execCtx, cancel := context.WithTimeout(ctx, timeoutDur)
	defer cancel()

	cmd := exec.Command(pyBin, "-I", "-B", "-c", sandboxLauncherPy)
	cmd.Stdin = bytes.NewReader(inputBytes)
	logBuf := newBoundedLogBuffer(64*1024, hostkit.MaxFunctionLogBytes)
	cmd.Stdout = logBuf
	cmd.Stderr = logBuf
	cmd.ExtraFiles = []*os.File{resW}
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C.UTF-8"}
	cmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid:   true,
		Pdeathsig: syscall.SIGKILL,
	}

	start := time.Now()
	if err := cmd.Start(); err != nil {
		_ = resW.Close()
		return hostkit.FunctionInvokeOutput{}, nil, hostkit.ProviderError(hostkit.Internal, 0, "SandboxStartFailed", err.Error())
	}
	_ = resW.Close()

	rootPID := cmd.Process.Pid
	var (
		monMu           sync.Mutex
		observedPIDs    = map[int]bool{rootPID: true}
		killedForMemory bool
		killedForDisk   bool
		killedForTime   bool
	)

	// Read outcome from fd 3 with N+1 sentinel bound (MaxFunctionResponseBytes + 4096 envelope).
	type readResult struct {
		data []byte
		err  error
	}
	readCh := make(chan readResult, 1)
	go func() {
		data, rerr := io.ReadAll(io.LimitReader(resR, hostkit.MaxFunctionResponseBytes+4096))
		readCh <- readResult{data: data, err: rerr}
	}()

	waitCh := make(chan error, 1)
	go func() {
		waitCh <- cmd.Wait()
	}()

	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()

	done := false
	for !done {
		select {
		case <-waitCh:
			done = true
		case <-execCtx.Done():
			monMu.Lock()
			if errors.Is(execCtx.Err(), context.DeadlineExceeded) {
				killedForTime = true
			}
			pids, _ := collectProcessTreeAndRSS(rootPID)
			for _, p := range pids {
				observedPIDs[p] = true
			}
			monMu.Unlock()
			_ = os.WriteFile(filepath.Join(cgDir, "cgroup.kill"), []byte("1"), 0o600)
			_ = syscall.Kill(-rootPID, syscall.SIGKILL)
			_ = cmd.Process.Kill()
			<-waitCh
			done = true
		case <-ticker.C:
			pids, rss := collectProcessTreeAndRSS(rootPID)
			diskBytes := scratchDirBytes(scratchTmp)
			monMu.Lock()
			for _, p := range pids {
				observedPIDs[p] = true
			}
			if diskBytes > maxScratchTmpBytes {
				killedForDisk = true
				monMu.Unlock()
				_ = os.WriteFile(filepath.Join(cgDir, "cgroup.kill"), []byte("1"), 0o600)
				_ = syscall.Kill(-rootPID, syscall.SIGKILL)
				_ = cmd.Process.Kill()
				<-waitCh
				done = true
				continue
			}
			// Allow 36 MiB interpreter shared-library overhead on top of spec.MemoryMB for the outer+inner processes.
			if rss > memLimitBytes+(36*1024*1024) || cgroupHadOOM(cgDir) {
				killedForMemory = true
				monMu.Unlock()
				_ = os.WriteFile(filepath.Join(cgDir, "cgroup.kill"), []byte("1"), 0o600)
				_ = syscall.Kill(-rootPID, syscall.SIGKILL)
				_ = cmd.Process.Kill()
				<-waitCh
				done = true
				continue
			}
			monMu.Unlock()
		}
	}

	elapsed := time.Since(start)
	_ = os.WriteFile(filepath.Join(cgDir, "cgroup.kill"), []byte("1"), 0o600)
	_ = syscall.Kill(-rootPID, syscall.SIGKILL)

	monMu.Lock()
	allPIDs := make([]int, 0, len(observedPIDs))
	for p := range observedPIDs {
		allPIDs = append(allPIDs, p)
	}
	isTimeout := killedForTime
	isOOM := killedForMemory || cgroupHadOOM(cgDir)
	isDiskQuota := killedForDisk || scratchDirBytes(scratchTmp) > maxScratchTmpBytes
	monMu.Unlock()

	waitForPIDsGone(allPIDs, 500*time.Millisecond)
	rr := <-readCh

	if ctx.Err() != nil && !isTimeout {
		return hostkit.FunctionInvokeOutput{}, allPIDs, hostkit.ProviderError(hostkit.Internal, 0, "InvokeContextCancelled", ctx.Err().Error())
	}

	billedMS := int64(math.Ceil(float64(elapsed.Nanoseconds()) / 1e6))
	if billedMS < 1 {
		billedMS = 1
	}
	maxBilled := spec.TimeoutSeconds * 1000
	if billedMS > maxBilled {
		billedMS = maxBilled
	}

	if isTimeout {
		return hostkit.FunctionInvokeOutput{
			StatusCode:      200,
			Payload:         `{"errorType":"Timeout","errorMessage":"Task timed out"}`,
			Logs:            logBuf.TailString(),
			FunctionError:   "Timeout",
			ExecutedVersion: spec.ExecutedVersion,
			BilledMS:        maxBilled,
			TimeoutSeconds:  spec.TimeoutSeconds,
			MemoryMB:        spec.MemoryMB,
		}, allPIDs, nil
	}

	if isOOM {
		return hostkit.FunctionInvokeOutput{
			StatusCode:      200,
			Payload:         `{"errorType":"OutOfMemory","errorMessage":"function execution exceeded memory_mb limit"}`,
			Logs:            logBuf.TailString(),
			FunctionError:   "Unhandled",
			ExecutedVersion: spec.ExecutedVersion,
			BilledMS:        billedMS,
			TimeoutSeconds:  spec.TimeoutSeconds,
			MemoryMB:        spec.MemoryMB,
		}, allPIDs, nil
	}

	if isDiskQuota {
		return hostkit.FunctionInvokeOutput{
			StatusCode:      200,
			Payload:         `{"errorType":"DiskQuotaExceeded","errorMessage":"function scratch directory exceeded 16 MiB limit"}`,
			Logs:            logBuf.TailString(),
			FunctionError:   "Unhandled",
			ExecutedVersion: spec.ExecutedVersion,
			BilledMS:        billedMS,
			TimeoutSeconds:  spec.TimeoutSeconds,
			MemoryMB:        spec.MemoryMB,
		}, allPIDs, nil
	}

	if len(rr.data) == 0 {
		return hostkit.FunctionInvokeOutput{
			StatusCode:      200,
			Payload:         `{"errorType":"RuntimeExitError","errorMessage":"function process exited without returning a payload"}`,
			Logs:            logBuf.TailString(),
			FunctionError:   "Unhandled",
			ExecutedVersion: spec.ExecutedVersion,
			BilledMS:        billedMS,
			TimeoutSeconds:  spec.TimeoutSeconds,
			MemoryMB:        spec.MemoryMB,
		}, allPIDs, nil
	}

	if len(rr.data) > hostkit.MaxFunctionResponseBytes+2048 {
		return hostkit.FunctionInvokeOutput{
			StatusCode:      200,
			Payload:         `{"errorType":"ResponseSizeExceeded","errorMessage":"function response payload exceeded 1048576 bytes"}`,
			Logs:            logBuf.TailString(),
			FunctionError:   "Unhandled",
			ExecutedVersion: spec.ExecutedVersion,
			BilledMS:        billedMS,
			TimeoutSeconds:  spec.TimeoutSeconds,
			MemoryMB:        spec.MemoryMB,
		}, allPIDs, nil
	}

	var outcome sandboxOutcome
	if err := json.Unmarshal(rr.data, &outcome); err != nil {
		return hostkit.FunctionInvokeOutput{
			StatusCode:      200,
			Payload:         `{"errorType":"MalformedRuntimeOutput","errorMessage":"function returned invalid JSON envelope"}`,
			Logs:            logBuf.TailString(),
			FunctionError:   "Unhandled",
			ExecutedVersion: spec.ExecutedVersion,
			BilledMS:        billedMS,
			TimeoutSeconds:  spec.TimeoutSeconds,
			MemoryMB:        spec.MemoryMB,
		}, allPIDs, nil
	}

	if outcome.InternalError != "" {
		return hostkit.FunctionInvokeOutput{}, allPIDs, hostkit.ProviderError(hostkit.Internal, 0, "SandboxInternalError", outcome.InternalError)
	}

	if len(outcome.Payload) > hostkit.MaxFunctionResponseBytes {
		return hostkit.FunctionInvokeOutput{
			StatusCode:      200,
			Payload:         `{"errorType":"ResponseSizeExceeded","errorMessage":"function response payload exceeded 1048576 bytes"}`,
			Logs:            logBuf.TailString(),
			FunctionError:   "Unhandled",
			ExecutedVersion: spec.ExecutedVersion,
			BilledMS:        billedMS,
			TimeoutSeconds:  spec.TimeoutSeconds,
			MemoryMB:        spec.MemoryMB,
		}, allPIDs, nil
	}

	if !outcome.OK {
		fe := outcome.FunctionError
		if fe == "" {
			fe = "Unhandled"
		}
		return hostkit.FunctionInvokeOutput{
			StatusCode:      200,
			Payload:         outcome.Payload,
			Logs:            logBuf.TailString(),
			FunctionError:   fe,
			ExecutedVersion: spec.ExecutedVersion,
			BilledMS:        billedMS,
			TimeoutSeconds:  spec.TimeoutSeconds,
			MemoryMB:        spec.MemoryMB,
		}, allPIDs, nil
	}

	return hostkit.FunctionInvokeOutput{
		StatusCode:      200,
		Payload:         outcome.Payload,
		Logs:            logBuf.TailString(),
		FunctionError:   "",
		ExecutedVersion: spec.ExecutedVersion,
		BilledMS:        billedMS,
		TimeoutSeconds:  spec.TimeoutSeconds,
		MemoryMB:        spec.MemoryMB,
	}, allPIDs, nil
}
