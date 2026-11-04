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

	// Self-test both python3.12 and nodejs20.x at 128 MiB in the namespace + cgroupv2 + Landlock + seccomp jail,
	// verifying PID 1, rlimits (NOFILE=64, NPROC=32, FSIZE=16MiB), /etc isolation, and synchronous aggregate
	// 16-MiB scratch quota across open-unlinked files.
	pyZip, _, cerr := hostkit.BuildDeterministicInlineZip(hostkit.RuntimePython312, "index.handler", `import errno, os, resource
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
    td = os.environ.get("TMPDIR", "/tmp")
    chunk = b"x" * (1024 * 1024)
    f1 = open(os.path.join(td, "unlinked_1.bin"), "wb+")
    os.unlink(f1.name)
    f2 = open(os.path.join(td, "unlinked_2.bin"), "wb+")
    os.unlink(f2.name)
    try:
        for _ in range(10):
            f1.write(chunk)
            f1.flush()
        blocked = False
        try:
            for _ in range(10):
                f2.write(chunk)
                f2.flush()
        except OSError as e:
            if e.errno in (errno.ENOSPC, errno.EFBIG, errno.EDQUOT, errno.EPERM):
                blocked = True
            else:
                raise
        assert blocked, "expected aggregate 16-MiB scratch quota to reject 20 MiB across open-unlinked files"
    finally:
        f1.close()
        f2.close()
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
import ctypes, errno, json, os, resource, select, signal, socket, stat, struct, subprocess, sys, time, traceback

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

MAX_SCRATCH_BYTES                  = 16 * 1024 * 1024
SECCOMP_SET_MODE_FILTER            = 1
SECCOMP_FILTER_FLAG_NEW_LISTENER   = (1 << 3)
SECCOMP_RET_USER_NOTIF             = 0x7fc00000
SECCOMP_RET_ALLOW                  = 0x7fff0000
SECCOMP_IOCTL_NOTIF_RECV           = 0xc0502100
SECCOMP_IOCTL_NOTIF_SEND           = 0xc0182101
SECCOMP_USER_NOTIF_FLAG_CONTINUE   = 1

_ARCH = os.uname().machine
if _ARCH in ("aarch64", "arm64"):
    SYS_seccomp         = 277
    SYS_truncate        = 45
    SYS_ftruncate       = 46
    SYS_fallocate       = 47
    SYS_write           = 64
    SYS_writev          = 66
    SYS_pwrite64        = 68
    SYS_pwritev         = 70
    SYS_sendfile        = 71
    SYS_splice          = 76
    SYS_copy_file_range = 285
    SYS_pwritev2        = 287
elif _ARCH in ("x86_64", "amd64"):
    SYS_seccomp         = 317
    SYS_write           = 1
    SYS_pwrite64        = 18
    SYS_writev          = 20
    SYS_sendfile        = 40
    SYS_truncate        = 76
    SYS_ftruncate       = 77
    SYS_splice          = 275
    SYS_fallocate       = 285
    SYS_pwritev         = 296
    SYS_copy_file_range = 326
    SYS_pwritev2        = 328
else:
    SYS_seccomp = -1

class RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]

class PathBeneathAttr(ctypes.Structure):
    _pack_ = 1
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]

class SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint16),
        ("jt", ctypes.c_uint8),
        ("jf", ctypes.c_uint8),
        ("k", ctypes.c_uint32),
    ]

class SockFprog(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_uint16),
        ("filter", ctypes.POINTER(SockFilter)),
    ]

class SeccompData(ctypes.Structure):
    _fields_ = [
        ("nr", ctypes.c_int),
        ("arch", ctypes.c_uint32),
        ("instruction_pointer", ctypes.c_uint64),
        ("args", ctypes.c_uint64 * 6),
    ]

class SeccompNotif(ctypes.Structure):
    _fields_ = [
        ("id", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("flags", ctypes.c_uint32),
        ("data", SeccompData),
    ]

class SeccompNotifResp(ctypes.Structure):
    _fields_ = [
        ("id", ctypes.c_uint64),
        ("val", ctypes.c_int64),
        ("error", ctypes.c_int32),
        ("flags", ctypes.c_uint32),
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

def install_seccomp_quota_listener(out_fd):
    if SYS_seccomp < 0:
        raise RuntimeError(f"unsupported architecture for seccomp listener: {_ARCH}")
    BPF_LD_W_ABS  = 0x20
    BPF_JMP_JEQ_K = 0x15
    BPF_RET_K     = 0x06
    spec = [
        ("ENTRY",    BPF_LD_W_ABS,  0,  None,       None),
        (None,       BPF_JMP_JEQ_K, SYS_write,           "CHECK_FD", None),
        (None,       BPF_JMP_JEQ_K, SYS_writev,          "CHECK_FD", None),
        (None,       BPF_JMP_JEQ_K, SYS_pwrite64,        "NOTIF",    None),
        (None,       BPF_JMP_JEQ_K, SYS_pwritev,         "NOTIF",    None),
        (None,       BPF_JMP_JEQ_K, SYS_pwritev2,        "NOTIF",    None),
        (None,       BPF_JMP_JEQ_K, SYS_truncate,        "NOTIF",    None),
        (None,       BPF_JMP_JEQ_K, SYS_ftruncate,       "NOTIF",    None),
        (None,       BPF_JMP_JEQ_K, SYS_fallocate,       "NOTIF",    None),
        (None,       BPF_JMP_JEQ_K, SYS_sendfile,        "NOTIF",    None),
        (None,       BPF_JMP_JEQ_K, SYS_splice,          "NOTIF",    None),
        (None,       BPF_JMP_JEQ_K, SYS_copy_file_range, "NOTIF",    "ALLOW"),
        ("CHECK_FD", BPF_LD_W_ABS,  20, None,       None),
        (None,       BPF_JMP_JEQ_K, 0,  None,       "NOTIF"),
        (None,       BPF_LD_W_ABS,  16, None,       None),
        (None,       BPF_JMP_JEQ_K, 1,  "ALLOW",    None),
        (None,       BPF_JMP_JEQ_K, 2,  "ALLOW",    None),
        (None,       BPF_JMP_JEQ_K, out_fd, "ALLOW", "NOTIF"),
        ("ALLOW",    BPF_RET_K,     SECCOMP_RET_ALLOW,      None, None),
        ("NOTIF",    BPF_RET_K,     SECCOMP_RET_USER_NOTIF, None, None),
    ]
    labels = {}
    for idx, item in enumerate(spec):
        if item[0] is not None:
            labels[item[0]] = idx
    arr = (SockFilter * len(spec))()
    for idx, (_lbl, code, k, jt_lbl, jf_lbl) in enumerate(spec):
        jt = (labels[jt_lbl] - (idx + 1)) if jt_lbl is not None else 0
        jf = (labels[jf_lbl] - (idx + 1)) if jf_lbl is not None else 0
        arr[idx] = SockFilter(code=code, jt=jt, jf=jf, k=int(k) & 0xffffffff)
    prog = SockFprog(len=len(spec), filter=arr)
    nfd = libc.syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_NEW_LISTENER, ctypes.byref(prog))
    if nfd < 0:
        raise RuntimeError(f"seccomp(SECCOMP_FILTER_FLAG_NEW_LISTENER) failed: errno={ctypes.get_errno()}")
    return nfd

def run_seccomp_supervisor(nfd, child_pid, scratch_tmp, cg_procs):
    last_approved = {}
    scratch_prefix = scratch_tmp.rstrip("/") + "/"

    def is_scratch_link(link):
        return link.startswith(scratch_prefix) or link == scratch_tmp or (
            link.startswith("/memfd:") and not link.startswith("/memfd:lmcloud_payload")
        )

    def scan_live_inodes(req_pid):
        live = {}
        try:
            for root, _dirs, files in os.walk(scratch_tmp):
                for fn in files:
                    p = os.path.join(root, fn)
                    try:
                        st = os.lstat(p)
                        if stat.S_ISREG(st.st_mode):
                            k = (st.st_dev, st.st_ino)
                            if st.st_size > live.get(k, 0):
                                live[k] = st.st_size
                    except OSError:
                        pass
        except OSError:
            pass
        pids = {child_pid}
        if req_pid > 0:
            pids.add(req_pid)
        if cg_procs:
            try:
                with open(cg_procs, "r") as f:
                    for line in f:
                        s = line.strip()
                        if s.isdigit():
                            pids.add(int(s))
            except OSError:
                pass
        for p in pids:
            fd_dir = f"/proc/{p}/fd"
            try:
                fd_list = os.listdir(fd_dir)
            except OSError:
                continue
            for fd_str in fd_list:
                fd_path = f"{fd_dir}/{fd_str}"
                try:
                    link = os.readlink(fd_path)
                except OSError:
                    continue
                if is_scratch_link(link):
                    try:
                        st = os.stat(fd_path)
                        if stat.S_ISREG(st.st_mode):
                            k = (st.st_dev, st.st_ino)
                            if st.st_size > live.get(k, 0):
                                live[k] = st.st_size
                    except OSError:
                        pass
        now_ts = time.monotonic()
        for k in list(last_approved.keys()):
            if k not in live:
                del last_approved[k]
            else:
                ap_sz, ap_ts = last_approved[k]
                if now_ts - ap_ts < 0.05 and ap_sz > live[k]:
                    live[k] = ap_sz
        return live

    def read_fdinfo(rpid, fd):
        pos = 0
        flags = 0
        try:
            with open(f"/proc/{rpid}/fdinfo/{fd}", "r") as f:
                for line in f:
                    if line.startswith("pos:"):
                        pos = int(line.split(":", 1)[1].strip())
                    elif line.startswith("flags:"):
                        flags = int(line.split(":", 1)[1].strip(), 8)
        except Exception:
            pass
        return pos, flags

    def sum_iovec(rpid, iov_ptr, iovcnt):
        if iovcnt == 0:
            return 0
        if iovcnt < 0 or iovcnt > 1024:
            return MAX_SCRATCH_BYTES + 1
        mfd = -1
        try:
            mfd = os.open(f"/proc/{rpid}/mem", os.O_RDONLY)
            raw = os.pread(mfd, iovcnt * 16, iov_ptr)
            if len(raw) != iovcnt * 16:
                return MAX_SCRATCH_BYTES + 1
            total = 0
            for i in range(iovcnt):
                _base, length = struct.unpack_from("<QQ", raw, i * 16)
                total += length
            return total
        except Exception:
            return MAX_SCRATCH_BYTES + 1
        finally:
            if mfd >= 0:
                try:
                    os.close(mfd)
                except OSError:
                    pass

    def read_c_string(rpid, ptr, max_len=4096):
        mfd = -1
        try:
            mfd = os.open(f"/proc/{rpid}/mem", os.O_RDONLY)
            raw = os.pread(mfd, max_len, ptr)
            idx = raw.find(b"\x00")
            if idx >= 0:
                raw = raw[:idx]
            return raw.decode("utf-8", errors="surrogateescape")
        except Exception:
            return ""
        finally:
            if mfd >= 0:
                try:
                    os.close(mfd)
                except OSError:
                    pass

    def evaluate_notif(req):
        nr = req.data.nr
        args = req.data.args
        rpid = req.pid if req.pid > 0 else child_pid

        if nr == SYS_truncate:
            length = ctypes.c_int64(args[1]).value
            if length < 0 or length > MAX_SCRATCH_BYTES:
                return -errno.ENOSPC
            path_str = read_c_string(rpid, args[0])
            if not path_str:
                return -errno.ENOSPC
            if not os.path.isabs(path_str):
                try:
                    cwd = os.readlink(f"/proc/{rpid}/cwd")
                    path_str = os.path.join(cwd, path_str)
                except OSError:
                    pass
            live = scan_live_inodes(rpid)
            key = None
            try:
                st = os.lstat(path_str)
                key = (st.st_dev, st.st_ino)
            except OSError:
                pass
            other_bytes = sum(sz for k, sz in live.items() if k != key)
            if other_bytes + length > MAX_SCRATCH_BYTES:
                return -errno.ENOSPC
            if key is not None:
                last_approved[key] = (length, time.monotonic())
            return 0

        if nr in (SYS_splice, SYS_copy_file_range):
            fd = int(args[2]) & 0xffffffff
        else:
            fd = int(args[0]) & 0xffffffff

        fd_path = f"/proc/{rpid}/fd/{fd}"
        try:
            link = os.readlink(fd_path)
        except OSError:
            return 0

        if not is_scratch_link(link):
            return 0

        try:
            st = os.stat(fd_path)
        except OSError:
            return 0
        if not stat.S_ISREG(st.st_mode):
            return 0

        key = (st.st_dev, st.st_ino)
        live = scan_live_inodes(rpid)
        cur_size = live.get(key, st.st_size)
        pos, flags = read_fdinfo(rpid, fd)
        if st.st_size == 0 and pos == 0:
            cur_size = 0

        if nr == SYS_ftruncate:
            length = ctypes.c_int64(args[1]).value
            if length < 0:
                return -errno.EINVAL
            new_size = length
        elif nr == SYS_fallocate:
            offset = ctypes.c_int64(args[2]).value
            length = ctypes.c_int64(args[3]).value
            if offset < 0 or length < 0:
                return -errno.EINVAL
            new_size = max(cur_size, offset + length)
        elif nr == SYS_write:
            count = int(args[2])
            base = cur_size if (flags & os.O_APPEND) else pos
            new_size = max(cur_size, base + count)
        elif nr == SYS_pwrite64:
            count = int(args[2])
            offset = ctypes.c_int64(args[3]).value
            if offset < 0:
                return -errno.EINVAL
            new_size = max(cur_size, offset + count)
        elif nr in (SYS_writev, SYS_pwritev, SYS_pwritev2):
            count = sum_iovec(rpid, int(args[1]), ctypes.c_int32(args[2]).value)
            if nr == SYS_writev:
                base = cur_size if (flags & os.O_APPEND) else pos
            else:
                off = ctypes.c_int64(args[3]).value
                base = cur_size if (off < 0 or (flags & os.O_APPEND)) else off
            new_size = max(cur_size, base + count)
        elif nr == SYS_sendfile:
            count = int(args[3])
            new_size = cur_size + count
        elif nr in (SYS_splice, SYS_copy_file_range):
            count = int(args[4])
            new_size = cur_size + count
        else:
            new_size = cur_size

        other_bytes = sum(sz for k, sz in live.items() if k != key)
        if new_size > MAX_SCRATCH_BYTES or (other_bytes + new_size) > MAX_SCRATCH_BYTES:
            return -errno.ENOSPC

        last_approved[key] = (new_size, time.monotonic())
        return 0

    poller = select.poll()
    poller.register(nfd, select.POLLIN | select.POLLHUP | select.POLLERR)
    while True:
        try:
            wpid, _st = os.waitpid(child_pid, os.WNOHANG)
            if wpid == child_pid:
                break
        except ChildProcessError:
            break
        except OSError:
            pass
        try:
            events = poller.poll(10)
        except InterruptedError:
            continue
        except OSError:
            break
        for _fd, ev in events:
            if ev & select.POLLIN:
                req = SeccompNotif()
                rc = libc.ioctl(nfd, SECCOMP_IOCTL_NOTIF_RECV, ctypes.byref(req))
                if rc != 0:
                    continue
                err_code = evaluate_notif(req)
                if err_code < 0:
                    resp = SeccompNotifResp(id=req.id, val=0, error=err_code, flags=0)
                else:
                    resp = SeccompNotifResp(id=req.id, val=0, error=0, flags=SECCOMP_USER_NOTIF_FLAG_CONTINUE)
                libc.ioctl(nfd, SECCOMP_IOCTL_NOTIF_SEND, ctypes.byref(resp))

def main():
    out_fd = os.dup(3)
    os.close(3)
    os.set_inheritable(out_fd, True)
    spec_raw = sys.stdin.buffer.read()
    spec = json.loads(spec_raw.decode("utf-8"))

    notif_parent_sock, notif_child_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_STREAM)
    notif_parent_sock.settimeout(5.0)

    rc = libc.unshare(CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWNET | CLONE_NEWIPC)
    if rc != 0:
        write_outcome(out_fd, {"internalError": f"unshare failed: errno={ctypes.get_errno()}"})
        os._exit(2)

    pid = os.fork()
    if pid > 0:
        notif_child_sock.close()
        def forward_kill(signum, _frame):
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
        signal.signal(signal.SIGTERM, forward_kill)
        signal.signal(signal.SIGINT, forward_kill)
        nfd = -1
        try:
            _msg, fds, _flags, _addr = socket.recv_fds(notif_parent_sock, 1, 1)
            if fds:
                nfd = fds[0]
        except Exception as e:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
            write_outcome(out_fd, {"internalError": f"failed to receive seccomp listener fd: {e}"})
            os.close(out_fd)
            os._exit(2)
        finally:
            notif_parent_sock.close()
        if nfd < 0:
            try:
                os.kill(pid, signal.SIGKILL)
            except OSError:
                pass
            write_outcome(out_fd, {"internalError": "seccomp listener fd not established"})
            os.close(out_fd)
            os._exit(2)
        os.close(out_fd)
        try:
            run_seccomp_supervisor(nfd, pid, spec["scratch_tmp"], spec.get("cgroup_procs_path", ""))
        finally:
            try:
                os.close(nfd)
            except OSError:
                pass
        try:
            os.waitpid(pid, 0)
        except OSError:
            pass
        os._exit(0)

    # Inside child: PID 1 of the isolated PID namespace!
    notif_parent_sock.close()
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

    try:
        nfd = install_seccomp_quota_listener(out_fd)
        socket.send_fds(notif_child_sock, [b"1"], [nfd])
        os.close(nfd)
        notif_child_sock.close()
    except Exception as e:
        write_outcome(out_fd, {"internalError": f"seccomp quota listener setup failed: {e}"})
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

type inodeKey struct {
	dev uint64
	ino uint64
}

func scratchDirBytes(dir string, pids []int) int64 {
	seen := map[inodeKey]int64{}
	var fallbackTotal int64
	prefix := strings.TrimSuffix(dir, "/") + "/"
	recordInfo := func(info os.FileInfo) {
		if info == nil || !info.Mode().IsRegular() {
			return
		}
		if st, ok := info.Sys().(*syscall.Stat_t); ok && st != nil {
			k := inodeKey{dev: uint64(st.Dev), ino: uint64(st.Ino)}
			if info.Size() > seen[k] {
				seen[k] = info.Size()
			}
			return
		}
		fallbackTotal += info.Size()
	}
	_ = filepath.WalkDir(dir, func(_ string, d os.DirEntry, err error) error {
		if err != nil || d == nil || d.IsDir() {
			return nil
		}
		if info, ierr := d.Info(); ierr == nil {
			recordInfo(info)
		}
		return nil
	})
	for _, pid := range pids {
		if pid <= 0 {
			continue
		}
		fdDir := fmt.Sprintf("/proc/%d/fd", pid)
		entries, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}
		for _, ent := range entries {
			fdPath := filepath.Join(fdDir, ent.Name())
			link, lerr := os.Readlink(fdPath)
			if lerr != nil {
				continue
			}
			if strings.HasPrefix(link, prefix) || link == dir || (strings.HasPrefix(link, "/memfd:") && !strings.HasPrefix(link, "/memfd:lmcloud_payload")) {
				if info, serr := os.Stat(fdPath); serr == nil {
					recordInfo(info)
				}
			}
		}
	}
	total := fallbackTotal
	for _, sz := range seen {
		total += sz
	}
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
			diskBytes := scratchDirBytes(scratchTmp, pids)
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
	isDiskQuota := killedForDisk || scratchDirBytes(scratchTmp, allPIDs) > maxScratchTmpBytes
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
