// SPDX-License-Identifier: MIT

package fakeadapter

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

func init() {
	if os.Getenv("LMCLOUD_SCRATCH_FUSE_HELPER") == "1" {
		runScratchFuseHelperMain()
		os.Exit(0)
	}
}

const (
	maxScratchTmpInodes  = 4096
	maxScratchFuseName   = 255
	maxScratchSymlinkLen = 4096
	fuseHelperTimeout    = 5 * time.Second
	mfdCloexec           = 0x0001
	exitDelayBytes       = 64 * 1024 * 1024

	fuseKernelMajor = 7
	fuseKernelMinor = 31

	fuseOpLookup      = 1
	fuseOpForget      = 2
	fuseOpGetattr     = 3
	fuseOpSetattr     = 4
	fuseOpReadlink    = 5
	fuseOpSymlink     = 6
	fuseOpMknod       = 8
	fuseOpMkdir       = 9
	fuseOpUnlink      = 10
	fuseOpRmdir       = 11
	fuseOpRename      = 12
	fuseOpLink        = 13
	fuseOpOpen        = 14
	fuseOpRead        = 15
	fuseOpWrite       = 16
	fuseOpStatfs      = 17
	fuseOpRelease     = 18
	fuseOpFsync       = 20
	fuseOpSetxattr    = 21
	fuseOpGetxattr    = 22
	fuseOpListxattr   = 23
	fuseOpRemovexattr = 24
	fuseOpFlush       = 25
	fuseOpInit        = 26
	fuseOpOpendir     = 27
	fuseOpReaddir     = 28
	fuseOpReleasedir  = 29
	fuseOpFsyncdir    = 30
	fuseOpAccess      = 34
	fuseOpCreate      = 35
	fuseOpInterrupt   = 36
	fuseOpDestroy     = 38
	fuseOpBatchForget = 42
	fuseOpFallocate   = 43
	fuseOpReaddirplus = 44
	fuseOpRename2     = 45
	fuseOpLseek       = 46

	fattrMode  = 1 << 0
	fattrUID   = 1 << 1
	fattrGID   = 1 << 2
	fattrSize  = 1 << 3
	fattrAtime = 1 << 4
	fattrMtime = 1 << 5

	fuseFlagAsyncRead    = 1 << 0
	fuseFlagAtomicOTrunc = 1 << 3
	fuseFlagBigWrites    = 1 << 5
	fuseFlagMaxPages     = 1 << 22
)

type fuseInode struct {
	ino             uint64
	mode            uint32
	nlink           uint32
	uid             uint32
	gid             uint32
	openCount       int32
	data            []byte
	children        map[string]uint64
	childrenPeak    int
	childrenDeletes int
	parent          uint64
	mtime           int64
}

type scratchFuseFS struct {
	mu              sync.Mutex
	fd              int
	watchWFD        int
	watchCmd        *exec.Cmd
	exitDelayFD     int
	mountDir        string
	fusermount      string
	maxBytes        int64
	maxInodes       int
	uid             uint32
	gid             uint32
	inodes          map[uint64]*fuseInode
	inodesPeak      int
	inodesDeletes   int
	nextIno         uint64
	pendingReleases int
	lastFlushTime   time.Time
	closed          bool
	doneCh          chan struct{}
}

func resolveFusermountBin() (string, error) {
	for _, candidate := range []string{"/usr/bin/fusermount3", "/bin/fusermount3", "/usr/bin/fusermount", "/bin/fusermount"} {
		if st, err := os.Stat(candidate); err == nil && !st.IsDir() {
			return candidate, nil
		}
	}
	if p, err := exec.LookPath("fusermount3"); err == nil {
		return p, nil
	}
	if p, err := exec.LookPath("fusermount"); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("fusermount3 not found")
}

func sweepDisconnectedScratchMounts(fmBin string) {
	raw, err := os.ReadFile("/proc/self/mountinfo")
	if err != nil {
		return
	}
	uidTag := fmt.Sprintf("user_id=%d", os.Getuid())
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 10 {
			continue
		}
		mntPoint := fields[4]
		sepIdx := -1
		for i := 6; i < len(fields); i++ {
			if fields[i] == "-" {
				sepIdx = i
				break
			}
		}
		if sepIdx < 0 || sepIdx+3 >= len(fields) {
			continue
		}
		fsType := fields[sepIdx+1]
		source := fields[sepIdx+2]
		superOpts := fields[sepIdx+3]
		if fsType != "fuse.tmpfs" || source != "lmcloud_scratch" {
			continue
		}
		ownedByUs := false
		for _, opt := range strings.Split(superOpts, ",") {
			if opt == uidTag {
				ownedByUs = true
				break
			}
		}
		if !ownedByUs {
			continue
		}
		var st syscall.Stat_t
		if err := syscall.Stat(mntPoint, &st); errors.Is(err, syscall.ENOTCONN) {
			if syscall.Unmount(mntPoint, syscall.MNT_DETACH) != nil && fmBin != "" {
				ctx, cancel := context.WithTimeout(context.Background(), fuseHelperTimeout)
				_ = exec.CommandContext(ctx, fmBin, "-u", "-z", "-q", "--", mntPoint).Run()
				cancel()
			}
		}
	}
}

func dupAboveCloexec(fd int, minFD int) int {
	if fd < 0 || fd >= minFD {
		return fd
	}
	newFD, _, errno := syscall.Syscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_DUPFD_CLOEXEC, uintptr(minFD))
	if errno != 0 {
		return fd
	}
	_ = syscall.Close(fd)
	return int(newFD)
}

func createExitDelayFD() int {
	var nr uintptr
	switch runtime.GOARCH {
	case "amd64":
		nr = 319
	case "arm64":
		nr = 279
	default:
		return -1
	}
	nameBytes := []byte("lmcloud_fuse_exit_sync\x00")
	r1, _, errno := syscall.Syscall(nr, uintptr(unsafe.Pointer(&nameBytes[0])), uintptr(mfdCloexec), 0)
	if errno != 0 {
		return -1
	}
	fd := int(r1)
	if err := syscall.Fallocate(fd, 0, 0, exitDelayBytes); err != nil {
		_ = syscall.Close(fd)
		return -1
	}
	return fd
}

func startFuseUnmountWatchdog(fmBin, mountDir string, watchR *os.File) (*exec.Cmd, error) {
	readyR, readyW, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("create watchdog readiness pipe: %w", err)
	}
	script := `echo ok >&3; exec 3>&-; read -r _ || true; exec "$1" -u -z -q -- "$2"`
	cmd := exec.Command("/bin/sh", "-c", script, "lmcloud-fuse-watchdog", fmBin, mountDir)
	cmd.Stdin = watchR
	cmd.ExtraFiles = []*os.File{readyW}
	cmd.Env = []string{"PATH=/usr/bin:/bin"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		_ = readyR.Close()
		_ = readyW.Close()
		return nil, fmt.Errorf("start fuse unmount watchdog: %w", err)
	}
	_ = readyW.Close()

	_ = readyR.SetReadDeadline(time.Now().Add(fuseHelperTimeout))
	var buf [8]byte
	n, readErr := readyR.Read(buf[:])
	_ = readyR.Close()
	if readErr != nil || n == 0 {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		return nil, fmt.Errorf("fuse unmount watchdog did not become ready: %w", readErr)
	}
	return cmd, nil
}

func mountScratchFuseFS(mountDir string, maxBytes int64, maxInodes int) (*scratchFuseFS, error) {
	fmBin, err := resolveFusermountBin()
	if err != nil {
		return nil, err
	}
	sweepDisconnectedScratchMounts(fmBin)

	// Allocate exitDelayFD at the lowest FD slot so in Linux's LIFO task_work_run()
	// during do_exit(), watchWFD (highest FD) closes first to wake the watchdog,
	// fuseFD closes second, and exitDelayFD (lowest FD) closes last to hold do_exit()
	// until the watchdog finishes detaching the mount.
	exitDelayFD := createExitDelayFD()

	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
	if err != nil {
		if exitDelayFD >= 0 {
			_ = syscall.Close(exitDelayFD)
		}
		return nil, fmt.Errorf("socketpair for fusermount3: %w", err)
	}
	parentSock := fds[0]
	syscall.CloseOnExec(parentSock)
	childFile := os.NewFile(uintptr(fds[1]), "fuse-commfd")

	mountCtx, mountCancel := context.WithTimeout(context.Background(), fuseHelperTimeout)
	defer mountCancel()
	cmd := exec.CommandContext(mountCtx, fmBin, "-o", "rw,nosuid,nodev,fsname=lmcloud_scratch,subtype=tmpfs", "--", mountDir)
	cmd.ExtraFiles = []*os.File{childFile}
	cmd.Env = []string{
		"PATH=/usr/bin:/bin",
		"_FUSE_COMMFD=3",
	}
	var stderrBuf [512]byte
	rPipe, wPipe, pipeErr := os.Pipe()
	if pipeErr == nil {
		cmd.Stderr = wPipe
	}
	if err := cmd.Start(); err != nil {
		_ = childFile.Close()
		_ = syscall.Close(parentSock)
		if exitDelayFD >= 0 {
			_ = syscall.Close(exitDelayFD)
		}
		if pipeErr == nil {
			_ = rPipe.Close()
			_ = wPipe.Close()
		}
		return nil, fmt.Errorf("start fusermount3: %w", err)
	}
	_ = childFile.Close()
	if pipeErr == nil {
		_ = wPipe.Close()
	}

	_ = syscall.SetsockoptTimeval(parentSock, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 5})
	msgBuf := make([]byte, 64)
	oobBuf := make([]byte, syscall.CmsgSpace(4))
	_, oobn, _, _, recvErr := syscall.Recvmsg(parentSock, msgBuf, oobBuf, 0)
	_ = syscall.Close(parentSock)
	waitErr := cmd.Wait()
	var errText string
	if pipeErr == nil {
		_ = rPipe.SetReadDeadline(time.Now().Add(fuseHelperTimeout))
		n, _ := rPipe.Read(stderrBuf[:])
		_ = rPipe.Close()
		errText = string(stderrBuf[:n])
	}
	if recvErr != nil {
		if exitDelayFD >= 0 {
			_ = syscall.Close(exitDelayFD)
		}
		return nil, fmt.Errorf("receive /dev/fuse fd from fusermount3: %w (wait=%v stderr=%q)", recvErr, waitErr, errText)
	}
	cmsgs, err := syscall.ParseSocketControlMessage(oobBuf[:oobn])
	if err != nil || len(cmsgs) == 0 {
		if exitDelayFD >= 0 {
			_ = syscall.Close(exitDelayFD)
		}
		return nil, fmt.Errorf("parse fusermount3 control message: %w (wait=%v stderr=%q)", err, waitErr, errText)
	}
	gotFDs, err := syscall.ParseUnixRights(&cmsgs[0])
	if err != nil || len(gotFDs) == 0 {
		if exitDelayFD >= 0 {
			_ = syscall.Close(exitDelayFD)
		}
		return nil, fmt.Errorf("parse /dev/fuse unix rights: %w", err)
	}
	fuseFD := gotFDs[0]
	syscall.CloseOnExec(fuseFD)
	if exitDelayFD >= 0 {
		fuseFD = dupAboveCloexec(fuseFD, exitDelayFD+1)
	}

	var wpipe [2]int
	if err := syscall.Pipe2(wpipe[:], syscall.O_CLOEXEC); err != nil {
		_ = syscall.Close(fuseFD)
		if exitDelayFD >= 0 {
			_ = syscall.Close(exitDelayFD)
		}
		if syscall.Unmount(mountDir, syscall.MNT_DETACH) != nil {
			uCtx, uCancel := context.WithTimeout(context.Background(), fuseHelperTimeout)
			_ = exec.CommandContext(uCtx, fmBin, "-u", "-z", "-q", "--", mountDir).Run()
			uCancel()
		}
		return nil, fmt.Errorf("create fuse watchdog pipe: %w", err)
	}
	watchR := os.NewFile(uintptr(wpipe[0]), "fuse-watch-r")
	minWatchFD := fuseFD + 1
	if exitDelayFD+1 > minWatchFD {
		minWatchFD = exitDelayFD + 1
	}
	watchWFD := dupAboveCloexec(wpipe[1], minWatchFD)

	watchCmd, err := startFuseUnmountWatchdog(fmBin, mountDir, watchR)
	_ = watchR.Close()
	if err != nil {
		_ = syscall.Close(fuseFD)
		_ = syscall.Close(watchWFD)
		if exitDelayFD >= 0 {
			_ = syscall.Close(exitDelayFD)
		}
		if syscall.Unmount(mountDir, syscall.MNT_DETACH) != nil {
			uCtx, uCancel := context.WithTimeout(context.Background(), fuseHelperTimeout)
			_ = exec.CommandContext(uCtx, fmBin, "-u", "-z", "-q", "--", mountDir).Run()
			uCancel()
		}
		return nil, err
	}

	uid := uint32(os.Getuid())
	gid := uint32(os.Getgid())
	now := time.Now().Unix()
	fs := &scratchFuseFS{
		fd:          fuseFD,
		watchWFD:    watchWFD,
		watchCmd:    watchCmd,
		exitDelayFD: exitDelayFD,
		mountDir:    mountDir,
		fusermount:  fmBin,
		maxBytes:    maxBytes,
		maxInodes:   maxInodes,
		uid:         uid,
		gid:         gid,
		inodes: map[uint64]*fuseInode{
			1: {
				ino:      1,
				mode:     syscall.S_IFDIR | 0o700,
				nlink:    2,
				uid:      uid,
				gid:      gid,
				children: map[string]uint64{},
				parent:   1,
				mtime:    now,
			},
		},
		nextIno: 2,
		doneCh:  make(chan struct{}),
	}
	go fs.serve()
	return fs, nil
}

func inodeAllocatedBytes(n *fuseInode) int64 {
	if n == nil {
		return 0
	}
	l := int64(len(n.data))
	c := int64(cap(n.data))
	if c > l {
		return c
	}
	return l
}

func (fs *scratchFuseFS) UsedBytes() int64 {
	fs.mu.Lock()
	for fs.pendingReleases > 0 && time.Since(fs.lastFlushTime) < 25*time.Millisecond {
		fs.mu.Unlock()
		time.Sleep(50 * time.Microsecond)
		fs.mu.Lock()
	}
	used := fs.usedBytesLocked()
	fs.mu.Unlock()
	return used
}

func (fs *scratchFuseFS) usedBytesLocked() int64 {
	var total int64
	for ino, n := range fs.inodes {
		if ino == 1 {
			continue
		}
		if n.nlink > 0 || n.openCount > 0 {
			total += inodeAllocatedBytes(n)
		}
	}
	return total
}

func (fs *scratchFuseFS) totalDirEntriesLocked() int {
	var count int
	for _, n := range fs.inodes {
		if n != nil && n.children != nil {
			count += len(n.children)
		}
	}
	return count
}

func validateFuseEntryName(name string) syscall.Errno {
	if name == "" || name == "." || name == ".." || strings.IndexByte(name, '/') >= 0 {
		return syscall.EINVAL
	}
	if len(name) > maxScratchFuseName {
		return syscall.ENAMETOOLONG
	}
	return 0
}

func (fs *scratchFuseFS) setInodeLocked(ino uint64, n *fuseInode) {
	fs.inodes[ino] = n
	if len(fs.inodes) > fs.inodesPeak {
		fs.inodesPeak = len(fs.inodes)
	}
}

func (fs *scratchFuseFS) setDirChildLocked(dir *fuseInode, name string, ino uint64) {
	if dir == nil {
		return
	}
	if dir.children == nil {
		dir.children = map[string]uint64{}
	}
	key := string([]byte(name))
	dir.children[key] = ino
	if len(dir.children) > dir.childrenPeak {
		dir.childrenPeak = len(dir.children)
	}
}

func (fs *scratchFuseFS) deleteDirChildLocked(dir *fuseInode, name string) {
	if dir == nil || dir.children == nil {
		return
	}
	delete(dir.children, name)
	dir.childrenDeletes++
	fs.compactDirChildrenLocked(dir)
}

func (fs *scratchFuseFS) compactDirChildrenLocked(dir *fuseInode) {
	if dir == nil || dir.children == nil {
		return
	}
	cur := len(dir.children)
	if cur == 0 {
		if dir.childrenPeak > 0 || dir.childrenDeletes > 0 {
			dir.children = map[string]uint64{}
			dir.childrenPeak = 0
			dir.childrenDeletes = 0
		}
		return
	}
	delThreshold := cur
	if delThreshold < 16 {
		delThreshold = 16
	}
	if (dir.childrenPeak > 1 && (cur*2 <= dir.childrenPeak || dir.childrenPeak-cur >= 256)) || dir.childrenDeletes >= delThreshold {
		compact := make(map[string]uint64, cur)
		for k, v := range dir.children {
			compact[k] = v
		}
		dir.children = compact
		dir.childrenPeak = cur
		dir.childrenDeletes = 0
	}
}

func (fs *scratchFuseFS) reclaimInodeLocked(ino uint64, n *fuseInode) {
	if ino == 1 || n == nil {
		return
	}
	if n.nlink == 0 && n.openCount <= 0 {
		n.data = nil
		n.children = nil
		n.childrenPeak = 0
		n.childrenDeletes = 0
		delete(fs.inodes, ino)
		fs.inodesDeletes++
		cur := len(fs.inodes)
		delThreshold := cur
		if delThreshold < 16 {
			delThreshold = 16
		}
		if (fs.inodesPeak > 2 && (cur*2 <= fs.inodesPeak || fs.inodesPeak-cur >= 256)) || fs.inodesDeletes >= delThreshold {
			compact := make(map[uint64]*fuseInode, cur)
			for k, v := range fs.inodes {
				compact[k] = v
			}
			fs.inodes = compact
			fs.inodesPeak = cur
			fs.inodesDeletes = 0
		}
	}
}

func (fs *scratchFuseFS) Close() {
	fs.mu.Lock()
	if fs.closed {
		fs.mu.Unlock()
		<-fs.doneCh
		return
	}
	fs.closed = true
	fd := fs.fd
	fs.fd = -1
	watchWFD := fs.watchWFD
	fs.watchWFD = -1
	watchCmd := fs.watchCmd
	fs.watchCmd = nil
	exitDelayFD := fs.exitDelayFD
	fs.exitDelayFD = -1
	for ino, n := range fs.inodes {
		if n != nil {
			n.data = nil
			if ino != 1 {
				n.children = nil
			}
		}
	}
	fs.mu.Unlock()

	if fd >= 0 {
		_ = syscall.Close(fd)
	}
	if watchWFD >= 0 {
		_ = syscall.Close(watchWFD)
	}
	if watchCmd != nil {
		waitCh := make(chan struct{})
		go func() {
			_ = watchCmd.Wait()
			close(waitCh)
		}()
		select {
		case <-waitCh:
		case <-time.After(fuseHelperTimeout):
			if watchCmd.Process != nil {
				_ = watchCmd.Process.Kill()
			}
			<-waitCh
		}
	}
	if syscall.Unmount(fs.mountDir, syscall.MNT_DETACH) != nil && fs.fusermount != "" {
		ctx, cancel := context.WithTimeout(context.Background(), fuseHelperTimeout)
		_ = exec.CommandContext(ctx, fs.fusermount, "-u", "-z", "-q", "--", fs.mountDir).Run()
		cancel()
	}
	if exitDelayFD >= 0 {
		_ = syscall.Close(exitDelayFD)
	}
	<-fs.doneCh
}

func (fs *scratchFuseFS) packAttr(b []byte, n *fuseInode) {
	size := uint64(len(n.data))
	blocks := (size + 511) / 512
	sec := uint64(n.mtime)
	binary.LittleEndian.PutUint64(b[0:8], n.ino)
	binary.LittleEndian.PutUint64(b[8:16], size)
	binary.LittleEndian.PutUint64(b[16:24], blocks)
	binary.LittleEndian.PutUint64(b[24:32], sec)
	binary.LittleEndian.PutUint64(b[32:40], sec)
	binary.LittleEndian.PutUint64(b[40:48], sec)
	binary.LittleEndian.PutUint32(b[48:52], 0)
	binary.LittleEndian.PutUint32(b[52:56], 0)
	binary.LittleEndian.PutUint32(b[56:60], 0)
	binary.LittleEndian.PutUint32(b[60:64], n.mode)
	binary.LittleEndian.PutUint32(b[64:68], n.nlink)
	binary.LittleEndian.PutUint32(b[68:72], n.uid)
	binary.LittleEndian.PutUint32(b[72:76], n.gid)
	binary.LittleEndian.PutUint32(b[76:80], 0)
	binary.LittleEndian.PutUint32(b[80:84], 4096)
	binary.LittleEndian.PutUint32(b[84:88], 0)
}

func (fs *scratchFuseFS) packEntry(b []byte, n *fuseInode) {
	// nodeid(8), generation(8), entry_valid(8), attr_valid(8), entry_valid_nsec(4), attr_valid_nsec(4), attr(88) = 128 bytes
	for i := range b[:40] {
		b[i] = 0
	}
	binary.LittleEndian.PutUint64(b[0:8], n.ino)
	binary.LittleEndian.PutUint64(b[8:16], 1)
	binary.LittleEndian.PutUint64(b[16:24], 60)
	if n.mode&syscall.S_IFMT == syscall.S_IFDIR {
		binary.LittleEndian.PutUint64(b[24:32], 60)
	}
	fs.packAttr(b[40:128], n)
}

func (fs *scratchFuseFS) packAttrOut(b []byte, n *fuseInode) {
	// attr_valid(8), attr_valid_nsec(4), dummy(4), attr(88) = 104 bytes
	for i := range b[:16] {
		b[i] = 0
	}
	fs.packAttr(b[16:104], n)
}

func (fs *scratchFuseFS) replyOK(fd int, unique uint64, payload []byte) {
	buf := make([]byte, 16+len(payload))
	binary.LittleEndian.PutUint32(buf[0:4], uint32(16+len(payload)))
	binary.LittleEndian.PutUint32(buf[4:8], 0)
	binary.LittleEndian.PutUint64(buf[8:16], unique)
	copy(buf[16:], payload)
	_, _ = syscall.Write(fd, buf)
}

func (fs *scratchFuseFS) replyErr(fd int, unique uint64, errno syscall.Errno) {
	var buf [16]byte
	binary.LittleEndian.PutUint32(buf[0:4], 16)
	neg := int32(-int(errno))
	binary.LittleEndian.PutUint32(buf[4:8], uint32(neg))
	binary.LittleEndian.PutUint64(buf[8:16], unique)
	_, _ = syscall.Write(fd, buf[:])
}

func cstrName(b []byte) string {
	for i, c := range b {
		if c == 0 {
			return string(b[:i])
		}
	}
	return string(b)
}

func splitTwoCStrings(b []byte) (string, string) {
	for i, c := range b {
		if c == 0 {
			rest := b[i+1:]
			return string(b[:i]), cstrName(rest)
		}
	}
	return string(b), ""
}

func (fs *scratchFuseFS) serve() {
	defer close(fs.doneCh)
	reqBuf := make([]byte, 131072+8192)
	for {
		fs.mu.Lock()
		fd := fs.fd
		fs.mu.Unlock()
		if fd < 0 {
			return
		}
		n, err := syscall.Read(fd, reqBuf)
		if err != nil {
			if err == syscall.EINTR || err == syscall.EAGAIN {
				continue
			}
			return
		}
		if n < 40 {
			continue
		}
		length := int(binary.LittleEndian.Uint32(reqBuf[0:4]))
		if length > n {
			length = n
		}
		opcode := binary.LittleEndian.Uint32(reqBuf[4:8])
		unique := binary.LittleEndian.Uint64(reqBuf[8:16])
		nodeid := binary.LittleEndian.Uint64(reqBuf[16:24])
		body := reqBuf[40:length]

		fs.handleRequest(fd, opcode, unique, nodeid, body)
	}
}

func (fs *scratchFuseFS) handleRequest(fd int, opcode uint32, unique uint64, nodeid uint64, body []byte) {
	fs.mu.Lock()
	defer fs.mu.Unlock()

	switch opcode {
	case fuseOpForget, fuseOpBatchForget, fuseOpInterrupt:
		return

	case fuseOpInit:
		if len(body) < 16 {
			fs.replyErr(fd, unique, syscall.EINVAL)
			return
		}
		maxRA := binary.LittleEndian.Uint32(body[8:12])
		inFlags := binary.LittleEndian.Uint32(body[12:16])
		outFlags := inFlags & (fuseFlagAsyncRead | fuseFlagAtomicOTrunc | fuseFlagBigWrites | fuseFlagMaxPages)
		var out [64]byte
		binary.LittleEndian.PutUint32(out[0:4], fuseKernelMajor)
		binary.LittleEndian.PutUint32(out[4:8], fuseKernelMinor)
		binary.LittleEndian.PutUint32(out[8:12], maxRA)
		binary.LittleEndian.PutUint32(out[12:16], outFlags)
		binary.LittleEndian.PutUint16(out[16:18], 16)
		binary.LittleEndian.PutUint16(out[18:20], 12)
		binary.LittleEndian.PutUint32(out[20:24], 131072)
		binary.LittleEndian.PutUint32(out[24:28], 1)
		binary.LittleEndian.PutUint16(out[28:30], 32)
		fs.replyOK(fd, unique, out[:])

	case fuseOpDestroy:
		fs.replyOK(fd, unique, nil)

	case fuseOpStatfs:
		used := fs.usedBytesLocked()
		freeBytes := fs.maxBytes - used
		if freeBytes < 0 {
			freeBytes = 0
		}
		freeInodes := fs.maxInodes - len(fs.inodes)
		if freeInodes < 0 {
			freeInodes = 0
		}
		var out [80]byte
		binary.LittleEndian.PutUint64(out[0:8], uint64(fs.maxBytes/4096))
		binary.LittleEndian.PutUint64(out[8:16], uint64(freeBytes/4096))
		binary.LittleEndian.PutUint64(out[16:24], uint64(freeBytes/4096))
		binary.LittleEndian.PutUint64(out[24:32], uint64(fs.maxInodes))
		binary.LittleEndian.PutUint64(out[32:40], uint64(freeInodes))
		binary.LittleEndian.PutUint32(out[40:44], 4096)
		binary.LittleEndian.PutUint32(out[44:48], 255)
		binary.LittleEndian.PutUint32(out[48:52], 4096)
		fs.replyOK(fd, unique, out[:])

	case fuseOpGetattr:
		n, ok := fs.inodes[nodeid]
		if !ok {
			fs.replyErr(fd, unique, syscall.ENOENT)
			return
		}
		var out [104]byte
		fs.packAttrOut(out[:], n)
		fs.replyOK(fd, unique, out[:])

	case fuseOpLookup:
		parent, ok := fs.inodes[nodeid]
		if !ok || parent.children == nil {
			fs.replyErr(fd, unique, syscall.ENOENT)
			return
		}
		name := cstrName(body)
		cino, ok := parent.children[name]
		if !ok {
			fs.replyErr(fd, unique, syscall.ENOENT)
			return
		}
		cn, ok := fs.inodes[cino]
		if !ok {
			fs.replyErr(fd, unique, syscall.ENOENT)
			return
		}
		var out [128]byte
		fs.packEntry(out[:], cn)
		fs.replyOK(fd, unique, out[:])

	case fuseOpAccess:
		if _, ok := fs.inodes[nodeid]; !ok {
			fs.replyErr(fd, unique, syscall.ENOENT)
			return
		}
		fs.replyOK(fd, unique, nil)

	case fuseOpSetattr:
		if len(body) < 88 {
			fs.replyErr(fd, unique, syscall.EINVAL)
			return
		}
		n, ok := fs.inodes[nodeid]
		if !ok {
			fs.replyErr(fd, unique, syscall.ENOENT)
			return
		}
		valid := binary.LittleEndian.Uint32(body[0:4])
		if valid&fattrSize != 0 {
			newSize := binary.LittleEndian.Uint64(body[16:24])
			if newSize > uint64(fs.maxBytes) {
				fs.replyErr(fd, unique, syscall.ENOSPC)
				return
			}
			other := fs.usedBytesLocked() - inodeAllocatedBytes(n)
			if other+int64(newSize) > fs.maxBytes {
				fs.replyErr(fd, unique, syscall.ENOSPC)
				return
			}
			sz := int(newSize)
			if sz == 0 {
				n.data = nil
			} else if sz < len(n.data) || cap(n.data) > sz {
				shrunk := make([]byte, sz)
				if sz < len(n.data) {
					copy(shrunk, n.data[:sz])
				} else {
					copy(shrunk, n.data)
				}
				n.data = shrunk
			} else if sz > len(n.data) {
				grown := make([]byte, sz)
				copy(grown, n.data)
				n.data = grown
			}
		}
		if valid&fattrMode != 0 {
			mode := binary.LittleEndian.Uint32(body[68:72])
			n.mode = (n.mode & syscall.S_IFMT) | (mode & 0o7777)
		}
		n.mtime = time.Now().Unix()
		var out [104]byte
		fs.packAttrOut(out[:], n)
		fs.replyOK(fd, unique, out[:])

	case fuseOpCreate:
		if len(body) < 16 {
			fs.replyErr(fd, unique, syscall.EINVAL)
			return
		}
		parent, ok := fs.inodes[nodeid]
		if !ok || parent.children == nil {
			fs.replyErr(fd, unique, syscall.ENOENT)
			return
		}
		flags := binary.LittleEndian.Uint32(body[0:4])
		mode := binary.LittleEndian.Uint32(body[4:8])
		name := cstrName(body[16:])
		if errno := validateFuseEntryName(name); errno != 0 {
			fs.replyErr(fd, unique, errno)
			return
		}
		var cn *fuseInode
		if cino, exists := parent.children[name]; exists {
			if flags&uint32(syscall.O_EXCL) != 0 {
				fs.replyErr(fd, unique, syscall.EEXIST)
				return
			}
			cn = fs.inodes[cino]
			if cn.mode&syscall.S_IFMT == syscall.S_IFDIR {
				fs.replyErr(fd, unique, syscall.EISDIR)
				return
			}
			if flags&uint32(syscall.O_TRUNC) != 0 {
				cn.data = nil
			}
			cn.openCount++
		} else {
			if len(fs.inodes) >= fs.maxInodes || fs.totalDirEntriesLocked() >= fs.maxInodes {
				fs.replyErr(fd, unique, syscall.ENOSPC)
				return
			}
			cino := fs.nextIno
			fs.nextIno++
			cn = &fuseInode{
				ino:       cino,
				mode:      syscall.S_IFREG | (mode & 0o7777),
				nlink:     1,
				uid:       fs.uid,
				gid:       fs.gid,
				openCount: 1,
				mtime:     time.Now().Unix(),
			}
			fs.setInodeLocked(cino, cn)
			fs.setDirChildLocked(parent, name, cino)
		}
		var out [144]byte
		fs.packEntry(out[:128], cn)
		binary.LittleEndian.PutUint64(out[128:136], cn.ino)
		binary.LittleEndian.PutUint32(out[136:140], 0)
		binary.LittleEndian.PutUint32(out[140:144], 0)
		fs.replyOK(fd, unique, out[:])

	case fuseOpMknod:
		if len(body) < 16 {
			fs.replyErr(fd, unique, syscall.EINVAL)
			return
		}
		parent, ok := fs.inodes[nodeid]
		if !ok || parent.children == nil {
			fs.replyErr(fd, unique, syscall.ENOENT)
			return
		}
		mode := binary.LittleEndian.Uint32(body[0:4])
		name := cstrName(body[16:])
		if errno := validateFuseEntryName(name); errno != 0 {
			fs.replyErr(fd, unique, errno)
			return
		}
		if _, exists := parent.children[name]; exists {
			fs.replyErr(fd, unique, syscall.EEXIST)
			return
		}
		if len(fs.inodes) >= fs.maxInodes || fs.totalDirEntriesLocked() >= fs.maxInodes {
			fs.replyErr(fd, unique, syscall.ENOSPC)
			return
		}
		cino := fs.nextIno
		fs.nextIno++
		ftype := mode & syscall.S_IFMT
		if ftype == 0 {
			ftype = syscall.S_IFREG
		}
		cn := &fuseInode{
			ino:   cino,
			mode:  ftype | (mode & 0o7777),
			nlink: 1,
			uid:   fs.uid,
			gid:   fs.gid,
			mtime: time.Now().Unix(),
		}
		fs.setInodeLocked(cino, cn)
		fs.setDirChildLocked(parent, name, cino)
		var out [128]byte
		fs.packEntry(out[:], cn)
		fs.replyOK(fd, unique, out[:])

	case fuseOpMkdir:
		if len(body) < 8 {
			fs.replyErr(fd, unique, syscall.EINVAL)
			return
		}
		parent, ok := fs.inodes[nodeid]
		if !ok || parent.children == nil {
			fs.replyErr(fd, unique, syscall.ENOENT)
			return
		}
		mode := binary.LittleEndian.Uint32(body[0:4])
		name := cstrName(body[8:])
		if errno := validateFuseEntryName(name); errno != 0 {
			fs.replyErr(fd, unique, errno)
			return
		}
		if _, exists := parent.children[name]; exists {
			fs.replyErr(fd, unique, syscall.EEXIST)
			return
		}
		if len(fs.inodes) >= fs.maxInodes || fs.totalDirEntriesLocked() >= fs.maxInodes {
			fs.replyErr(fd, unique, syscall.ENOSPC)
			return
		}
		cino := fs.nextIno
		fs.nextIno++
		cn := &fuseInode{
			ino:      cino,
			mode:     syscall.S_IFDIR | (mode & 0o7777),
			nlink:    2,
			uid:      fs.uid,
			gid:      fs.gid,
			children: map[string]uint64{},
			parent:   nodeid,
			mtime:    time.Now().Unix(),
		}
		fs.setInodeLocked(cino, cn)
		fs.setDirChildLocked(parent, name, cino)
		parent.nlink++
		var out [128]byte
		fs.packEntry(out[:], cn)
		fs.replyOK(fd, unique, out[:])

	case fuseOpUnlink:
		parent, ok := fs.inodes[nodeid]
		if !ok || parent.children == nil {
			fs.replyErr(fd, unique, syscall.ENOENT)
			return
		}
		name := cstrName(body)
		cino, exists := parent.children[name]
		if !exists {
			fs.replyErr(fd, unique, syscall.ENOENT)
			return
		}
		cn := fs.inodes[cino]
		if cn != nil && cn.mode&syscall.S_IFMT == syscall.S_IFDIR {
			fs.replyErr(fd, unique, syscall.EISDIR)
			return
		}
		fs.deleteDirChildLocked(parent, name)
		if cn != nil {
			if cn.nlink > 0 {
				cn.nlink--
			}
			fs.reclaimInodeLocked(cino, cn)
		}
		fs.replyOK(fd, unique, nil)

	case fuseOpRmdir:
		parent, ok := fs.inodes[nodeid]
		if !ok || parent.children == nil {
			fs.replyErr(fd, unique, syscall.ENOENT)
			return
		}
		name := cstrName(body)
		cino, exists := parent.children[name]
		if !exists {
			fs.replyErr(fd, unique, syscall.ENOENT)
			return
		}
		cn := fs.inodes[cino]
		if cn == nil || cn.mode&syscall.S_IFMT != syscall.S_IFDIR {
			fs.replyErr(fd, unique, syscall.ENOTDIR)
			return
		}
		if len(cn.children) > 0 {
			fs.replyErr(fd, unique, syscall.ENOTEMPTY)
			return
		}
		fs.deleteDirChildLocked(parent, name)
		if parent.nlink > 2 {
			parent.nlink--
		}
		cn.nlink = 0
		fs.reclaimInodeLocked(cino, cn)
		fs.replyOK(fd, unique, nil)

	case fuseOpRename, fuseOpRename2:
		var newDirIno uint64
		var flags uint32
		var names []byte
		if opcode == fuseOpRename {
			if len(body) < 8 {
				fs.replyErr(fd, unique, syscall.EINVAL)
				return
			}
			newDirIno = binary.LittleEndian.Uint64(body[0:8])
			names = body[8:]
		} else {
			if len(body) < 16 {
				fs.replyErr(fd, unique, syscall.EINVAL)
				return
			}
			newDirIno = binary.LittleEndian.Uint64(body[0:8])
			flags = binary.LittleEndian.Uint32(body[8:12])
			names = body[16:]
		}
		oldParent, ok1 := fs.inodes[nodeid]
		newParent, ok2 := fs.inodes[newDirIno]
		if !ok1 || !ok2 || oldParent.children == nil || newParent.children == nil {
			fs.replyErr(fd, unique, syscall.ENOENT)
			return
		}
		oldName, newName := splitTwoCStrings(names)
		if errno := validateFuseEntryName(oldName); errno != 0 {
			fs.replyErr(fd, unique, errno)
			return
		}
		if errno := validateFuseEntryName(newName); errno != 0 {
			fs.replyErr(fd, unique, errno)
			return
		}
		srcIno, exists := oldParent.children[oldName]
		if !exists {
			fs.replyErr(fd, unique, syscall.ENOENT)
			return
		}
		if dstIno, dstExists := newParent.children[newName]; dstExists {
			if flags&1 != 0 { // RENAME_NOREPLACE
				fs.replyErr(fd, unique, syscall.EEXIST)
				return
			}
			if dstIno != srcIno {
				if dst := fs.inodes[dstIno]; dst != nil {
					if dst.mode&syscall.S_IFMT == syscall.S_IFDIR && len(dst.children) > 0 {
						fs.replyErr(fd, unique, syscall.ENOTEMPTY)
						return
					}
					if dst.nlink > 0 {
						dst.nlink--
					}
					if dst.mode&syscall.S_IFMT == syscall.S_IFDIR {
						dst.nlink = 0
					}
					fs.reclaimInodeLocked(dstIno, dst)
				}
			}
		}
		fs.deleteDirChildLocked(oldParent, oldName)
		fs.setDirChildLocked(newParent, newName, srcIno)
		if src := fs.inodes[srcIno]; src != nil && src.mode&syscall.S_IFMT == syscall.S_IFDIR {
			src.parent = newDirIno
		}
		fs.replyOK(fd, unique, nil)

	case fuseOpLink:
		if len(body) < 8 {
			fs.replyErr(fd, unique, syscall.EINVAL)
			return
		}
		oldIno := binary.LittleEndian.Uint64(body[0:8])
		name := cstrName(body[8:])
		if errno := validateFuseEntryName(name); errno != 0 {
			fs.replyErr(fd, unique, errno)
			return
		}
		parent, ok1 := fs.inodes[nodeid]
		target, ok2 := fs.inodes[oldIno]
		if !ok1 || !ok2 || parent.children == nil {
			fs.replyErr(fd, unique, syscall.ENOENT)
			return
		}
		if target.mode&syscall.S_IFMT == syscall.S_IFDIR {
			fs.replyErr(fd, unique, syscall.EPERM)
			return
		}
		if _, exists := parent.children[name]; exists {
			fs.replyErr(fd, unique, syscall.EEXIST)
			return
		}
		if fs.totalDirEntriesLocked() >= fs.maxInodes {
			fs.replyErr(fd, unique, syscall.ENOSPC)
			return
		}
		target.nlink++
		fs.setDirChildLocked(parent, name, oldIno)
		var out [128]byte
		fs.packEntry(out[:], target)
		fs.replyOK(fd, unique, out[:])

	case fuseOpSymlink:
		parent, ok := fs.inodes[nodeid]
		if !ok || parent.children == nil {
			fs.replyErr(fd, unique, syscall.ENOENT)
			return
		}
		name, target := splitTwoCStrings(body)
		if errno := validateFuseEntryName(name); errno != 0 {
			fs.replyErr(fd, unique, errno)
			return
		}
		if target == "" {
			fs.replyErr(fd, unique, syscall.ENOENT)
			return
		}
		if len(target) > maxScratchSymlinkLen {
			fs.replyErr(fd, unique, syscall.ENAMETOOLONG)
			return
		}
		if _, exists := parent.children[name]; exists {
			fs.replyErr(fd, unique, syscall.EEXIST)
			return
		}
		if len(fs.inodes) >= fs.maxInodes || fs.totalDirEntriesLocked() >= fs.maxInodes || fs.usedBytesLocked()+int64(len(target)) > fs.maxBytes {
			fs.replyErr(fd, unique, syscall.ENOSPC)
			return
		}
		cino := fs.nextIno
		fs.nextIno++
		symData := make([]byte, len(target))
		copy(symData, target)
		cn := &fuseInode{
			ino:   cino,
			mode:  syscall.S_IFLNK | 0o777,
			nlink: 1,
			uid:   fs.uid,
			gid:   fs.gid,
			data:  symData,
			mtime: time.Now().Unix(),
		}
		fs.setInodeLocked(cino, cn)
		fs.setDirChildLocked(parent, name, cino)
		var out [128]byte
		fs.packEntry(out[:], cn)
		fs.replyOK(fd, unique, out[:])

	case fuseOpReadlink:
		n, ok := fs.inodes[nodeid]
		if !ok || n.mode&syscall.S_IFMT != syscall.S_IFLNK {
			fs.replyErr(fd, unique, syscall.EINVAL)
			return
		}
		fs.replyOK(fd, unique, n.data)

	case fuseOpOpen, fuseOpOpendir:
		n, ok := fs.inodes[nodeid]
		if !ok {
			fs.replyErr(fd, unique, syscall.ENOENT)
			return
		}
		if opcode == fuseOpOpen && len(body) >= 4 {
			flags := binary.LittleEndian.Uint32(body[0:4])
			if flags&uint32(syscall.O_TRUNC) != 0 {
				n.data = nil
			}
		}
		n.openCount++
		var out [16]byte
		binary.LittleEndian.PutUint64(out[0:8], nodeid)
		fs.replyOK(fd, unique, out[:])

	case fuseOpRelease, fuseOpReleasedir:
		if fs.pendingReleases > 0 {
			fs.pendingReleases--
		}
		if n, ok := fs.inodes[nodeid]; ok {
			n.openCount--
			fs.reclaimInodeLocked(nodeid, n)
		}
		fs.replyOK(fd, unique, nil)

	case fuseOpFlush:
		fs.pendingReleases++
		fs.lastFlushTime = time.Now()
		fs.replyOK(fd, unique, nil)

	case fuseOpFsync, fuseOpFsyncdir:
		fs.replyOK(fd, unique, nil)

	case fuseOpRead:
		if len(body) < 24 {
			fs.replyErr(fd, unique, syscall.EINVAL)
			return
		}
		n, ok := fs.inodes[nodeid]
		if !ok {
			fs.replyErr(fd, unique, syscall.ENOENT)
			return
		}
		offset := binary.LittleEndian.Uint64(body[8:16])
		size := binary.LittleEndian.Uint32(body[16:20])
		if offset >= uint64(len(n.data)) {
			fs.replyOK(fd, unique, nil)
			return
		}
		end := offset + uint64(size)
		if end > uint64(len(n.data)) {
			end = uint64(len(n.data))
		}
		fs.replyOK(fd, unique, n.data[offset:end])

	case fuseOpWrite:
		if len(body) < 40 {
			fs.replyErr(fd, unique, syscall.EINVAL)
			return
		}
		n, ok := fs.inodes[nodeid]
		if !ok {
			fs.replyErr(fd, unique, syscall.ENOENT)
			return
		}
		offset := binary.LittleEndian.Uint64(body[8:16])
		size := binary.LittleEndian.Uint32(body[16:20])
		data := body[40:]
		if uint32(len(data)) > size {
			data = data[:size]
		}
		end := offset + uint64(len(data))
		if end > uint64(fs.maxBytes) {
			fs.replyErr(fd, unique, syscall.ENOSPC)
			return
		}
		newSize := len(n.data)
		if int(end) > newSize {
			newSize = int(end)
		}
		other := fs.usedBytesLocked() - inodeAllocatedBytes(n)
		if other+int64(newSize) > fs.maxBytes {
			fs.replyErr(fd, unique, syscall.ENOSPC)
			return
		}
		if newSize > len(n.data) {
			grown := make([]byte, newSize)
			copy(grown, n.data)
			n.data = grown
		}
		copy(n.data[offset:], data)
		n.mtime = time.Now().Unix()
		var out [8]byte
		binary.LittleEndian.PutUint32(out[0:4], uint32(len(data)))
		fs.replyOK(fd, unique, out[:])

	case fuseOpFallocate:
		if len(body) < 32 {
			fs.replyErr(fd, unique, syscall.EINVAL)
			return
		}
		n, ok := fs.inodes[nodeid]
		if !ok {
			fs.replyErr(fd, unique, syscall.ENOENT)
			return
		}
		offset := binary.LittleEndian.Uint64(body[8:16])
		length := binary.LittleEndian.Uint64(body[16:24])
		mode := binary.LittleEndian.Uint32(body[24:28])
		if mode&^uint32(1) != 0 {
			fs.replyErr(fd, unique, syscall.EOPNOTSUPP)
			return
		}
		end := offset + length
		if end > uint64(fs.maxBytes) {
			fs.replyErr(fd, unique, syscall.ENOSPC)
			return
		}
		newSize := len(n.data)
		if int(end) > newSize {
			newSize = int(end)
		}
		other := fs.usedBytesLocked() - inodeAllocatedBytes(n)
		if other+int64(newSize) > fs.maxBytes {
			fs.replyErr(fd, unique, syscall.ENOSPC)
			return
		}
		if mode&1 == 0 && newSize > len(n.data) {
			grown := make([]byte, newSize)
			copy(grown, n.data)
			n.data = grown
		}
		n.mtime = time.Now().Unix()
		fs.replyOK(fd, unique, nil)

	case fuseOpReaddir:
		if len(body) < 24 {
			fs.replyErr(fd, unique, syscall.EINVAL)
			return
		}
		n, ok := fs.inodes[nodeid]
		if !ok || n.children == nil {
			fs.replyErr(fd, unique, syscall.ENOENT)
			return
		}
		offset := binary.LittleEndian.Uint64(body[8:16])
		maxSize := int(binary.LittleEndian.Uint32(body[16:20]))

		type dirEnt struct {
			name string
			ino  uint64
			typ  uint32
		}
		names := make([]string, 0, len(n.children))
		for k := range n.children {
			names = append(names, k)
		}
		sort.Strings(names)
		entries := make([]dirEnt, 0, 2+len(names))
		entries = append(entries,
			dirEnt{name: ".", ino: n.ino, typ: syscall.DT_DIR},
			dirEnt{name: "..", ino: n.parent, typ: syscall.DT_DIR},
		)
		for _, k := range names {
			cino := n.children[k]
			typ := uint32(syscall.DT_REG)
			if cn := fs.inodes[cino]; cn != nil {
				typ = (cn.mode & syscall.S_IFMT) >> 12
			}
			entries = append(entries, dirEnt{name: k, ino: cino, typ: typ})
		}
		if int(offset) >= len(entries) {
			fs.replyOK(fd, unique, nil)
			return
		}
		var out []byte
		for idx := int(offset); idx < len(entries); idx++ {
			ent := entries[idx]
			nameBytes := []byte(ent.name)
			recLen := (24 + len(nameBytes) + 7) &^ 7
			if len(out)+recLen > maxSize {
				break
			}
			rec := make([]byte, recLen)
			binary.LittleEndian.PutUint64(rec[0:8], ent.ino)
			binary.LittleEndian.PutUint64(rec[8:16], uint64(idx+1))
			binary.LittleEndian.PutUint32(rec[16:20], uint32(len(nameBytes)))
			binary.LittleEndian.PutUint32(rec[20:24], ent.typ)
			copy(rec[24:], nameBytes)
			out = append(out, rec...)
		}
		fs.replyOK(fd, unique, out)

	case fuseOpGetxattr, fuseOpListxattr:
		fs.replyErr(fd, unique, syscall.ENODATA)

	case fuseOpSetxattr, fuseOpRemovexattr:
		fs.replyErr(fd, unique, syscall.EOPNOTSUPP)

	default:
		fs.replyErr(fd, unique, syscall.ENOSYS)
	}
}

type scratchFuseHelper struct {
	mu         sync.Mutex
	ctrlFD     int
	cmd        *exec.Cmd
	watchCmd   *exec.Cmd
	cgDir      string
	mountDir   string
	fusermount string
	maxBytes   int64
	lastUsed   int64
	closed     bool
}

func waitBoundedCmd(cmd *exec.Cmd, timeout time.Duration) {
	if cmd == nil {
		return
	}
	waitCh := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(waitCh)
	}()
	select {
	case <-waitCh:
	case <-time.After(timeout):
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		<-waitCh
	}
}

func isRaceEnabledProcess() bool {
	if bi, ok := debug.ReadBuildInfo(); ok && bi != nil {
		for _, s := range bi.Settings {
			if s.Key == "-race" && s.Value == "true" {
				return true
			}
		}
	}
	raw, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return false
	}
	fields := strings.Fields(string(raw))
	if len(fields) == 0 {
		return false
	}
	pages, err := strconv.ParseInt(fields[0], 10, 64)
	if err != nil {
		return false
	}
	return pages > 200_000
}

func runScratchFuseHelperMain() {
	_, _, _ = syscall.RawSyscall(syscall.SYS_PRCTL, syscall.PR_SET_PDEATHSIG, uintptr(syscall.SIGKILL), 0)
	if ppidStr := os.Getenv("LMCLOUD_SCRATCH_FUSE_PPID"); ppidStr != "" {
		if wantPPID, err := strconv.Atoi(ppidStr); err == nil && wantPPID > 0 {
			if os.Getppid() != wantPPID {
				os.Exit(1)
			}
		}
	}
	maxBytes := int64(16 * 1024 * 1024)
	if s := os.Getenv("LMCLOUD_SCRATCH_FUSE_MAX_BYTES"); s != "" {
		if v, err := strconv.ParseInt(s, 10, 64); err == nil && v > 0 {
			maxBytes = v
		}
	}
	maxInodes := maxScratchTmpInodes
	if s := os.Getenv("LMCLOUD_SCRATCH_FUSE_MAX_INODES"); s != "" {
		if v, err := strconv.Atoi(s); err == nil && v > 0 {
			maxInodes = v
		}
	}
	mountDir := os.Getenv("LMCLOUD_SCRATCH_FUSE_MOUNT_DIR")

	// Bound Go runtime memory to the 16 MiB data budget plus fixed runtime overhead.
	if isRaceEnabledProcess() {
		debug.SetMemoryLimit(maxBytes + 128*1024*1024)
	} else {
		debug.SetMemoryLimit(maxBytes + 16*1024*1024)
		const asLimit = 2 * 1024 * 1024 * 1024
		_ = syscall.Setrlimit(syscall.RLIMIT_AS, &syscall.Rlimit{Cur: asLimit, Max: asLimit})
	}
	debug.SetGCPercent(20)

	const (
		fuseFD   = 3
		watchWFD = 4
		ctrlFD   = 5
	)
	syscall.CloseOnExec(fuseFD)
	syscall.CloseOnExec(watchWFD)
	syscall.CloseOnExec(ctrlFD)

	if _, err := syscall.Write(ctrlFD, []byte("READY")); err != nil {
		os.Exit(1)
	}
	var startBuf [16]byte
	n, err := syscall.Read(ctrlFD, startBuf[:])
	if err != nil || string(startBuf[:n]) != "START" {
		os.Exit(1)
	}

	uid := uint32(os.Getuid())
	gid := uint32(os.Getgid())
	now := time.Now().Unix()
	fs := &scratchFuseFS{
		fd:          fuseFD,
		watchWFD:    watchWFD,
		exitDelayFD: -1,
		mountDir:    mountDir,
		maxBytes:    maxBytes,
		maxInodes:   maxInodes,
		uid:         uid,
		gid:         gid,
		inodes: map[uint64]*fuseInode{
			1: {
				ino:      1,
				mode:     syscall.S_IFDIR | 0o700,
				nlink:    2,
				uid:      uid,
				gid:      gid,
				children: map[string]uint64{},
				parent:   1,
				mtime:    now,
			},
		},
		inodesPeak: 1,
		nextIno:    2,
		doneCh:     make(chan struct{}),
	}
	go fs.serve()

	if _, err := syscall.Write(ctrlFD, []byte("OK")); err != nil {
		fs.Close()
		os.Exit(1)
	}

	go func() {
		<-fs.doneCh
		_ = syscall.Close(ctrlFD)
	}()

	var cmdBuf [16]byte
	for {
		n, err := syscall.Read(ctrlFD, cmdBuf[:])
		if err != nil || n == 0 {
			break
		}
		switch string(cmdBuf[:n]) {
		case "USED":
			used := fs.UsedBytes()
			var reply [8]byte
			binary.LittleEndian.PutUint64(reply[:], uint64(used))
			_, _ = syscall.Write(ctrlFD, reply[:])
		case "CLOSE":
			fs.Close()
			_, _ = syscall.Write(ctrlFD, []byte("BYE"))
			os.Exit(0)
		}
	}
	fs.Close()
	os.Exit(0)
}

func mountScratchFuseHelper(mountDir string, maxBytes int64, maxInodes int, cgParent string) (*scratchFuseHelper, error) {
	if cgParent == "" {
		return nil, fmt.Errorf("missing cgroup v2 parent for scratch fuse helper")
	}
	fmBin, err := resolveFusermountBin()
	if err != nil {
		return nil, err
	}
	sweepDisconnectedScratchMounts(fmBin)

	cgDir, err := os.MkdirTemp(cgParent, "lmcloud-fuse-*.scope")
	if err != nil {
		return nil, fmt.Errorf("create fuse helper cgroup: %w", err)
	}
	cleanupCg := func() {
		_ = os.WriteFile(filepath.Join(cgDir, "cgroup.kill"), []byte("1"), 0o600)
		_ = os.Remove(cgDir)
	}
	if err := os.WriteFile(filepath.Join(cgDir, "memory.swap.max"), []byte("0"), 0o600); err != nil {
		cleanupCg()
		return nil, fmt.Errorf("configure fuse helper cgroup swap: %w", err)
	}
	_ = os.WriteFile(filepath.Join(cgDir, "memory.oom.group"), []byte("1"), 0o600)
	if err := os.WriteFile(filepath.Join(cgDir, "pids.max"), []byte("32"), 0o600); err != nil {
		cleanupCg()
		return nil, fmt.Errorf("configure fuse helper cgroup pids: %w", err)
	}
	initMemMax := "268435456"
	if isRaceEnabledProcess() {
		initMemMax = "536870912"
	}
	if err := os.WriteFile(filepath.Join(cgDir, "memory.max"), []byte(initMemMax), 0o600); err != nil {
		cleanupCg()
		return nil, fmt.Errorf("configure fuse helper cgroup initial memory.max: %w", err)
	}

	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
	if err != nil {
		cleanupCg()
		return nil, fmt.Errorf("socketpair for fusermount3: %w", err)
	}
	parentSock := fds[0]
	syscall.CloseOnExec(parentSock)
	childFile := os.NewFile(uintptr(fds[1]), "fuse-commfd")

	mountCtx, mountCancel := context.WithTimeout(context.Background(), fuseHelperTimeout)
	defer mountCancel()
	mcmd := exec.CommandContext(mountCtx, fmBin, "-o", "rw,nosuid,nodev,fsname=lmcloud_scratch,subtype=tmpfs", "--", mountDir)
	mcmd.ExtraFiles = []*os.File{childFile}
	mcmd.Env = []string{
		"PATH=/usr/bin:/bin",
		"_FUSE_COMMFD=3",
	}
	var stderrBuf [512]byte
	rPipe, wPipe, pipeErr := os.Pipe()
	if pipeErr == nil {
		mcmd.Stderr = wPipe
	}
	if err := mcmd.Start(); err != nil {
		_ = childFile.Close()
		_ = syscall.Close(parentSock)
		if pipeErr == nil {
			_ = rPipe.Close()
			_ = wPipe.Close()
		}
		cleanupCg()
		return nil, fmt.Errorf("start fusermount3: %w", err)
	}
	_ = childFile.Close()
	if pipeErr == nil {
		_ = wPipe.Close()
	}

	_ = syscall.SetsockoptTimeval(parentSock, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 5})
	msgBuf := make([]byte, 64)
	oobBuf := make([]byte, syscall.CmsgSpace(4))
	_, oobn, _, _, recvErr := syscall.Recvmsg(parentSock, msgBuf, oobBuf, 0)
	_ = syscall.Close(parentSock)
	waitErr := mcmd.Wait()
	var errText string
	if pipeErr == nil {
		_ = rPipe.SetReadDeadline(time.Now().Add(fuseHelperTimeout))
		n, _ := rPipe.Read(stderrBuf[:])
		_ = rPipe.Close()
		errText = string(stderrBuf[:n])
	}
	if recvErr != nil {
		cleanupCg()
		return nil, fmt.Errorf("receive /dev/fuse fd from fusermount3: %w (wait=%v stderr=%q)", recvErr, waitErr, errText)
	}
	cmsgs, err := syscall.ParseSocketControlMessage(oobBuf[:oobn])
	if err != nil || len(cmsgs) == 0 {
		cleanupCg()
		return nil, fmt.Errorf("parse fusermount3 control message: %w (wait=%v stderr=%q)", err, waitErr, errText)
	}
	gotFDs, err := syscall.ParseUnixRights(&cmsgs[0])
	if err != nil || len(gotFDs) == 0 {
		cleanupCg()
		return nil, fmt.Errorf("parse /dev/fuse unix rights: %w", err)
	}
	fuseFD := gotFDs[0]
	syscall.CloseOnExec(fuseFD)

	unmountDir := func() {
		if syscall.Unmount(mountDir, syscall.MNT_DETACH) != nil {
			uCtx, uCancel := context.WithTimeout(context.Background(), fuseHelperTimeout)
			_ = exec.CommandContext(uCtx, fmBin, "-u", "-z", "-q", "--", mountDir).Run()
			uCancel()
		}
	}

	var wpipe [2]int
	if err := syscall.Pipe2(wpipe[:], syscall.O_CLOEXEC); err != nil {
		_ = syscall.Close(fuseFD)
		unmountDir()
		cleanupCg()
		return nil, fmt.Errorf("create fuse watchdog pipe: %w", err)
	}
	watchR := os.NewFile(uintptr(wpipe[0]), "fuse-watch-r")
	watchWFD := wpipe[1]

	watchCmd, err := startFuseUnmountWatchdog(fmBin, mountDir, watchR)
	_ = watchR.Close()
	if err != nil {
		_ = syscall.Close(fuseFD)
		_ = syscall.Close(watchWFD)
		unmountDir()
		cleanupCg()
		return nil, err
	}

	ctrlPair, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
	if err != nil {
		_ = syscall.Close(fuseFD)
		_ = syscall.Close(watchWFD)
		waitBoundedCmd(watchCmd, fuseHelperTimeout)
		unmountDir()
		cleanupCg()
		return nil, fmt.Errorf("socketpair for fuse helper control: %w", err)
	}
	ctrlParent := ctrlPair[0]
	syscall.CloseOnExec(ctrlParent)
	_ = syscall.SetsockoptTimeval(ctrlParent, syscall.SOL_SOCKET, syscall.SO_RCVTIMEO, &syscall.Timeval{Sec: 5})
	_ = syscall.SetsockoptTimeval(ctrlParent, syscall.SOL_SOCKET, syscall.SO_SNDTIMEO, &syscall.Timeval{Sec: 5})

	fuseFile := os.NewFile(uintptr(fuseFD), "dev-fuse")
	watchWFile := os.NewFile(uintptr(watchWFD), "fuse-watch-w")
	ctrlChildFile := os.NewFile(uintptr(ctrlPair[1]), "fuse-ctrl-child")

	helperCmd := exec.Command(os.Args[0])
	helperCmd.ExtraFiles = []*os.File{fuseFile, watchWFile, ctrlChildFile}
	helperCmd.Env = []string{
		"PATH=/usr/bin:/bin",
		"LMCLOUD_SCRATCH_FUSE_HELPER=1",
		"LMCLOUD_SCRATCH_FUSE_MAX_BYTES=" + strconv.FormatInt(maxBytes, 10),
		"LMCLOUD_SCRATCH_FUSE_MAX_INODES=" + strconv.Itoa(maxInodes),
		"LMCLOUD_SCRATCH_FUSE_PPID=" + strconv.Itoa(os.Getpid()),
		"LMCLOUD_SCRATCH_FUSE_MOUNT_DIR=" + mountDir,
	}
	helperCmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid:   true,
		Pdeathsig: syscall.SIGKILL,
	}
	startErr := helperCmd.Start()
	_ = fuseFile.Close()
	_ = watchWFile.Close()
	_ = ctrlChildFile.Close()
	if startErr != nil {
		_ = syscall.Close(ctrlParent)
		waitBoundedCmd(watchCmd, fuseHelperTimeout)
		unmountDir()
		cleanupCg()
		return nil, fmt.Errorf("start scratch fuse helper process: %w", startErr)
	}

	abortHelper := func() {
		_ = syscall.Close(ctrlParent)
		if helperCmd.Process != nil {
			_ = helperCmd.Process.Kill()
		}
		waitBoundedCmd(helperCmd, fuseHelperTimeout)
		waitBoundedCmd(watchCmd, fuseHelperTimeout)
		unmountDir()
		cleanupCg()
	}

	var readyBuf [16]byte
	rn, rerr := syscall.Read(ctrlParent, readyBuf[:])
	if rerr != nil || string(readyBuf[:rn]) != "READY" {
		abortHelper()
		return nil, fmt.Errorf("scratch fuse helper failed readiness handshake: %w", rerr)
	}

	if err := os.WriteFile(filepath.Join(cgDir, "cgroup.procs"), []byte(strconv.Itoa(helperCmd.Process.Pid)), 0o600); err != nil {
		abortHelper()
		return nil, fmt.Errorf("move scratch fuse helper into cgroup: %w", err)
	}

	baseMem := int64(0)
	if rawMem, merr := os.ReadFile(filepath.Join(cgDir, "memory.current")); merr == nil {
		if v, perr := strconv.ParseInt(strings.TrimSpace(string(rawMem)), 10, 64); perr == nil && v > 0 {
			baseMem = v
		}
	}
	// Tighten cgroup memory.max to baseline RSS + 16 MiB data budget + fixed server overhead
	// (accounting for ThreadSanitizer shadow memory when running under -race).
	overhead := int64(24 * 1024 * 1024)
	if isRaceEnabledProcess() {
		overhead = 256 * 1024 * 1024
	}
	memCap := baseMem + maxBytes + overhead
	if err := os.WriteFile(filepath.Join(cgDir, "memory.max"), []byte(strconv.FormatInt(memCap, 10)), 0o600); err != nil {
		abortHelper()
		return nil, fmt.Errorf("tighten scratch fuse helper cgroup memory.max: %w", err)
	}

	if _, werr := syscall.Write(ctrlParent, []byte("START")); werr != nil {
		abortHelper()
		return nil, fmt.Errorf("send START to scratch fuse helper: %w", werr)
	}
	var okBuf [16]byte
	on, oerr := syscall.Read(ctrlParent, okBuf[:])
	if oerr != nil || string(okBuf[:on]) != "OK" {
		abortHelper()
		return nil, fmt.Errorf("scratch fuse helper failed start confirmation: %w", oerr)
	}

	return &scratchFuseHelper{
		ctrlFD:     ctrlParent,
		cmd:        helperCmd,
		watchCmd:   watchCmd,
		cgDir:      cgDir,
		mountDir:   mountDir,
		fusermount: fmBin,
		maxBytes:   maxBytes,
	}, nil
}

func (h *scratchFuseHelper) UsedBytes() int64 {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.closed {
		return h.lastUsed
	}
	if h.cgDir != "" && cgroupHadOOM(h.cgDir) {
		h.lastUsed = h.maxBytes + 1
		return h.lastUsed
	}
	if h.ctrlFD < 0 {
		return h.lastUsed
	}
	if _, err := syscall.Write(h.ctrlFD, []byte("USED")); err != nil {
		if h.cgDir != "" && cgroupHadOOM(h.cgDir) {
			h.lastUsed = h.maxBytes + 1
		}
		return h.lastUsed
	}
	var reply [8]byte
	n, err := syscall.Read(h.ctrlFD, reply[:])
	if err != nil || n != 8 {
		if h.cgDir != "" && cgroupHadOOM(h.cgDir) {
			h.lastUsed = h.maxBytes + 1
		}
		return h.lastUsed
	}
	used := int64(binary.LittleEndian.Uint64(reply[:]))
	h.lastUsed = used
	return used
}

func (h *scratchFuseHelper) Close() {
	h.mu.Lock()
	if h.closed {
		h.mu.Unlock()
		return
	}
	h.closed = true
	ctrlFD := h.ctrlFD
	h.ctrlFD = -1
	cmd := h.cmd
	h.cmd = nil
	watchCmd := h.watchCmd
	h.watchCmd = nil
	cgDir := h.cgDir
	h.cgDir = ""
	h.mu.Unlock()

	if ctrlFD >= 0 {
		_, _ = syscall.Write(ctrlFD, []byte("CLOSE"))
		_ = syscall.Close(ctrlFD)
	}
	if cmd != nil && cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
	if cgDir != "" {
		_ = os.WriteFile(filepath.Join(cgDir, "cgroup.kill"), []byte("1"), 0o600)
	}
	waitBoundedCmd(cmd, fuseHelperTimeout)
	waitBoundedCmd(watchCmd, fuseHelperTimeout)
	if syscall.Unmount(h.mountDir, syscall.MNT_DETACH) != nil && h.fusermount != "" {
		ctx, cancel := context.WithTimeout(context.Background(), fuseHelperTimeout)
		_ = exec.CommandContext(ctx, h.fusermount, "-u", "-z", "-q", "--", h.mountDir).Run()
		cancel()
	}
	if cgDir != "" {
		_ = os.WriteFile(filepath.Join(cgDir, "cgroup.kill"), []byte("1"), 0o600)
		_ = os.Remove(cgDir)
	}
}
