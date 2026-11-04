// SPDX-License-Identifier: MIT

package fakeadapter

import (
	"encoding/binary"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"sync"
	"syscall"
	"time"
)

const (
	maxScratchTmpInodes = 4096

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
	ino       uint64
	mode      uint32
	nlink     uint32
	uid       uint32
	gid       uint32
	openCount int32
	data      []byte
	children  map[string]uint64
	parent    uint64
	mtime     int64
}

type scratchFuseFS struct {
	mu           sync.Mutex
	fd           int
	mountDir     string
	fusermount   string
	maxBytes     int64
	maxInodes    int
	uid          uint32
	gid          uint32
	inodes       map[uint64]*fuseInode
	nextIno      uint64
	closed       bool
	doneCh       chan struct{}
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

func mountScratchFuseFS(mountDir string, maxBytes int64, maxInodes int) (*scratchFuseFS, error) {
	fmBin, err := resolveFusermountBin()
	if err != nil {
		return nil, err
	}
	fds, err := syscall.Socketpair(syscall.AF_UNIX, syscall.SOCK_SEQPACKET, 0)
	if err != nil {
		return nil, fmt.Errorf("socketpair for fusermount3: %w", err)
	}
	parentSock := fds[0]
	childFile := os.NewFile(uintptr(fds[1]), "fuse-commfd")

	cmd := exec.Command(fmBin, "-o", "rw,nosuid,nodev,fsname=lmcloud_scratch,subtype=tmpfs", "--", mountDir)
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
		n, _ := rPipe.Read(stderrBuf[:])
		_ = rPipe.Close()
		errText = string(stderrBuf[:n])
	}
	if recvErr != nil {
		return nil, fmt.Errorf("receive /dev/fuse fd from fusermount3: %w (wait=%v stderr=%q)", recvErr, waitErr, errText)
	}
	cmsgs, err := syscall.ParseSocketControlMessage(oobBuf[:oobn])
	if err != nil || len(cmsgs) == 0 {
		return nil, fmt.Errorf("parse fusermount3 control message: %w (wait=%v stderr=%q)", err, waitErr, errText)
	}
	gotFDs, err := syscall.ParseUnixRights(&cmsgs[0])
	if err != nil || len(gotFDs) == 0 {
		return nil, fmt.Errorf("parse /dev/fuse unix rights: %w", err)
	}
	fuseFD := gotFDs[0]
	syscall.CloseOnExec(fuseFD)

	uid := uint32(os.Getuid())
	gid := uint32(os.Getgid())
	now := time.Now().Unix()
	fs := &scratchFuseFS{
		fd:         fuseFD,
		mountDir:   mountDir,
		fusermount: fmBin,
		maxBytes:   maxBytes,
		maxInodes:  maxInodes,
		uid:        uid,
		gid:        gid,
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

func (fs *scratchFuseFS) UsedBytes() int64 {
	fs.mu.Lock()
	defer fs.mu.Unlock()
	return fs.usedBytesLocked()
}

func (fs *scratchFuseFS) usedBytesLocked() int64 {
	var total int64
	for ino, n := range fs.inodes {
		if ino == 1 {
			continue
		}
		if n.nlink > 0 || n.openCount > 0 {
			total += int64(len(n.data))
		}
	}
	return total
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
	fs.mu.Unlock()

	if fd >= 0 {
		_ = syscall.Close(fd)
	}
	if syscall.Unmount(fs.mountDir, syscall.MNT_DETACH) != nil && fs.fusermount != "" {
		_ = exec.Command(fs.fusermount, "-u", "-z", "--", fs.mountDir).Run()
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
			other := fs.usedBytesLocked() - int64(len(n.data))
			if other+int64(newSize) > fs.maxBytes {
				fs.replyErr(fd, unique, syscall.ENOSPC)
				return
			}
			sz := int(newSize)
			if sz < len(n.data) {
				n.data = n.data[:sz]
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
		if name == "" {
			fs.replyErr(fd, unique, syscall.EINVAL)
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
			if len(fs.inodes) >= fs.maxInodes {
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
			fs.inodes[cino] = cn
			parent.children[name] = cino
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
		if _, exists := parent.children[name]; exists {
			fs.replyErr(fd, unique, syscall.EEXIST)
			return
		}
		if len(fs.inodes) >= fs.maxInodes {
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
		fs.inodes[cino] = cn
		parent.children[name] = cino
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
		if _, exists := parent.children[name]; exists {
			fs.replyErr(fd, unique, syscall.EEXIST)
			return
		}
		if len(fs.inodes) >= fs.maxInodes {
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
		fs.inodes[cino] = cn
		parent.children[name] = cino
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
		delete(parent.children, name)
		if cn != nil {
			if cn.nlink > 0 {
				cn.nlink--
			}
			if cn.nlink == 0 && cn.openCount <= 0 {
				delete(fs.inodes, cino)
			}
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
		delete(parent.children, name)
		if parent.nlink > 2 {
			parent.nlink--
		}
		cn.nlink = 0
		if cn.openCount <= 0 {
			delete(fs.inodes, cino)
		}
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
					if dst.nlink == 0 && dst.openCount <= 0 {
						delete(fs.inodes, dstIno)
					}
				}
			}
		}
		delete(oldParent.children, oldName)
		newParent.children[newName] = srcIno
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
		target.nlink++
		parent.children[name] = oldIno
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
		if _, exists := parent.children[name]; exists {
			fs.replyErr(fd, unique, syscall.EEXIST)
			return
		}
		if len(fs.inodes) >= fs.maxInodes || fs.usedBytesLocked()+int64(len(target)) > fs.maxBytes {
			fs.replyErr(fd, unique, syscall.ENOSPC)
			return
		}
		cino := fs.nextIno
		fs.nextIno++
		cn := &fuseInode{
			ino:   cino,
			mode:  syscall.S_IFLNK | 0o777,
			nlink: 1,
			uid:   fs.uid,
			gid:   fs.gid,
			data:  []byte(target),
			mtime: time.Now().Unix(),
		}
		fs.inodes[cino] = cn
		parent.children[name] = cino
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
		if n, ok := fs.inodes[nodeid]; ok {
			n.openCount--
			if n.nlink == 0 && n.openCount <= 0 && nodeid != 1 {
				delete(fs.inodes, nodeid)
			}
		}
		fs.replyOK(fd, unique, nil)

	case fuseOpFlush, fuseOpFsync, fuseOpFsyncdir:
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
		other := fs.usedBytesLocked() - int64(len(n.data))
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
		other := fs.usedBytesLocked() - int64(len(n.data))
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
