// SPDX-License-Identifier: MIT

//go:build unix

package safety

import (
	"errors"
	"fmt"
	"os"
	"syscall"
)

func lockJournalFile(f *os.File) error {
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
			return fmt.Errorf("%w: %s is held by another active process", ErrJournalLeaseBusy, f.Name())
		}
		return fmt.Errorf("flock %s: %w", f.Name(), err)
	}
	return nil
}

func unlockJournalFile(f *os.File) error {
	if f == nil {
		return nil
	}
	return syscall.Flock(int(f.Fd()), syscall.LOCK_UN)
}

func verifyFileOwnerUID(info os.FileInfo, path string) error {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	uid := uint32(os.Geteuid())
	if st.Uid != uid {
		return fmt.Errorf("safety path %q is owned by uid %d, want current euid %d", path, st.Uid, uid)
	}
	return nil
}
