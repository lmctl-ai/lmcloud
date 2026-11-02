// SPDX-License-Identifier: MIT

//go:build windows

package safety

import (
	"errors"
	"os"
)

func lockJournalFile(_ *os.File) error {
	return errors.New("live journal locking is not supported on Windows; live mode is refused on Windows")
}

func unlockJournalFile(_ *os.File) error {
	return nil
}

func verifyFileOwnerUID(_ os.FileInfo, _ string) error {
	return errors.New("live journal ownership verification is not supported on Windows; live mode is refused on Windows")
}
