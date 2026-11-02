// SPDX-License-Identifier: MIT

//go:build windows

package fakeadapter

// Windows test runs are single-process per scenario step; the in-process mutex
// is the only guard. Do not run concurrent fake hosts on one state file there.
type fileLock struct{}

func lockFile(string) (*fileLock, error) { return &fileLock{}, nil }

func (l *fileLock) unlock() {}
