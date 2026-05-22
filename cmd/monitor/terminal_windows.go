//go:build windows

package monitor

import "golang.org/x/sys/windows"

// isTerminalFd reports whether the given file descriptor refers to a
// console (the Windows analogue of a terminal). GetConsoleMode
// succeeds only on a handle backed by a real console; it fails with
// ERROR_INVALID_HANDLE when stdin/stdout is redirected from a file or
// pipe, which is exactly the "not a terminal" answer the caller wants.
func isTerminalFd(fd uintptr) bool {
	var mode uint32
	return windows.GetConsoleMode(windows.Handle(fd), &mode) == nil
}
