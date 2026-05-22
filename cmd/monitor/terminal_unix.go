//go:build unix

package monitor

import "syscall"

// isTerminalFd reports whether the given file descriptor refers to
// a character device (a terminal). The earlier shape ignored the fd
// parameter and always Stat'd os.Stdin, so callers asking about a
// non-stdin fd (e.g. checking stdout for live-display compatibility)
// got the wrong answer when the binary was invoked with stdin
// redirected from a file but stdout still attached to the terminal.
//
// Uses syscall.Fstat directly rather than wrapping the fd in
// os.NewFile. The wrapper attaches a finalizer that, on GC, would
// close the underlying descriptor — for fd 0 (stdin) that meant a
// later read from stdin returned EBADF after the wrapper was
// reclaimed. Fstat on the raw fd has no such side effect.
func isTerminalFd(fd uintptr) bool {
	var stat syscall.Stat_t
	if err := syscall.Fstat(int(fd), &stat); err != nil { //nolint:gosec // file descriptors fit in int on every supported platform
		return false
	}
	return stat.Mode&syscall.S_IFCHR != 0
}
