//go:build unix

package e2e_test

import (
	"os/exec"
	"syscall"
)

// setProcessGroup puts the child in its own process group so a SIGKILL
// to -PID reaches any grandchildren the binary might spawn.
func setProcessGroup(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// killProcessGroup sends SIGKILL to the entire process group of cmd.
// Used on context-deadline timeout so a wedged stave subprocess tree
// does not keep stdout open and hang cmd.Run() past ctx cancellation.
func killProcessGroup(cmd *exec.Cmd) {
	if cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}
