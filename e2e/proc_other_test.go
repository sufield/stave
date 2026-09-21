//go:build !unix

package e2e_test

import "os/exec"

//nolint:unused
func setProcessGroup(cmd *exec.Cmd) {}

//nolint:unused
func killProcessGroup(cmd *exec.Cmd) {}
