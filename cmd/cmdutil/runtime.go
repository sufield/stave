package cmdutil

import (
	"io"

	"github.com/sufield/stave/internal/cli/ui"
)

// NewRuntime initializes a UI runtime using explicit output streams.
// This allows the UI logic to remain independent of the CLI framework.
func NewRuntime(stdout, stderr io.Writer, quiet bool) *ui.Runtime {
	rt := ui.NewRuntime(stdout, stderr)
	rt.Quiet = quiet
	return rt
}

// NewRuntimeFromFlags is a convenience helper that bridges CLI state to the UI.
// It uses the GlobalFlags struct refactored in previous steps.
func NewRuntimeFromFlags(stdout, stderr io.Writer, flags GlobalFlags) *ui.Runtime {
	return NewRuntime(stdout, stderr, flags.Quiet)
}
