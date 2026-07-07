package compliance

import (
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/compliancemapping"
)

// options holds the parsed flags for `stave compliance`.
type options struct {
	framework     string
	snapshot      string
	controls      string
	controlsSet   bool
	format        string
	evalTime      string
	strict        bool
	verifyMapping bool
}

// Prepare resolves and validates flags at the CLI boundary (PreRunE).
func (o *options) Prepare(cmd *cobra.Command) error {
	o.controlsSet = cmd.Flags().Changed("controls")

	if _, err := compliancemapping.Load(o.framework); err != nil {
		return &ui.UserError{Err: err} // unknown framework → exit 2
	}
	// --verify-mapping checks the mapping against the catalog only; it needs no
	// snapshot. Every other mode evaluates a snapshot.
	if o.snapshot == "" && !o.verifyMapping {
		return &ui.UserError{Err: errSnapshotRequired}
	}
	if o.snapshot != "" && o.snapshot != "-" {
		o.snapshot = filepath.Clean(o.snapshot)
	}
	if o.controlsSet {
		o.controls = filepath.Clean(o.controls)
	}
	// Fail fast on an unknown --format at the boundary, not mid-render.
	if _, err := NewRenderer(o.format); err != nil {
		return &ui.UserError{Err: err}
	}
	return nil
}
