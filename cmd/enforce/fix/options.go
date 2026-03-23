package fix

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/platform/fsutil"
)

// fixOptions holds the raw CLI flag values for the fix command.
type fixOptions struct {
	InputPath  string
	FindingRef string
}

// BindFlags attaches the options to a Cobra command.
func (o *fixOptions) BindFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&o.InputPath, "input", "", "Path to evaluation JSON (required)")
	f.StringVar(&o.FindingRef, "finding", "", "Finding selector: <control_id>@<asset_id> (required)")
	_ = cmd.MarkFlagRequired("input")
	_ = cmd.MarkFlagRequired("finding")
}

// Prepare normalizes paths. Called from PreRunE.
func (o *fixOptions) Prepare(_ *cobra.Command) error {
	o.InputPath = fsutil.CleanUserPath(o.InputPath)
	return nil
}
