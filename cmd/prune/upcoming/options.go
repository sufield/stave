package upcoming

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/cmdctx"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// options holds the raw CLI flag values for the upcoming command.
type options struct {
	CtlDir     string
	ObsDir     string
	MaxUnsafe  string
	DueSoon    string
	NowRaw     string
	FormatFlag string
	DueWithin  string
	ControlIDs []string
	AssetTypes []string
	Statuses   []string
}

// BindFlags attaches the options to a Cobra command.
func (o *options) BindFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&o.CtlDir, "controls", "i", o.CtlDir, "Path to control definitions directory")
	f.StringVarP(&o.ObsDir, "observations", "o", o.ObsDir, "Path to observation snapshots directory")
	f.StringVar(&o.MaxUnsafe, "max-unsafe", "", cliflags.WithDynamicDefaultHelp("Maximum allowed unsafe duration (e.g., 24h, 7d)"))
	f.StringVar(&o.NowRaw, "now", "", "Override current time (RFC3339). If omitted, uses wall clock")
	f.StringVar(&o.DueSoon, "due-soon", o.DueSoon, "Threshold for 'due soon' reminders (e.g., 4h, 1d)")
	f.StringVarP(&o.FormatFlag, "format", "f", o.FormatFlag, "Output format: text or json")
	f.StringSliceVar(&o.ControlIDs, "control-id", nil, "Filter to one or more control IDs")
	f.StringSliceVar(&o.AssetTypes, "asset-type", nil, "Filter to one or more asset types")
	f.StringSliceVar(&o.Statuses, "status", nil, "Filter status: OVERDUE, DUE_NOW, UPCOMING")
	f.StringVar(&o.DueWithin, "due-within", "", "Filter to items due within duration from --now (e.g., 24h, 3d)")
	_ = cmd.RegisterFlagCompletionFunc("format", cliflags.CompleteFixed("text", "json"))
	_ = cmd.RegisterFlagCompletionFunc("status", cliflags.CompleteFixed("OVERDUE", "DUE_NOW", "UPCOMING"))
}

// Prepare resolves config defaults and normalizes paths. Called from PreRunE.
func (o *options) Prepare(cmd *cobra.Command) error {
	o.resolveConfigDefaults(cmd)
	o.normalize()
	return nil
}

// resolveConfigDefaults fills flag values from project config when the user
// did not set them explicitly on the command line.
func (o *options) resolveConfigDefaults(cmd *cobra.Command) {
	if !cmd.Flags().Changed("max-unsafe") {
		o.MaxUnsafe = cmdctx.EvaluatorFromCmd(cmd).MaxUnsafeDuration()
	}
}

// normalize cleans user-supplied paths.
func (o *options) normalize() {
	o.CtlDir = fsutil.CleanUserPath(o.CtlDir)
	o.ObsDir = fsutil.CleanUserPath(o.ObsDir)
}
