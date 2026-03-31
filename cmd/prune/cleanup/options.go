package cleanup

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/cmdctx"
	pruneretention "github.com/sufield/stave/cmd/prune/retention"
	appconfig "github.com/sufield/stave/internal/app/config"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// options holds the raw CLI flag values for the cleanup (prune) command.
type options struct {
	ObsDir     string
	OlderThan  string
	Tier       string
	NowRaw     string
	KeepMin    int
	DryRun     bool
	FormatFlag string

	// Captured in Prepare so resolveRetention is cobra-free.
	olderThanSet bool
	tierSet      bool
	formatSet    bool
	eval         *appconfig.Evaluator
}

// BindFlags attaches the options to a Cobra command.
func (o *options) BindFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&o.ObsDir, "observations", "o", o.ObsDir, "Path to observation snapshots directory")
	f.StringVar(&o.OlderThan, "older-than", "", cliflags.WithDynamicDefaultHelp("Prune snapshots older than this age (e.g., 14d, 720h)"))
	f.StringVar(&o.Tier, "retention-tier", "", cliflags.WithDynamicDefaultHelp("Retention tier from stave.yaml snapshot_retention_tiers (e.g., critical, non_critical)"))
	f.StringVar(&o.NowRaw, "now", "", "Reference time (RFC3339). If omitted, uses wall clock")
	f.IntVar(&o.KeepMin, "keep-min", o.KeepMin, "Minimum number of snapshots to keep")
	f.BoolVar(&o.DryRun, "dry-run", false, "Preview planned file operations without applying them")
	f.StringVarP(&o.FormatFlag, "format", "f", o.FormatFlag, "Output format: text or json")
	_ = cmd.RegisterFlagCompletionFunc("format", cliflags.CompleteFixed(cliflags.FormatsTextJSON...))
}

// Prepare captures cobra state and normalizes paths. Called from PreRunE.
func (o *options) Prepare(cmd *cobra.Command) error {
	if cmd != nil {
		o.olderThanSet = cmd.Flags().Changed("older-than")
		o.tierSet = cmd.Flags().Changed("retention-tier")
		o.formatSet = cmd.Flags().Changed("format")
		o.eval = cmdctx.EvaluatorFromCmd(cmd)
	}
	o.ObsDir = fsutil.CleanUserPath(o.ObsDir)
	return nil
}

// resolveRetention resolves the retention parameters from config and flags.
// Does not take *cobra.Command — all cobra state was captured in Prepare.
func (o *options) resolveRetention() (pruneretention.ResolvedRetention, error) {
	return pruneretention.ResolveRetention(
		pruneretention.RawRetentionOpts{OlderThan: o.OlderThan, Tier: o.Tier, NowRaw: o.NowRaw, FormatFlag: o.FormatFlag},
		o.eval,
		o.olderThanSet, o.tierSet, o.formatSet, false,
	)
}
