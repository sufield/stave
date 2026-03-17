package hygiene

import (
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	pruneshared "github.com/sufield/stave/cmd/prune/shared"
	"github.com/sufield/stave/internal/pkg/timeutil"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// rawOptions holds the unparsed flag values captured by Cobra.
type rawOptions struct {
	ctlDir, obsDir, arcDir                        string
	maxUnsafe, dueSoon, lookback, olderThan, tier string
	keepMin                                       int
	nowRaw, formatFlag                            string
	controlIDs, assetTypes, statuses              []string
	dueWithin                                     string
}

// resolve parses and validates all raw flag values into a ready-to-use Config.
func (o *rawOptions) resolve(cmd *cobra.Command) (Config, error) {
	gf := cmdutil.GetGlobalFlags(cmd)
	eval := projconfig.Global()

	// Path inference
	res, _ := projctx.NewResolver()
	engine := projctx.NewInferenceEngine(res)
	resolvedCtl := engine.InferDir("controls", o.ctlDir)
	resolvedObs := engine.InferDir("observations", o.obsDir)

	// Dynamic defaults
	maxUnsafe := o.maxUnsafe
	if maxUnsafe == "" {
		maxUnsafe = eval.MaxUnsafe()
	}
	olderThan := o.olderThan
	if olderThan == "" {
		olderThan = eval.SnapshotRetention()
	}
	tier := o.tier
	if tier == "" {
		tier = eval.RetentionTier()
	}

	// Boundary parsing
	validTier, err := pruneshared.ValidateRetentionTier(tier)
	if err != nil {
		return Config{}, err
	}
	retentionDur, err := pruneshared.ResolveOlderThan(olderThan, cmd.Flags().Changed("older-than"), validTier)
	if err != nil {
		return Config{}, err
	}
	now, err := compose.ResolveNow(o.nowRaw)
	if err != nil {
		return Config{}, err
	}
	format, err := compose.ResolveFormatValue(cmd, o.formatFlag)
	if err != nil {
		return Config{}, err
	}
	maxUnsafeDur, err := timeutil.ParseDurationFlag(maxUnsafe, "--max-unsafe")
	if err != nil {
		return Config{}, err
	}
	dueSoonDur, err := timeutil.ParseDurationFlag(o.dueSoon, "--due-soon")
	if err != nil {
		return Config{}, err
	}
	lookbackDur, err := timeutil.ParseDurationFlag(o.lookback, "--lookback")
	if err != nil {
		return Config{}, err
	}

	return Config{
		ControlsDir:     fsutil.CleanUserPath(resolvedCtl),
		ObservationsDir: fsutil.CleanUserPath(resolvedObs),
		ArchiveDir:      fsutil.CleanUserPath(o.arcDir),
		MaxUnsafe:       maxUnsafeDur,
		DueSoon:         dueSoonDur,
		Lookback:        lookbackDur,
		OlderThan:       retentionDur,
		RetentionTier:   validTier,
		KeepMin:         o.keepMin,
		Now:             now,
		Format:          format,
		Quiet:           gf.Quiet,
		Stdout:          cmd.OutOrStdout(),
		Filter: UpcomingFilter{
			ControlIDs:   cmdutil.ToControlIDs(o.controlIDs),
			AssetTypes:   cmdutil.ToAssetTypes(o.assetTypes),
			Statuses:     toStatuses(o.statuses),
			DueWithin:    parseDueWithin(o.dueWithin),
			DueWithinRaw: o.dueWithin,
		},
	}, nil
}

func parseDueWithin(raw string) time.Duration {
	if raw == "" {
		return 0
	}
	d, _ := timeutil.ParseDurationFlag(raw, "--due-within")
	return d
}
