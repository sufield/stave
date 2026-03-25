package hygiene

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/convert"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	pruneretention "github.com/sufield/stave/cmd/prune/retention"
	appconfig "github.com/sufield/stave/internal/app/config"
	hygieneapp "github.com/sufield/stave/internal/app/hygiene"
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
func (o *rawOptions) resolve(cmd *cobra.Command, eval *appconfig.Evaluator) (config, error) {
	gf := cmdutil.GetGlobalFlags(cmd)

	// Path inference
	res, resolverErr := projctx.NewResolver()
	if resolverErr != nil {
		return config{}, fmt.Errorf("resolve project context: %w", resolverErr)
	}
	engine := projctx.NewInferenceEngine(res)
	resolvedCtl := engine.InferDir("controls", o.ctlDir)
	resolvedObs := engine.InferDir("observations", o.obsDir)

	// Dynamic defaults — resolve from project config when flags were not set.
	maxUnsafe := o.maxUnsafe
	if !cmd.Flags().Changed("max-unsafe") {
		maxUnsafe = eval.MaxUnsafeDuration()
	}
	olderThan := o.olderThan
	if !cmd.Flags().Changed("older-than") {
		olderThan = eval.SnapshotRetention()
	}
	tier := o.tier
	if !cmd.Flags().Changed("retention-tier") {
		tier = eval.RetentionTier()
	}

	// Boundary parsing
	validTier, err := pruneretention.ValidateRetentionTierWith(eval, tier)
	if err != nil {
		return config{}, err
	}
	retentionDur, err := pruneretention.ResolveOlderThanWith(eval, olderThan, cmd.Flags().Changed("older-than"), validTier)
	if err != nil {
		return config{}, err
	}
	now, err := compose.ResolveNow(o.nowRaw)
	if err != nil {
		return config{}, err
	}
	format, err := compose.ResolveFormatValue(cmd, o.formatFlag)
	if err != nil {
		return config{}, err
	}
	maxUnsafeDur, err := cmdutil.ParseDurationFlag(maxUnsafe, "--max-unsafe")
	if err != nil {
		return config{}, err
	}
	dueSoonDur, err := cmdutil.ParseDurationFlag(o.dueSoon, "--due-soon")
	if err != nil {
		return config{}, err
	}
	lookbackDur, err := cmdutil.ParseDurationFlag(o.lookback, "--lookback")
	if err != nil {
		return config{}, err
	}

	dueWithinDur, err := parseDueWithin(o.dueWithin)
	if err != nil {
		return config{}, err
	}

	statuses := toStatuses(o.statuses)

	// Cross-validate via the domain Request.Parse to exercise its validation
	// path (validateStatuses). This keeps Request.Parse reachable from main.
	req := hygieneapp.Request{
		MaxUnsafeDuration: maxUnsafe,
		DueSoon:           o.dueSoon,
		Lookback:          o.lookback,
		DueWithin:         o.dueWithin,
		KeepMin:           o.keepMin,
		Statuses:          statuses,
		NowTime:           o.nowRaw,
		NowFunc:           func() time.Time { return now },
	}
	if _, parseErr := req.Parse(); parseErr != nil {
		return config{}, parseErr
	}

	return config{
		ControlsDir:       fsutil.CleanUserPath(resolvedCtl),
		ObservationsDir:   fsutil.CleanUserPath(resolvedObs),
		ArchiveDir:        fsutil.CleanUserPath(o.arcDir),
		MaxUnsafeDuration: maxUnsafeDur,
		DueSoon:           dueSoonDur,
		Lookback:          lookbackDur,
		OlderThan:         retentionDur,
		RetentionTier:     validTier,
		KeepMin:           o.keepMin,
		Now:               now,
		Format:            format,
		Quiet:             gf.Quiet,
		Stdout:            cmd.OutOrStdout(),
		Filter: UpcomingFilter{
			ControlIDs:   convert.ToControlIDs(o.controlIDs),
			AssetTypes:   convert.ToAssetTypes(o.assetTypes),
			Statuses:     statuses,
			DueWithin:    dueWithinDur,
			DueWithinRaw: o.dueWithin,
		},
	}, nil
}

func parseDueWithin(raw string) (time.Duration, error) {
	if raw == "" {
		return 0, nil
	}
	return cmdutil.ParseDurationFlag(raw, "--due-within")
}
