package hygiene

import (
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/cmdctx"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/convert"
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

	// Captured in prepare so resolve is cobra-free.
	maxUnsafeSet bool
	olderThanSet bool
	tierSet      bool
	formatSet    bool
	eval         *appconfig.Evaluator
	gf           cliflags.GlobalFlags
}

// prepare captures cobra state for resolve. Called from PreRunE.
func (o *rawOptions) prepare(cmd *cobra.Command) error {
	o.maxUnsafeSet = cmd.Flags().Changed("max-unsafe")
	o.olderThanSet = cmd.Flags().Changed("older-than")
	o.tierSet = cmd.Flags().Changed("retention-tier")
	o.formatSet = cmd.Flags().Changed("format")
	o.eval = cmdctx.EvaluatorFromCmd(cmd)
	o.gf = cliflags.GetGlobalFlags(cmd)
	return nil
}

// resolve parses and validates all raw flag values into a ready-to-use Config.
// Does not take *cobra.Command — all cobra state was captured in prepare.
func (o *rawOptions) resolve(stdout io.Writer) (config, error) {
	eval := o.eval

	// Dynamic defaults — resolve from project config when flags were not set.
	maxUnsafe := o.maxUnsafe
	if !o.maxUnsafeSet {
		maxUnsafe = eval.MaxUnsafeDuration()
	}
	olderThan := o.olderThan
	if !o.olderThanSet {
		olderThan = eval.SnapshotRetention()
	}
	tier := o.tier
	if !o.tierSet {
		tier = eval.RetentionTier()
	}

	// Common evaluation context: path inference + now/format/max-unsafe.
	ec, err := compose.PrepareEvaluationContext(compose.EvalContextRequest{
		ControlsDir:                o.ctlDir,
		ObservationsDir:            o.obsDir,
		MaxUnsafeDuration:          maxUnsafe,
		NowTime:                    o.nowRaw,
		Format:                     o.formatFlag,
		FormatChanged:              o.formatSet,
		SkipControlsValidation:     true,
		SkipObservationsValidation: true,
	})
	if err != nil {
		return config{}, err
	}

	// Hygiene-specific boundary parsing.
	validTier, err := pruneretention.ValidateRetentionTierWith(eval, tier)
	if err != nil {
		return config{}, err
	}
	retentionDur, err := pruneretention.ResolveOlderThanWith(eval, olderThan, o.olderThanSet, validTier)
	if err != nil {
		return config{}, err
	}
	dueSoonDur, err := cliflags.ParseDurationFlag(o.dueSoon, "--due-soon")
	if err != nil {
		return config{}, err
	}
	lookbackDur, err := cliflags.ParseDurationFlag(o.lookback, "--lookback")
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
		NowFunc:           func() time.Time { return ec.Now },
	}
	if _, parseErr := req.Parse(); parseErr != nil {
		return config{}, parseErr
	}

	return config{
		ControlsDir:       ec.ControlsDir,
		ObservationsDir:   ec.ObservationsDir,
		ArchiveDir:        fsutil.CleanUserPath(o.arcDir),
		MaxUnsafeDuration: ec.MaxUnsafe,
		DueSoon:           dueSoonDur,
		Lookback:          lookbackDur,
		OlderThan:         retentionDur,
		RetentionTier:     validTier,
		KeepMin:           o.keepMin,
		Now:               ec.Now,
		Format:            ec.Format,
		Quiet:             o.gf.Quiet,
		Stdout:            stdout,
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
	return cliflags.ParseDurationFlag(raw, "--due-within")
}
