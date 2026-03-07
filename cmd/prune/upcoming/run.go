package upcoming

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/pkg/timeutil"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type upcomingFlagsType struct {
	controlsDir, observationsDir string
	maxUnsafe, now, dueSoon      string
	format, dueWithin            string
	controlIDs, assetTypes       []string
	statuses                     []string
}

var upcomingFlags upcomingFlagsType

func runUpcoming(cmd *cobra.Command, _ []string) error {
	opts, err := gatherUpcomingOptions(cmd)
	if err != nil {
		return err
	}

	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}
	loaded, err := cmdutil.LoadObsAndInv(ctx, opts.ObservationsDir, opts.ControlsDir)
	if err != nil {
		return err
	}
	snapshots := loaded.Snapshots
	controls := loaded.Controls

	items := computeUpcomingItems(snapshots, controls, UpcomingComputeOptions{
		GlobalMaxUnsafe: opts.MaxUnsafe,
		Now:             opts.Now,
	})
	items = applyUpcomingFilter(items, opts.Now, opts.Filter)
	if san := cmdutil.GetSanitizer(cmd); san != nil {
		items = sanitizeUpcomingItems(san, items)
	}
	summary := summarizeUpcoming(items, opts.DueSoon)
	report := renderUpcomingMarkdown(items, summary, UpcomingRenderOptions{
		Now:              opts.Now,
		DueSoonThreshold: opts.DueSoon,
	})
	jsonOut := buildUpcomingOutput(opts, summary, items)

	if !cmdutil.QuietEnabled(cmd) {
		return writeUpcomingOutput(opts.Format, cmd.OutOrStdout(), report, jsonOut)
	}
	return nil
}

func gatherUpcomingOptions(cmd *cobra.Command) (upcomingRunOptions, error) {
	opts := upcomingRunOptions{
		ControlsDir:     fsutil.CleanUserPath(upcomingFlags.controlsDir),
		ObservationsDir: fsutil.CleanUserPath(upcomingFlags.observationsDir),
		MaxUnsafeRaw:    strings.TrimSpace(upcomingFlags.maxUnsafe),
		DueSoonRaw:      strings.TrimSpace(upcomingFlags.dueSoon),
	}

	maxUnsafeDur, err := timeutil.ParseDuration(opts.MaxUnsafeRaw)
	if err != nil {
		return upcomingRunOptions{}, fmt.Errorf("invalid --max-unsafe %q (use format: 168h, 7d, or 1d12h)", upcomingFlags.maxUnsafe)
	}
	dueSoonDur, err := timeutil.ParseDuration(opts.DueSoonRaw)
	if err != nil {
		return upcomingRunOptions{}, fmt.Errorf("invalid --due-soon %q (use format: 24h, 1d, or 1d12h)", upcomingFlags.dueSoon)
	}
	if dueSoonDur < 0 {
		return upcomingRunOptions{}, fmt.Errorf("invalid --due-soon %q: must be >= 0", upcomingFlags.dueSoon)
	}

	var dueWithinDur *time.Duration
	if strings.TrimSpace(upcomingFlags.dueWithin) != "" {
		parsedDueWithin, parseErr := timeutil.ParseDuration(upcomingFlags.dueWithin)
		if parseErr != nil {
			return upcomingRunOptions{}, fmt.Errorf("invalid --due-within %q (use format: 24h, 1d, or 1d12h)", upcomingFlags.dueWithin)
		}
		if parsedDueWithin < 0 {
			return upcomingRunOptions{}, fmt.Errorf("invalid --due-within %q: must be >= 0", upcomingFlags.dueWithin)
		}
		dueWithinDur = &parsedDueWithin
	}

	now, err := cmdutil.ResolveNow(upcomingFlags.now)
	if err != nil {
		return upcomingRunOptions{}, err
	}
	format, err := cmdutil.ResolveFormatValue(cmd, upcomingFlags.format)
	if err != nil {
		return upcomingRunOptions{}, err
	}
	filter, err := newUpcomingFilter(UpcomingFilterCriteria{
		ControlIDs: toControlIDs(upcomingFlags.controlIDs),
		AssetTypes: toAssetTypes(upcomingFlags.assetTypes),
		Statuses:   upcomingFlags.statuses,
		DueWithin:  dueWithinDur,
	})
	if err != nil {
		return upcomingRunOptions{}, err
	}

	opts.MaxUnsafe = maxUnsafeDur
	opts.DueSoon = dueSoonDur
	opts.Now = now
	opts.Format = format
	opts.Filter = filter
	return opts, nil
}
