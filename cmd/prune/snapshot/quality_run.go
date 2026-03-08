package snapshot

import (
	"context"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/pkg/timeutil"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type qualityFlagsType struct {
	observationsDir           string
	maxStaleness, maxGap, now string
	format                    string
	required                  []string
	minSnapshots              int
	strict                    bool
}

var qualityFlags qualityFlagsType

func runQuality(cmd *cobra.Command, _ []string) error {
	runInput, err := prepareQualityInput(cmd)
	if err != nil {
		return err
	}
	snapshots, err := loadQualitySnapshots(cmdutil.CommandContext(cmd), runInput.observationsDir)
	if err != nil {
		return err
	}

	report := assessQuality(qualityParams{
		Snapshots:         snapshots,
		Now:               runInput.now,
		MinSnapshots:      runInput.minSnapshots,
		MaxStaleness:      runInput.maxStaleness,
		MaxGap:            runInput.maxGap,
		RequiredResources: runInput.requiredAssets,
		Strict:            runInput.strict,
	})

	if err := writeQualityOutput(cmd.OutOrStdout(), runInput.format, report, cmdutil.QuietEnabled(cmd)); err != nil {
		return err
	}
	if !report.Pass {
		return ui.ErrViolationsFound
	}
	return nil
}

func prepareQualityInput(cmd *cobra.Command) (qualityInput, error) {
	qualityFlags.observationsDir = fsutil.CleanUserPath(qualityFlags.observationsDir)
	if err := validateMinSnapshots(); err != nil {
		return qualityInput{}, err
	}
	maxStaleness, maxGap, err := parseQualityDurations()
	if err != nil {
		return qualityInput{}, err
	}
	now, err := resolveQualityNow()
	if err != nil {
		return qualityInput{}, err
	}
	format, err := resolveQualityFormat(cmd)
	if err != nil {
		return qualityInput{}, err
	}
	return qualityInput{
		observationsDir: qualityFlags.observationsDir,
		minSnapshots:    qualityFlags.minSnapshots,
		maxStaleness:    maxStaleness,
		maxGap:          maxGap,
		requiredAssets:  qualityFlags.required,
		now:             now,
		format:          format,
		strict:          qualityFlags.strict,
	}, nil
}

func validateMinSnapshots() error {
	if qualityFlags.minSnapshots >= 1 {
		return nil
	}
	return fmt.Errorf("invalid --min-snapshots %d: must be >= 1", qualityFlags.minSnapshots)
}

func parseQualityDurations() (time.Duration, time.Duration, error) {
	maxStaleness, err := timeutil.ParseDurationFlag(qualityFlags.maxStaleness, "--max-staleness")
	if err != nil {
		return 0, 0, err
	}
	if maxStaleness < 0 {
		return 0, 0, fmt.Errorf("invalid --max-staleness %q: must be >= 0", qualityFlags.maxStaleness)
	}
	maxGap, err := timeutil.ParseDurationFlag(qualityFlags.maxGap, "--max-gap")
	if err != nil {
		return 0, 0, err
	}
	if maxGap < 0 {
		return 0, 0, fmt.Errorf("invalid --max-gap %q: must be >= 0", qualityFlags.maxGap)
	}
	return maxStaleness, maxGap, nil
}

func resolveQualityNow() (time.Time, error) {
	return cmdutil.ResolveNow(qualityFlags.now)
}

func resolveQualityFormat(cmd *cobra.Command) (ui.OutputFormat, error) {
	return cmdutil.ResolveFormatValue(cmd, qualityFlags.format)
}

func loadQualitySnapshots(ctx context.Context, observationsDir string) ([]asset.Snapshot, error) {
	loader, err := cmdutil.NewObservationRepository()
	if err != nil {
		return nil, fmt.Errorf("create observation loader: %w", err)
	}
	result, err := loader.LoadSnapshots(ctx, observationsDir)
	if err != nil {
		return nil, fmt.Errorf("load observations: %w", err)
	}
	return result.Snapshots, nil
}
