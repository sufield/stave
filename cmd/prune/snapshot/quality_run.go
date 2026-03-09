package snapshot

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/cli/ui"
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

func runQuality(cmd *cobra.Command, flags *qualityFlagsType) error {
	runInput, err := prepareQualityInput(cmd, flags)
	if err != nil {
		return err
	}
	snapshots, err := compose.LoadSnapshots(compose.CommandContext(cmd), runInput.observationsDir)
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

func prepareQualityInput(cmd *cobra.Command, flags *qualityFlagsType) (qualityInput, error) {
	flags.observationsDir = fsutil.CleanUserPath(flags.observationsDir)
	if flags.minSnapshots < 1 {
		return qualityInput{}, fmt.Errorf("invalid --min-snapshots %d: must be >= 1", flags.minSnapshots)
	}
	maxStaleness, err := timeutil.ParseDurationFlag(flags.maxStaleness, "--max-staleness")
	if err != nil {
		return qualityInput{}, err
	}
	if maxStaleness < 0 {
		return qualityInput{}, fmt.Errorf("invalid --max-staleness %q: must be >= 0", flags.maxStaleness)
	}
	maxGap, err := timeutil.ParseDurationFlag(flags.maxGap, "--max-gap")
	if err != nil {
		return qualityInput{}, err
	}
	if maxGap < 0 {
		return qualityInput{}, fmt.Errorf("invalid --max-gap %q: must be >= 0", flags.maxGap)
	}
	now, err := compose.ResolveNow(flags.now)
	if err != nil {
		return qualityInput{}, err
	}
	format, err := compose.ResolveFormatValue(cmd, flags.format)
	if err != nil {
		return qualityInput{}, err
	}
	return qualityInput{
		observationsDir: flags.observationsDir,
		minSnapshots:    flags.minSnapshots,
		maxStaleness:    maxStaleness,
		maxGap:          maxGap,
		requiredAssets:  flags.required,
		now:             now,
		format:          format,
		strict:          flags.strict,
	}, nil
}
