package diff

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
)

func run(cmd *cobra.Command, opts *options) error {
	if opts == nil {
		opts = defaultOptions()
	}
	opts.normalize()

	format, err := opts.resolveFormat(cmd)
	if err != nil {
		return err
	}
	filter, err := opts.buildFilter()
	if err != nil {
		return err
	}

	rt := ui.NewRuntime(cmd.OutOrStdout(), cmd.ErrOrStderr())
	rt.Quiet = cmdutil.QuietEnabled(cmd)
	stop := rt.BeginProgress("Computing observation delta")
	out, err := compute(opts.ObservationsDir, filter)
	stop()
	if err != nil {
		return err
	}
	return writeOutput(cmd, cmd.OutOrStdout(), format, out)
}

func compute(observationsDir string, filter asset.FilterOptions) (asset.ObservationDelta, error) {
	loader, err := cmdutil.NewObservationRepository()
	if err != nil {
		return asset.ObservationDelta{}, fmt.Errorf("create observation loader: %w", err)
	}
	result, err := loader.LoadSnapshots(context.Background(), observationsDir)
	if err != nil {
		return asset.ObservationDelta{}, fmt.Errorf("load observations: %w", err)
	}
	if len(result.Snapshots) < 2 {
		return asset.ObservationDelta{}, fmt.Errorf("need at least 2 snapshots in %s for diff", observationsDir)
	}

	prev, curr, err := asset.LatestTwoSnapshots(result.Snapshots)
	if err != nil {
		return asset.ObservationDelta{}, fmt.Errorf("select latest snapshots: %w", err)
	}
	return asset.ComputeObservationDelta(prev, curr).ApplyFilter(filter), nil
}
