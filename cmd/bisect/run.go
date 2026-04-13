package bisect

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cmdctx"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	appbisect "github.com/sufield/stave/internal/app/bisect"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/engine"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/platform/fsutil"
)

func runBisect(cmd *cobra.Command, opts *options) error {
	if err := opts.validate(); err != nil {
		return err
	}

	logger := cmdctx.LoggerFromCmd(cmd)
	controlsDir := fsutil.CleanUserPath(opts.ControlsDir)
	obsDir := fsutil.CleanUserPath(opts.ObsDir)

	// Load controls.
	f := compose.DefaultFactories()
	ctlRepo, err := f.NewCtlRepo()
	if err != nil {
		return fmt.Errorf("create control loader: %w", err)
	}
	controls, err := ctlRepo.LoadControls(cmd.Context(), controlsDir)
	if err != nil {
		return fmt.Errorf("load controls from %s: %w", controlsDir, err)
	}

	// Find the target control.
	targetID := kernel.ControlID(opts.ControlID)
	target, found := appbisect.FindControl(controls, targetID)
	if !found {
		return fmt.Errorf("control %s not found in %s", targetID, controlsDir)
	}

	// Load snapshot archive.
	snapshots, err := appbisect.LoadSnapshotDir(obsDir, fsutil.ReadFileLimited, logger)
	if err != nil {
		return err
	}

	// Resolve clock.
	var clock ports.Clock = ports.RealClock{}
	if opts.Now != "" {
		t, parseErr := time.Parse(time.RFC3339, opts.Now)
		if parseErr != nil {
			return fmt.Errorf("invalid --now: %w", parseErr)
		}
		clock = ports.FixedClock(t)
	}

	// Resolve CEL evaluator.
	celEval, err := f.NewCELEvaluator()
	if err != nil {
		return fmt.Errorf("create CEL evaluator: %w", err)
	}

	// Build evaluator function for the single control.
	evaluator := appbisect.MakeEvaluator(
		func(snaps []asset.Snapshot) (evaluation.ComplianceReport, error) {
			a := engine.NewAssessor()
			a.Controls = []policy.ControlDefinition{target}
			a.Clock = clock
			a.PredicateEval = celEval
			return a.Assess(snaps)
		},
		targetID,
		opts.ResourceARN,
	)

	// Parse mode.
	modeInt, _ := parseMode(opts.Mode)
	mode := appbisect.Mode(modeInt)

	// Run.
	eng := &appbisect.Engine{Evaluate: evaluator}
	result, err := eng.Run(cmd.Context(), snapshots, mode, string(targetID), opts.ResourceARN)
	if err != nil {
		return err
	}

	// Output.
	return writeOutput(cmd.OutOrStdout(), cmd.ErrOrStderr(), result, opts.Format, logger)
}
