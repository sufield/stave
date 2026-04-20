package bisect

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"time"

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

// Input is the per-run payload the bisect command's RunE assembles
// at the adapter boundary. All cobra-owned values are pre-resolved
// so runBisect runs on plain data. Context is passed as a function
// argument per Go convention, not stored on the struct.
type Input struct {
	Stdout io.Writer
	Stderr io.Writer
	Logger *slog.Logger
	Opts   *options
}

func runBisect(ctx context.Context, in Input) error {
	opts := in.Opts
	if err := opts.validate(); err != nil {
		return err
	}

	controlsDir := fsutil.CleanUserPath(opts.ControlsDir)
	obsDir := fsutil.CleanUserPath(opts.ObsDir)

	// Load controls.
	f := compose.DefaultFactories()
	ctlRepo, err := f.NewCtlRepo()
	if err != nil {
		return fmt.Errorf("create control loader: %w", err)
	}
	controls, err := ctlRepo.LoadControls(ctx, controlsDir)
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
	snapshots, err := appbisect.LoadSnapshotDir(obsDir, fsutil.ReadFileLimited, in.Logger)
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
	result, err := eng.Run(ctx, snapshots, mode, string(targetID), opts.ResourceARN)
	if err != nil {
		return err
	}

	// Output.
	return writeOutput(in.Stdout, in.Stderr, result, opts.Format, in.Logger)
}
