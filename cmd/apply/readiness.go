package apply

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

// ReadinessConfig defines the parsed, validated parameters for readiness
// assessment. All fields are native types — flag string parsing happens
// before construction in ResolveDryRun.
type ReadinessConfig struct {
	ControlsDir       string
	ObservationsDir   string
	MaxUnsafeDuration time.Duration
	EvalTime          time.Time
	Format            cmdutil.OutputFormat
	Quiet             bool
	Sanitize          bool
	Stdout            io.Writer

	ControlsFlagSet        bool
	HasEnabledControlPacks bool
	EnabledPacks           []string
}

// runDryRun performs only readiness checks (apply --dry-run). The assessment,
// prerequisite checks, and plan rendering live in the pkg/stave facade
// (stave.AssessReadiness); the command writes the rendered bytes (quiet-gated)
// and maps a not-ready result to the validation exit code.
func runDryRun(ctx context.Context, cfg ReadinessConfig) error {
	out, ready, err := stave.AssessReadiness(ctx, stave.ReadinessRequest{
		ControlsDir:            cfg.ControlsDir,
		ObservationsDir:        cfg.ObservationsDir,
		MaxUnsafe:              cfg.MaxUnsafeDuration,
		EvalTime:               cfg.EvalTime,
		Sanitize:               cfg.Sanitize,
		Format:                 string(cfg.Format),
		ControlsFlagSet:        cfg.ControlsFlagSet,
		HasEnabledControlPacks: cfg.HasEnabledControlPacks,
	}, cfg.EnabledPacks, "")
	if err != nil {
		return err //nolint:wrapcheck // facade already wrapped; preserve exit codes.
	}

	if !cfg.Quiet {
		if _, werr := cfg.Stdout.Write(out); werr != nil {
			return fmt.Errorf("write readiness report: %w", werr)
		}
	}
	if !ready {
		return ui.ErrValidationFailed
	}
	return nil
}
