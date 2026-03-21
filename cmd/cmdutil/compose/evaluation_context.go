package compose

import (
	"log/slog"
	"time"

	"github.com/spf13/cobra"

	appconfig "github.com/sufield/stave/internal/app/config"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/pkg/timeutil"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
	"github.com/sufield/stave/pkg/alpha/domain/ports"
)

// EvaluationContextInput holds raw flag values before parsing.
// All fields are strings — they come directly from Cobra flags.
type EvaluationContextInput struct {
	ControlsDir     string
	ObservationsDir string
	MaxUnsafe       string
	NowTime         string
	Format          string
}

// PreparedEvaluationContext holds parsed, validated evaluation parameters.
// It replaces the inline setup sequences that each command handler previously
// built independently.
type PreparedEvaluationContext struct {
	Clock           ports.Clock
	MaxUnsafe       time.Duration
	Format          ui.OutputFormat
	Sanitizer       kernel.Sanitizer
	ControlsDir     string
	ObservationsDir string
	Logger          *slog.Logger
	Evaluator       *appconfig.Evaluator
}

// PrepareEvaluationContext parses and validates raw flag values into a
// ready-to-use evaluation context. This centralizes the sequence:
// clean paths → parse duration → resolve clock → resolve format.
func PrepareEvaluationContext(
	cmd *cobra.Command,
	input EvaluationContextInput,
	evaluator *appconfig.Evaluator,
	logger *slog.Logger,
	sanitizer kernel.Sanitizer,
) (PreparedEvaluationContext, error) {
	ctlDir := fsutil.CleanUserPath(input.ControlsDir)
	obsDir := fsutil.CleanUserPath(input.ObservationsDir)

	var maxUnsafe time.Duration
	if input.MaxUnsafe != "" {
		d, err := timeutil.ParseDurationFlag(input.MaxUnsafe, "--max-unsafe")
		if err != nil {
			return PreparedEvaluationContext{}, err
		}
		maxUnsafe = d
	}

	clock, err := ResolveClock(input.NowTime)
	if err != nil {
		return PreparedEvaluationContext{}, err
	}

	format, err := ResolveFormatValue(cmd, input.Format)
	if err != nil {
		return PreparedEvaluationContext{}, err
	}

	return PreparedEvaluationContext{
		Clock:           clock,
		MaxUnsafe:       maxUnsafe,
		Format:          format,
		Sanitizer:       sanitizer,
		ControlsDir:     ctlDir,
		ObservationsDir: obsDir,
		Logger:          logger,
		Evaluator:       evaluator,
	}, nil
}
