package compose

import (
	"fmt"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/dircheck"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// EvalContextRequest groups the raw CLI values for common evaluation setup.
// Commands fill in the fields they need; unused fields use zero values.
type EvalContextRequest struct {
	// Directory paths (raw flag values).
	ControlsDir     string
	ObservationsDir string
	ControlsChanged bool
	ObsChanged      bool

	// Common flag values (raw strings).
	MaxUnsafeDuration string
	NowTime           string
	Format            string
	FormatChanged     bool
	IsJSONMode        bool

	// Options — control which resolution steps run.
	SkipPathInference          bool // skip resolver/engine/inference (e.g., gate)
	SkipControlsValidation     bool // skip controls dir existence check (e.g., packs, stdin)
	SkipObservationsValidation bool // skip observations dir existence check (e.g., stdin)
	SkipMaxUnsafe              bool // skip --max-unsafe parsing
	SkipClock                  bool // skip --now / clock resolution
	SkipFormat                 bool // skip --format parsing
}

// EvalContext holds resolved evaluation parameters. Fields are populated
// based on which resolution steps were requested (see Skip* fields above).
type EvalContext struct {
	// Project context — nil when SkipPathInference is true.
	Resolver *projctx.Resolver
	Engine   *projctx.InferenceEngine

	// Resolved directory paths (inferred and cleaned).
	ControlsDir     string
	ObservationsDir string

	// Parsed common flag values.
	MaxUnsafe time.Duration
	Clock     ports.Clock
	Now       time.Time
	Format    ui.OutputFormat
}

// PrepareEvaluationContext resolves common evaluation parameters from raw CLI
// flags. This centralizes the repeated setup that most evaluation commands
// perform: project context resolution, path inference, directory validation,
// and common flag parsing.
//
// The function is cobra-free — callers extract flag-changed booleans from
// cobra before calling. This makes the function testable without a command tree.
func PrepareEvaluationContext(req EvalContextRequest) (EvalContext, error) {
	var ec EvalContext

	if err := resolvePaths(&ec, req); err != nil {
		return EvalContext{}, err
	}
	if err := resolveFlags(&ec, req); err != nil {
		return EvalContext{}, err
	}

	return ec, nil
}

// resolvePaths handles directory inference, cleaning, and validation.
func resolvePaths(ec *EvalContext, req EvalContextRequest) error {
	if req.SkipPathInference {
		ec.ControlsDir = fsutil.CleanUserPath(req.ControlsDir)
		ec.ObservationsDir = fsutil.CleanUserPath(req.ObservationsDir)
		return nil
	}

	resolver, err := projctx.NewResolver()
	if err != nil {
		return ui.WithHint(
			fmt.Errorf("resolve project context: %w", err),
			ui.ErrHintProjectContext,
		)
	}
	engine := projctx.NewInferenceEngine(resolver)
	ec.Resolver = resolver
	ec.Engine = engine

	ec.ControlsDir = fsutil.CleanUserPath(req.ControlsDir)
	ec.ObservationsDir = fsutil.CleanUserPath(req.ObservationsDir)

	if !req.ControlsChanged {
		if inferred := engine.InferDir("controls", ""); inferred != "" {
			ec.ControlsDir = inferred
		}
	}
	if !req.ObsChanged {
		if inferred := engine.InferDir("observations", ""); inferred != "" {
			ec.ObservationsDir = inferred
		}
	}

	if !req.SkipControlsValidation {
		if err := dircheck.ValidateFlagDir("--controls", ec.ControlsDir, "controls", ui.ErrHintControlsNotAccessible, engine.Log); err != nil {
			return err
		}
	}
	if !req.SkipObservationsValidation {
		if err := dircheck.ValidateFlagDir("--observations", ec.ObservationsDir, "observations", ui.ErrHintObservationsNotAccessible, engine.Log); err != nil {
			return err
		}
	}
	return nil
}

// resolveFlags parses common flag values (max-unsafe, clock, format).
func resolveFlags(ec *EvalContext, req EvalContextRequest) error {
	if !req.SkipMaxUnsafe {
		dur, err := cliflags.ParseDurationFlag(req.MaxUnsafeDuration, "--max-unsafe")
		if err != nil {
			return ui.WithHint(err, ui.ErrHintInvalidMaxUnsafe)
		}
		ec.MaxUnsafe = dur
	}

	if !req.SkipClock {
		clock, err := ResolveClock(req.NowTime)
		if err != nil {
			return err
		}
		ec.Clock = clock

		now, err := ResolveNow(req.NowTime)
		if err != nil {
			return err
		}
		ec.Now = now
	}

	if !req.SkipFormat {
		format, err := ResolveFormatValuePure(req.Format, req.FormatChanged, req.IsJSONMode)
		if err != nil {
			return err
		}
		ec.Format = format
	}
	return nil
}
