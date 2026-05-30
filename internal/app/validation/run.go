package validation

import (
	"context"
	"fmt"
	"time"

	ctlbuiltin "github.com/sufield/stave/internal/adapters/controls/builtin"
	"github.com/sufield/stave/internal/adapters/predicate"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	policy "github.com/sufield/stave/internal/core/controldef"
)

// Config holds configuration for the validate use case.
type Config struct {
	ControlsDir       string
	ObservationsDir   string
	MaxUnsafeDuration time.Duration
	NowTime           time.Time
	SanitizePaths     bool // When true, directory/file paths in evidence are marked sensitive.
	PredicateParser   policy.PredicateParser
	PredicateEval     policy.PredicateEval
}

// Run orchestrates the validation use case.
// It loads files using adapters and delegates validation to the domain.
type Run struct {
	ObservationRepo appcontracts.ObservationRepository
	ControlRepo     appcontracts.ControlRepository
}

// NewRun creates a new validate run instance.
func NewRun(
	obsRepo appcontracts.ObservationRepository,
	ctlRepo appcontracts.ControlRepository,
) *Run {
	return &Run{
		ObservationRepo: obsRepo,
		ControlRepo:     ctlRepo,
	}
}

// Execute loads data and runs domain validation.
// App layer handles file I/O; domain handles validation logic.
func (v *Run) Execute(ctx context.Context, cfg Config) (*Report, error) {
	// Empty ControlsDir selects the embedded built-in catalog (set by the
	// CLI's built-in-catalog fallback when --controls is absent).
	var controls []policy.ControlDefinition
	if cfg.ControlsDir == "" {
		store := ctlbuiltin.NewControlStore(ctlbuiltin.EmbeddedFS(), "embedded", ctlbuiltin.WithAliasResolver(predicate.ResolverFunc()))
		all, builtinErr := store.All()
		if builtinErr != nil {
			return nil, fmt.Errorf("load built-in control catalog: %w", builtinErr)
		}
		controls = all
	} else {
		loaded, ctlErr := appcontracts.LoadControls(ctx, v.ControlRepo, cfg.ControlsDir)
		if ctlErr != nil {
			return nil, fmt.Errorf("load controls from %s: %w", cfg.ControlsDir, ctlErr)
		}
		controls = loaded
	}
	obsResult, obsErr := appcontracts.LoadSnapshots(ctx, v.ObservationRepo, cfg.ObservationsDir)
	if obsErr != nil {
		return nil, fmt.Errorf("load observations from %s: %w", cfg.ObservationsDir, obsErr)
	}
	snapshots := obsResult.Snapshots

	serviceResult := ValidateLoaded(Input{
		Controls:          controls,
		Snapshots:         snapshots,
		MaxUnsafeDuration: cfg.MaxUnsafeDuration,
		NowTime:           cfg.NowTime,
		PredicateParser:   cfg.PredicateParser,
		PredicateEval:     cfg.PredicateEval,
	})
	return &serviceResult, nil
}
