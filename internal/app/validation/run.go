package validation

import (
	"context"
	"errors"
	"fmt"
	"time"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	service "github.com/sufield/stave/internal/app/service"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/diag"
	"github.com/sufield/stave/internal/domain/policy"
)

// Config holds configuration for the validate use case.
type Config struct {
	ControlsDir     string
	ObservationsDir string
	MaxUnsafe       time.Duration
	NowTime         time.Time
	SanitizePaths   bool // When true, directory/file paths in evidence are marked sensitive.
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
func (v *Run) Execute(ctx context.Context, cfg Config) (*service.ValidationResult, error) {
	controls, ctlErr := loadControls(ctx, v.ControlRepo, cfg.ControlsDir)
	snapshots, obsErr := loadSnapshots(ctx, v.ObservationRepo, cfg.ObservationsDir)

	loadErrors := diag.NewResult()
	loadErrors.Merge(cfg.diagnoseLoad(ctlErr, diag.CodeControlLoadFailed,
		"Check that the controls directory exists and contains valid YAML files",
		cfg.ControlsDir))
	loadErrors.Merge(cfg.diagnoseLoad(obsErr, diag.CodeObservationLoadFailed,
		"Check that the observations directory exists and contains valid JSON files",
		cfg.ObservationsDir))

	if len(loadErrors.Issues) > 0 {
		return &service.ValidationResult{Diagnostics: loadErrors}, nil
	}

	serviceResult := service.ValidateLoaded(service.ValidationInput{
		Controls:  controls,
		Snapshots: snapshots,
		MaxUnsafe: cfg.MaxUnsafe,
		NowTime:   cfg.NowTime,
	})
	return &serviceResult, nil
}

// diagnoseLoad converts a load error into a diagnostic result.
// Config is the receiver so SanitizePaths is available without passing it as a parameter.
func (c Config) diagnoseLoad(err error, code string, action string, path string) *diag.Result {
	if err == nil {
		return nil
	}
	if res, ok := errors.AsType[*diag.Result](err); ok {
		return res
	}
	result := diag.NewResult()
	builder := diag.New(code).Error().Action(action)
	if c.SanitizePaths {
		builder.WithSensitive("directory", path)
	} else {
		builder.With("directory", path)
	}
	result.Add(builder.WithSensitive("error", err.Error()).Build())
	return result
}

func loadControls(
	ctx context.Context,
	repo appcontracts.ControlRepository,
	dir string,
) ([]policy.ControlDefinition, error) {
	controls, err := repo.LoadControls(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("failed to load controls: %w", err)
	}
	return controls, nil
}

func loadSnapshots(
	ctx context.Context,
	repo appcontracts.ObservationRepository,
	dir string,
) ([]asset.Snapshot, error) {
	result, err := repo.LoadSnapshots(ctx, dir)
	if err != nil {
		return nil, fmt.Errorf("failed to load observations: %w", err)
	}
	return result.Snapshots, nil
}
