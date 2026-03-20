package validate

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	ctlyaml "github.com/sufield/stave/internal/adapters/input/controls/yaml"
	"github.com/sufield/stave/internal/cli/ui"
	schemas "github.com/sufield/stave/internal/contracts/schema"
	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
	"github.com/sufield/stave/pkg/alpha/domain/validation"

	appvalidation "github.com/sufield/stave/internal/app/validation"
)

// runValidateSingleFile handles the orchestration of validating a single input.
func runValidateSingleFile(reporter *Reporter, opts *options) error {
	// 1. Read Input
	data, source, err := ui.ReadInput(os.Stdin, opts.InputPath)
	if err != nil {
		return fmt.Errorf("failed to read input %q: %w", source, err)
	}

	// 2. Prepare Request
	req, err := buildValidationRequest(data, opts)
	if err != nil {
		return err
	}

	// 3. Execute Service
	service := appvalidation.NewContentService(func() appvalidation.SchemaValidator {
		return contractvalidator.New()
	})
	result, err := service.Validate(req)
	if err != nil {
		return fmt.Errorf("validation failed for %q: %w", source, err)
	}

	// 4. Report Results
	if err := reporter.Write(result, opts); err != nil {
		return err
	}
	return reporter.ExitStatus(result)
}

// buildValidationRequest creates the appropriate request based on options.
func buildValidationRequest(data []byte, opts *options) (appvalidation.ContentValidator, error) {
	if opts.Kind == "" {
		return appvalidation.AutoRequest{Data: data}, nil
	}

	normalizedKind, err := normalizeKind(opts.Kind)
	if err != nil {
		return nil, err
	}

	return appvalidation.ExplicitRequest{
		Data:          data,
		Kind:          normalizedKind,
		SchemaVersion: opts.SchemaVersion,
		Strict:        opts.Strict,
	}, nil
}

// normalizeKind converts various CLI aliases into canonical domain kinds.
func normalizeKind(raw string) (schemas.Kind, error) {
	switch ui.NormalizeToken(raw) {
	case "control", "controls":
		return schemas.KindControl, nil
	case "observation", "obs", "snapshot", "snapshots":
		return schemas.KindObservation, nil
	case "finding", "findings":
		return schemas.KindFinding, nil
	default:
		return "", ui.EnumError("--kind", raw, []string{"control", "observation", "finding"})
	}
}

// NewReadinessValidator creates a validation function for plan/apply commands.
// It removes the dependency on cobra.Command by accepting the sanitize flag directly.
func NewReadinessValidator(ctx context.Context, p *compose.Provider, ctlDir, obsDir string, sanitize bool) func(time.Duration, time.Time) (validation.ValidationResult, error) {
	return func(maxUnsafeDur time.Duration, now time.Time) (validation.ValidationResult, error) {
		obsRepo, err := p.NewObservationRepo()
		if err != nil {
			return validation.ValidationResult{}, err
		}
		ctlRepo, err := p.NewControlRepo()
		if err != nil {
			return validation.ValidationResult{}, err
		}

		runner := appvalidation.NewRun(obsRepo, ctlRepo)
		result, err := runner.Execute(ctx, appvalidation.Config{
			ControlsDir:     ctlDir,
			ObservationsDir: obsDir,
			MaxUnsafe:       maxUnsafeDur,
			NowTime:         now,
			SanitizePaths:   sanitize,
			PredicateParser: ctlyaml.ParsePredicate,
		})
		if err != nil {
			return validation.ValidationResult{}, err
		}

		result.Diagnostics.AddAll(PackConfigIssues())

		var vr validation.ValidationResult
		vr.Diagnostics = result.Diagnostics
		vr.Summary.ControlsLoaded = result.Summary.ControlsLoaded
		vr.Summary.SnapshotsLoaded = result.Summary.SnapshotsLoaded
		vr.Summary.AssetObservationsLoaded = result.Summary.AssetObservationsLoaded
		return vr, nil
	}
}
