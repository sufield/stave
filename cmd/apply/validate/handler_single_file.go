package validate

import (
	"context"
	"fmt"
	"io"
	"time"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/cli/ui"
	schemas "github.com/sufield/stave/internal/contracts/schema"
	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
	"github.com/sufield/stave/pkg/alpha/domain/diag"
	"github.com/sufield/stave/pkg/alpha/domain/validation"

	appvalidation "github.com/sufield/stave/internal/app/validation"
)

// runValidateSingleFile handles the orchestration of validating a single input.
func runValidateSingleFile(stdin io.Reader, reporter *Reporter, opts *options) error {
	data, source, err := ui.ReadInput(stdin, opts.InputPath)
	if err != nil {
		return fmt.Errorf("read input %q: %w", source, err)
	}

	req, err := buildValidationRequest(data, opts)
	if err != nil {
		return err
	}

	service := appvalidation.NewContentService(contractvalidator.New)
	result, err := service.Validate(req)
	if err != nil {
		return fmt.Errorf("validation failed for %q: %w", source, err)
	}

	if err := reporter.Write(result, opts.hintCtx()); err != nil {
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

// kindAliases maps CLI input to canonical schema kinds.
var kindAliases = map[string]schemas.Kind{
	"control":     schemas.KindControl,
	"controls":    schemas.KindControl,
	"observation": schemas.KindObservation,
	"obs":         schemas.KindObservation,
	"snapshot":    schemas.KindObservation,
	"snapshots":   schemas.KindObservation,
	"finding":     schemas.KindFinding,
	"findings":    schemas.KindFinding,
}

// normalizeKind converts various CLI aliases into canonical domain kinds.
func normalizeKind(raw string) (schemas.Kind, error) {
	if k, ok := kindAliases[ui.NormalizeToken(raw)]; ok {
		return k, nil
	}
	return "", ui.EnumError("--kind", raw, []string{"control", "observation", "finding"})
}

// NewReadinessValidator creates a validation function for plan/apply commands.
// extraChecks provides additional diagnostic checks (e.g. pack config validation)
// that run after the core evaluation.
func NewReadinessValidator(
	ctx context.Context,
	newObsRepo compose.ObsRepoFactory,
	newCtlRepo compose.CtlRepoFactory,
	ctlDir, obsDir string,
	sanitize bool,
	extraChecks func() []diag.Issue,
) func(time.Duration, time.Time) (validation.Result, error) {
	return func(maxUnsafeDuration time.Duration, now time.Time) (validation.Result, error) {
		obsRepo, err := newObsRepo()
		if err != nil {
			return validation.Result{}, err
		}
		ctlRepo, err := newCtlRepo()
		if err != nil {
			return validation.Result{}, err
		}

		runner := appvalidation.NewRun(obsRepo, ctlRepo)
		result, err := runner.Execute(ctx, appvalidation.Config{
			ControlsDir:       ctlDir,
			ObservationsDir:   obsDir,
			MaxUnsafeDuration: maxUnsafeDuration,
			NowTime:           now,
			SanitizePaths:     sanitize,
			PredicateParser:   ctlyaml.ParsePredicate,
		})
		if err != nil {
			return validation.Result{}, err
		}

		if extraChecks != nil {
			result.Diagnostics.AddAll(extraChecks())
		}

		return toValidationResult(result), nil
	}
}

// toValidationResult converts an app-layer validation result to the domain type.
func toValidationResult(result *appvalidation.Result) validation.Result {
	return validation.Result{
		Diagnostics: result.Diagnostics,
		Summary: struct {
			ControlsLoaded          int
			SnapshotsLoaded         int
			AssetObservationsLoaded int
		}{
			ControlsLoaded:          result.Summary.ControlsLoaded,
			SnapshotsLoaded:         result.Summary.SnapshotsLoaded,
			AssetObservationsLoaded: result.Summary.AssetObservationsLoaded,
		},
	}
}
