package stave

import (
	"context"
	"fmt"
	"strings"
	"time"

	packs "github.com/sufield/stave/internal/adapters/controls/pack"
	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appvalidation "github.com/sufield/stave/internal/app/validation"
	"github.com/sufield/stave/internal/core/diag"
	schemaval "github.com/sufield/stave/internal/core/schemaval"
)

// NewReadinessEvaluator builds the validation closure used by readiness
// assessment (`stave apply --dry-run`) and the validate command. It loads
// the observation and control repositories from the supplied factories,
// runs the core validation against the embedded builtin catalog fallback,
// applies any extra diagnostic checks, and returns the evaluation state.
//
// The repository factories use the underlying contract interface types
// (identical to cmd/cmdutil/compose's ObsRepoFactory/CtlRepoFactory
// aliases) so callers can pass their constructors across the facade
// boundary without pkg/stave depending on cmd/cmdutil. extraChecks
// supplies additional findings (e.g. project-config pack validation) that
// are recorded after the core evaluation.
//
// Moved out of cmd/apply/validate so `apply --dry-run` and `validate`
// share one library implementation instead of cmd/apply importing a
// sibling command package.
func NewReadinessEvaluator(
	ctx context.Context,
	newObsRepo func() (appcontracts.ObservationRepository, error),
	newCtlRepo func() (appcontracts.ControlRepository, error),
	ctlDir, obsDir string,
	sanitize bool,
	extraChecks func() []diag.Finding,
) func(time.Duration, time.Time) (schemaval.EvaluationState, error) {
	return func(maxUnsafeDuration time.Duration, now time.Time) (schemaval.EvaluationState, error) {
		obsRepo, err := newObsRepo()
		if err != nil {
			return schemaval.EvaluationState{}, err
		}
		ctlRepo, err := newCtlRepo()
		if err != nil {
			return schemaval.EvaluationState{}, err
		}

		runner := appvalidation.NewRun(obsRepo, ctlRepo)
		runner.BuiltinCatalog = builtinControls
		result, err := runner.Execute(ctx, appvalidation.Config{
			ControlsDir:       ctlDir,
			ObservationsDir:   obsDir,
			MaxUnsafeDuration: maxUnsafeDuration,
			EvalTimeRaw:       now,
			SanitizePaths:     sanitize,
			PredicateParser:   ctlyaml.ParsePredicate,
		})
		if err != nil {
			return schemaval.EvaluationState{}, fmt.Errorf("execute readiness validation: %w", err)
		}

		if extraChecks != nil {
			result.Diagnostics.RecordAll(extraChecks())
		}

		return toEvaluationState(result), nil
	}
}

// toEvaluationState converts an app-layer validation report into the
// domain evaluation state consumed by readiness assessment.
func toEvaluationState(result *appvalidation.Report) schemaval.EvaluationState {
	state := schemaval.EvaluationState{Diagnostics: result.Diagnostics}
	state.LoadMetrics.ControlsLoaded = result.Summary.ControlsLoaded
	state.LoadMetrics.SnapshotsLoaded = result.Summary.SnapshotsLoaded
	state.LoadMetrics.ResourcesLoaded = result.Summary.AssetObservationsLoaded
	return state
}

// ValidatePackConfiguration checks the supplied enabled control-pack names
// against the embedded pack registry and returns one error-level finding
// per unknown pack. An empty input returns nil.
//
// Discovering which packs a project enables (reading stave.yaml) stays in
// the command layer; only the registry check crosses into the library.
func ValidatePackConfiguration(enabledPacks []string) []diag.Finding {
	if len(enabledPacks) == 0 {
		return nil
	}
	reg, err := packs.NewEmbeddedRegistry()
	if err != nil {
		return []diag.Finding{
			diag.NewFinding(diag.RulePackRegistryLoadFailed).
				Error().
				Remediation("Reinstall Stave binary or verify embedded registry integrity").
				SensitiveAttribute("error", err.Error()).
				Build(),
		}
	}
	known := reg.PackNames()
	knownSet := make(map[string]struct{}, len(known))
	for _, name := range known {
		knownSet[name] = struct{}{}
	}
	var issues []diag.Finding
	for _, raw := range enabledPacks {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}
		if _, ok := knownSet[name]; ok {
			continue
		}
		issues = append(issues, diag.NewFinding(diag.RuleUnknownControlPack).
			Error().
			Remediation("Use a configured pack name: "+strings.Join(known, ", ")).
			Attribute("pack", name).
			Build())
	}
	return issues
}
