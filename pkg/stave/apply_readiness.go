package stave

import (
	"context"

	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/adapters/observations"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/core/diag"
	"github.com/sufield/stave/pkg/stave/internal/applycmd"
)

// ReadinessRequest is the parsed input for `apply --dry-run`.
type ReadinessRequest = applycmd.ReadinessRequest

// AssessReadiness runs the `apply --dry-run` readiness pipeline (prerequisite
// checks, controls/observations accessibility, evaluation dryness) and renders
// the plan report to bytes. The facade self-constructs its repositories from
// the request paths; enabledPacks + packConfigLoadErr come from command-side
// stave.yaml discovery. Returns the rendered report, whether the project is
// ready, and any error. A not-ready result is signalled via the bool so the
// command can map it to its exit code.
func AssessReadiness(ctx context.Context, req ReadinessRequest, enabledPacks []string, packConfigLoadErr string) ([]byte, bool, error) {
	obsFactory := func() (appcontracts.ObservationRepository, error) {
		return observations.NewObservationLoader(), nil
	}
	ctlFactory := func() (appcontracts.ControlRepository, error) {
		return ctlyaml.NewControlLoader(), nil
	}
	extraChecks := func() []diag.Finding {
		return packConfigDiagnostics(enabledPacks, packConfigLoadErr)
	}
	runEval := NewReadinessEvaluator(ctx, obsFactory, ctlFactory, req.ControlsDir, req.ObservationsDir, req.Sanitize, extraChecks)
	return applycmd.AssessReadiness(req, runEval) //nolint:wrapcheck // engine already wraps; preserve the not-ready signal.
}
