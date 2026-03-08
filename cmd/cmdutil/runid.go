package cmdutil

import (
	"strings"

	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/platform/identity"
	"github.com/sufield/stave/internal/platform/logging"
	"github.com/sufield/stave/internal/version"
)

// AttachRunID computes a deterministic run ID from input hashes and sets it on
// the default logger.
func AttachRunID(inputsHash, controlsHash string) {
	logger := logging.DefaultLogger()
	runID := identity.ComputeRunID(version.Version, strings.TrimSpace(inputsHash), strings.TrimSpace(controlsHash))
	logging.SetDefaultLogger(logging.WithRunID(logger, runID))
}

// AttachRunIDFromPlan extracts hashes from an evaluation plan and attaches a
// run ID. No-op if plan is nil.
func AttachRunIDFromPlan(plan *appeval.EvaluationPlan) {
	if plan == nil {
		return
	}
	AttachRunID(plan.ObservationsHash.String(), plan.ControlsHash.String())
}
