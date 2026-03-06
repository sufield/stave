package evaluate

import (
	"context"
	"os"

	"github.com/spf13/cobra"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appeval "github.com/sufield/stave/internal/app/eval"
	appworkflow "github.com/sufield/stave/internal/app/workflow"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/safetyenvelope"
	"github.com/sufield/stave/internal/version"
)

func runEvaluateWithTemplateParams(_ *cobra.Command, params evaluateParams) error {
	attachTemplateRunID()
	obsLoader, ctlLoader, err := buildTemplateRepositories(params)
	if err != nil {
		return ui.EvaluateErrorWithHint(err)
	}
	artifacts, err := loadTemplateArtifacts(obsLoader, ctlLoader)
	if err != nil {
		return ui.EvaluateErrorWithHint(err)
	}
	result := evaluateTemplateArtifacts(params, artifacts)
	evalEnvelope := buildTemplateEvaluation(result)
	if err := ui.ExecuteTemplate(os.Stdout, applyFlags.evaluateTemplateStr, evalEnvelope); err != nil {
		return err
	}
	return evaluateViolationsExit(result)
}

func attachTemplateRunID() {
	controlsHash, _ := fsutil.HashDirByExt(applyFlags.controlsDir, ".yaml", ".yml")
	observationsHash := ""
	if applyFlags.observationsDir != "-" {
		h, _ := fsutil.HashDirByExt(applyFlags.observationsDir, ".json")
		observationsHash = h.String()
	}
	attachRunID(observationsHash, controlsHash.String())
}

func buildTemplateRepositories(params evaluateParams) (appcontracts.ObservationRepository, appcontracts.ControlRepository, error) {
	obsLoader, err := buildObservationLoader(params.source)
	if err != nil {
		return nil, nil, err
	}
	ctlLoader, err := newControlRepository()
	if err != nil {
		return nil, nil, err
	}
	return obsLoader, ctlLoader, nil
}

func loadTemplateArtifacts(obsLoader appcontracts.ObservationRepository, ctlLoader appcontracts.ControlRepository) (appeval.IntentEvaluationResult, error) {
	intent := appeval.NewIntentEvaluation(obsLoader, ctlLoader)
	artifacts := intent.LoadArtifacts(context.Background(), appeval.IntentEvaluationConfig{
		ControlsDir:         applyFlags.controlsDir,
		ObservationsDir:     applyFlags.observationsDir,
		OptionalSnapshots:   true,
		SkipSourceTypeCheck: true,
		AllowUnknownInput:   applyFlags.allowUnknownInput,
	})
	if artifacts.HasErrors() {
		return appeval.IntentEvaluationResult{}, artifacts.FirstError()
	}
	return artifacts, nil
}

func evaluateTemplateArtifacts(params evaluateParams, artifacts appeval.IntentEvaluationResult) evaluation.Result {
	return appworkflow.EvaluateLoaded(appworkflow.EvaluationRequest{
		Controls:    artifacts.Controls,
		Snapshots:   artifacts.Snapshots,
		MaxUnsafe:   params.maxDuration,
		Clock:       params.clock,
		ToolVersion: version.Version,
	})
}

func buildTemplateEvaluation(result evaluation.Result) safetyenvelope.Evaluation {
	return appworkflow.BuildEvaluationEnvelope(result)
}

func evaluateViolationsExit(result evaluation.Result) error {
	return ui.SafetyExitError(string(result.SafetyStatus()))
}
