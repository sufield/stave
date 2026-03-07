package apply

import (
	"context"
	"os"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/adapters/output"
	appcontracts "github.com/sufield/stave/internal/app/contracts"
	appeval "github.com/sufield/stave/internal/app/eval"
	appworkflow "github.com/sufield/stave/internal/app/workflow"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/remediation"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/version"
)

func runApplyWithTemplateParams(cmd *cobra.Command, params applyParams) error {
	attachTemplateRunID()
	obsLoader, ctlLoader, err := buildTemplateRepositories(params)
	if err != nil {
		return ui.EvaluateErrorWithHint(err)
	}
	artifacts, err := loadTemplateArtifacts(obsLoader, ctlLoader)
	if err != nil {
		return ui.EvaluateErrorWithHint(err)
	}
	result := applyTemplateArtifacts(params, artifacts)

	enricher := remediation.NewMapper()
	san := cmdutil.GetSanitizer(cmd)
	enrichFn := func(r evaluation.Result) appcontracts.EnrichedResult {
		return output.Enrich(enricher, san, r)
	}

	data := &appeval.PipelineData{Result: result}
	if pipeErr := appeval.NewPipeline(context.Background(), data).
		Then(appeval.EnrichStep(enrichFn)).
		Error(); pipeErr != nil {
		return ui.EvaluateErrorWithHint(pipeErr)
	}

	evalEnvelope := appworkflow.BuildSafetyEnvelopeFromEnriched(data.Enriched)
	if err := ui.ExecuteTemplate(os.Stdout, applyFlags.applyTemplateStr, evalEnvelope); err != nil {
		return err
	}
	return applyViolationsExit(result)
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

func buildTemplateRepositories(params applyParams) (appcontracts.ObservationRepository, appcontracts.ControlRepository, error) {
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

func applyTemplateArtifacts(params applyParams, artifacts appeval.IntentEvaluationResult) evaluation.Result {
	return appworkflow.EvaluateLoaded(appworkflow.EvaluationRequest{
		Controls:    artifacts.Controls,
		Snapshots:   artifacts.Snapshots,
		MaxUnsafe:   params.maxDuration,
		Clock:       params.clock,
		ToolVersion: version.Version,
	})
}

func applyViolationsExit(result evaluation.Result) error {
	return ui.SafetyExitError(string(result.SafetyStatus()))
}
