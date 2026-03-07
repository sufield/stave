package verify

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	appeval "github.com/sufield/stave/internal/app/eval"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/kernel"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/domain/ports"
	"github.com/sufield/stave/internal/safetyenvelope"
	staveversion "github.com/sufield/stave/internal/version"
)

// verificationSanitizer sanitizes asset identifiers in verification output.
type verificationSanitizer interface {
	Verification(asset.ID) asset.ID
}

func runVerify(cmd *cobra.Command, rt *ui.Runtime, opts *options) error {
	execCtx, err := opts.prepareExecution(cmd.Context())
	if err != nil {
		return err
	}
	controls, err := loadVerifyControls(execCtx.ctx, execCtx.controlsDir)
	if err != nil {
		return err
	}

	beforeDone := rt.BeginProgress("apply before observations")
	beforeEval, err := runVerifyEvaluation(execCtx, controls, execCtx.beforeDir)
	beforeDone()
	if err != nil {
		return fmt.Errorf("before evaluation: %w", err)
	}

	afterDone := rt.BeginProgress("apply after observations")
	afterEval, err := runVerifyEvaluation(execCtx, controls, execCtx.afterDir)
	afterDone()
	if err != nil {
		return fmt.Errorf("after evaluation: %w", err)
	}

	outcome := buildVerificationOutcome(cmd, execCtx, beforeEval, afterEval)
	if err := writeVerificationJSON(cmd.OutOrStdout(), outcome.result); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return verifyOutcomeExit(cmd, rt, outcome)
}

type verifyEvaluation struct {
	result        *evaluation.Result
	snapshotCount int
}

type verifyOutcome struct {
	result          safetyenvelope.Verification
	remainingCount  int
	introducedCount int
}

func loadVerifyControls(ctx context.Context, controlsDir string) ([]policy.ControlDefinition, error) {
	ctlLoader, err := cmdutil.NewControlRepository()
	if err != nil {
		return nil, fmt.Errorf("create control loader: %w", err)
	}
	controls, err := ctlLoader.LoadControls(ctx, controlsDir)
	if err != nil {
		return nil, fmt.Errorf("load controls: %w", err)
	}
	if len(controls) == 0 {
		return nil, fmt.Errorf("no controls in %s", controlsDir)
	}
	return controls, nil
}

func runVerifyEvaluation(execCtx verifyExecution, controls []policy.ControlDefinition, observationsDir string) (verifyEvaluation, error) {
	result, snaps, err := runEvaluation(runEvaluationRequest{
		Context:          execCtx.ctx,
		ObservationsDir:  observationsDir,
		Controls:         controls,
		MaxUnsafe:        execCtx.maxUnsafe,
		Clock:            execCtx.clock,
		AllowUnknownType: execCtx.allowUnknown,
	})
	if err != nil {
		return verifyEvaluation{}, err
	}
	return verifyEvaluation{result: result, snapshotCount: snaps}, nil
}

func buildVerificationOutcome(cmd *cobra.Command, execCtx verifyExecution, before, after verifyEvaluation) verifyOutcome {
	diff := evaluation.CompareVerificationFindings(before.result.Findings, after.result.Findings)
	sanitizer := cmdutil.GetSanitizer(cmd)
	resolved := redactVerificationEntries(sanitizer, toEntries(diff.Resolved))
	remaining := redactVerificationEntries(sanitizer, toEntries(diff.Remaining))
	introduced := redactVerificationEntries(sanitizer, toEntries(diff.Introduced))

	result := safetyenvelope.Verification{
		SchemaVersion: kernel.SchemaOutput,
		Kind:          safetyenvelope.KindVerification,
		Run: safetyenvelope.VerificationRunInfo{
			ToolVersion:     staveversion.Version,
			Offline:         true,
			Now:             execCtx.clock.Now(),
			MaxUnsafe:       execCtx.maxUnsafe,
			BeforeSnapshots: before.snapshotCount,
			AfterSnapshots:  after.snapshotCount,
		},
		Summary: safetyenvelope.VerificationSummary{
			BeforeViolations: len(before.result.Findings),
			AfterViolations:  len(after.result.Findings),
			Resolved:         len(resolved),
			Remaining:        len(remaining),
			Introduced:       len(introduced),
		},
		Resolved:   resolved,
		Remaining:  remaining,
		Introduced: introduced,
	}
	result.Normalize()
	return verifyOutcome{
		result:          result,
		remainingCount:  len(remaining),
		introducedCount: len(introduced),
	}
}

func redactVerificationEntries(sanitizer verificationSanitizer, entries []safetyenvelope.VerificationEntry) []safetyenvelope.VerificationEntry {
	out := make([]safetyenvelope.VerificationEntry, len(entries))
	for i, e := range entries {
		out[i] = e
		out[i].AssetID = sanitizer.Verification(e.AssetID)
	}
	return out
}

func verifyOutcomeExit(cmd *cobra.Command, rt *ui.Runtime, outcome verifyOutcome) error {
	if outcome.remainingCount > 0 || outcome.introducedCount > 0 {
		rt.Quiet = cmdutil.QuietEnabled(cmd)
		rt.PrintNextSteps(
			"Run `stave diagnose` against the after observations to understand remaining violations.",
			"Run `stave ci fix-loop` for automated before/after comparison with detailed reports.",
		)
		return ui.ErrViolationsFound
	}
	return nil
}

// runEvaluation evaluates observations against controls and returns the result.
type runEvaluationRequest struct {
	Context          context.Context
	ObservationsDir  string
	Controls         []policy.ControlDefinition
	MaxUnsafe        time.Duration
	Clock            ports.Clock
	AllowUnknownType bool
}

func runEvaluation(req runEvaluationRequest) (*evaluation.Result, int, error) {
	loader, err := cmdutil.NewObservationRepository()
	if err != nil {
		return nil, 0, fmt.Errorf("create observation loader: %w", err)
	}
	return appeval.RunDirectoryEvaluation(appeval.DirectoryEvaluationRequest{
		Context:           req.Context,
		ObservationsDir:   req.ObservationsDir,
		Controls:          req.Controls,
		MaxUnsafe:         req.MaxUnsafe,
		Clock:             req.Clock,
		AllowUnknownType:  req.AllowUnknownType,
		ToolVersion:       staveversion.Version,
		ObservationLoader: loader,
	})
}

func toEntry(f evaluation.Finding) safetyenvelope.VerificationEntry {
	return safetyenvelope.VerificationEntry{
		ControlID:   f.ControlID,
		ControlName: f.ControlName,
		AssetID:     f.AssetID,
		AssetType:   f.AssetType,
	}
}

func toEntries(findings []evaluation.Finding) []safetyenvelope.VerificationEntry {
	entries := make([]safetyenvelope.VerificationEntry, 0, len(findings))
	for _, f := range findings {
		entries = append(entries, toEntry(f))
	}
	return entries
}

func writeVerificationJSON(w io.Writer, result safetyenvelope.Verification) error {
	if err := safetyenvelope.ValidateVerification(result); err != nil {
		return fmt.Errorf("write output: %w", err)
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(result)
}
