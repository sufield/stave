// Package cliapi is the CLI-internal escape hatch over pkg/stave.Apply.
// It returns the same trimmed *stave.Assessment public Apply produces,
// alongside the raw *evaluation.ComplianceReport that cmd/apply's
// SARIF/JSON/text formatters consume.
//
// External Go consumers should NOT import this package — use
// pkg/stave.Apply and the public Assessment surface instead. The
// internal report carries fields (RiskSignals, AttackStageSummary,
// TopExposures, ExceptedFindings, AcknowledgedFindings,
// SkippedControls, ExemptedAssets, Metadata, Checks, EvidencePackage,
// run-metadata) that are intentionally absent from the public API
// because they couple library callers to engine refactor velocity.
//
// The Go internal-package rule prevents external imports of
// pkg/stave/internal/applycore, but cliapi is not in an internal
// directory — its "don't use this from outside the CLI" status is a
// documentation contract, not a build-time enforcement. The audit
// in coderabbit/9.md explains the design choice.
package cliapi

import (
	"context"
	"errors"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/sir"
	"github.com/sufield/stave/pkg/stave"
	"github.com/sufield/stave/pkg/stave/internal/applycore"
)

// ApplyResult holds both views of an evaluation run. Assessment is
// the trimmed public type the library promotes; ComplianceReport is
// the raw engine output that cmd/apply needs for SARIF/JSON/text
// rendering. Controls is the active control catalog the workflow
// loaded — cmd/apply uses it to compute the per-tool coverage
// posture that the output pipeline writes alongside findings.
//
// All three fields are derived from the same evaluation pass and
// stay consistent for the lifetime of the result.
type ApplyResult struct {
	Assessment       *stave.Assessment
	ComplianceReport *evaluation.ComplianceReport
	Controls         []policy.ControlDefinition

	// SIRDocument is the projection applycore built for fact-id
	// correlation during evaluation. Surfaced here so cmd/exportsir
	// can reuse it for `stave export-sir` output without re-loading
	// controls + snapshots and re-running the SIR builder. nil when
	// the builder failed during evaluation — annotateContributingFactIDs
	// is best-effort, so a SIR failure leaves findings un-annotated
	// rather than blocking the report; the same nil propagates here.
	SIRDocument *sir.Document
}

// IsIncomplete reports whether the result lacks the mandatory
// ComplianceReport — the data downstream consumers (cmd/apply,
// scoring, output formatters) require to do useful work. A nil
// receiver counts as incomplete so callers can collapse the
// "did Apply return anything at all" check into the same probe.
//
// Apply is contracted to return (non-nil result with non-nil
// ComplianceReport, nil err) on success; the predicate documents
// that contract on the type so a future API change adds new
// mandatory fields by extending IsIncomplete in one place.
func (r *ApplyResult) IsIncomplete() bool {
	return r == nil || r.ComplianceReport == nil
}

// Apply runs the same evaluation pipeline as [stave.Apply] and
// returns both the public Assessment and the raw internal report.
// Use this from cmd/apply (and only from cmd/apply) when output
// formatters need access to fields the public Assessment doesn't
// surface.
func Apply(ctx context.Context, cfg stave.Config) (*ApplyResult, error) {
	if cfg.SnapshotsDir == "" {
		return nil, errors.New("cliapi.Apply: Config.SnapshotsDir is required")
	}

	r, err := applycore.Run(ctx, stave.ApplyInputsFromConfig(cfg))
	if err != nil {
		return nil, err
	}

	return &ApplyResult{
		Assessment:       stave.BuildAssessment(r.Report, r.Controls),
		ComplianceReport: r.Report,
		Controls:         r.Controls,
		SIRDocument:      r.SIRDocument,
	}, nil
}
