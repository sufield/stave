package stave

import (
	"time"

	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/report"
)

// FromReportAssessment converts a persisted *report.Assessment (the
// shape on disk after `stave apply --format json`) into the public
// *Assessment shape. Used by callers that load a prior run from disk
// and want to feed it into [Score] or other library entry points.
//
// The conversion is field-for-field; remediation.Finding's embedded
// evaluation.Finding fields are mapped through the same helpers
// buildAssessment uses for fresh Apply runs, so library and CLI
// agree on what each field means.
func FromReportAssessment(r *report.Assessment) *Assessment {
	if r == nil {
		return nil
	}

	slaBreaches := 0
	for i := range r.Findings {
		if r.Findings[i].IsAnyBreach() {
			slaBreaches++
		}
	}

	// Coverage carries through from the source report when the
	// producer captured it. The on-disk shape stores it under
	// CoveragePosture as a *coverage.CoverageIndex (json:"-" — set
	// by the in-memory pipeline, not persisted), so a
	// FromReportAssessment caller that loaded JSON from disk gets
	// nil here and the resulting Assessment.Coverage stays zero.
	// Callers that need recomputed coverage should run
	// BuildAssessment / cliapi.Apply against the original controls
	// instead of round-tripping through the JSON wire format.
	var coverage CoveragePosture
	if r.CoveragePosture != nil {
		coverage = *r.CoveragePosture
	}

	return &Assessment{
		SchemaVersion: string(r.SchemaVersion),
		Status:        Status(r.Status),
		Run: RunInfo{
			StaveVersion: r.Run.StaveVersion,
			EvalTime:     r.Run.EvalTime,
			// Mirror the SLA threshold the engine ran against so
			// downstream consumers see the same field BuildAssessment
			// sets in pkg/stave/apply.go — the previous shape dropped
			// MaxUnsafe and made FromReportAssessment non-equivalent
			// to the apply path.
			MaxUnsafe: time.Duration(r.Run.MaxUnsafeDuration),
			Snapshots: r.Run.Snapshots,
		},
		Summary: Summary{
			TotalAssets:        r.Summary.TotalAssets,
			ExposedResources:   r.Summary.ExposedResources,
			Violations:         r.Summary.Violations,
			FrameworkReadiness: convertFrameworkReadiness(r.Summary.FrameworkReadiness),
		},
		Coverage:      coverage,
		Findings:      convertReportFindings(r.Findings),
		Issues:        r.Issues,
		ChainFindings: convertChainFindings(r.ChainFindings),
		SLABreaches:   slaBreaches,
	}
}

// convertReportFindings unwraps the remediation.Finding wrapper so
// the public Finding shape carries the embedded evaluation.Finding's
// fields directly. Reuses convertFinding from apply.go for the
// per-record mapping.
func convertReportFindings(fs []remediation.Finding) []Finding {
	if len(fs) == 0 {
		return nil
	}
	out := make([]Finding, len(fs))
	for i := range fs {
		out[i] = convertFinding(&fs[i].Finding)
	}
	return out
}
