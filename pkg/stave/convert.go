package stave

import (
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
		if r.Findings[i].SLABreached {
			slaBreaches++
		}
	}

	return &Assessment{
		SchemaVersion: string(r.SchemaVersion),
		Status:        Status(r.Status),
		Run: RunInfo{
			StaveVersion: r.Run.StaveVersion,
			Now:          r.Run.Now,
			Snapshots:    r.Run.Snapshots,
		},
		Summary: Summary{
			TotalAssets:        r.Summary.TotalAssets,
			ExposedResources:   r.Summary.ExposedResources,
			Violations:         r.Summary.Violations,
			FrameworkReadiness: convertFrameworkReadiness(r.Summary.FrameworkReadiness),
		},
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
