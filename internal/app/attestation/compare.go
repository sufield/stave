package attestation

import (
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
	staveversion "github.com/sufield/stave/internal/version"
)

// CompareRequest defines the inputs for a baseline/target comparison.
type CompareRequest struct {
	BaselineFindings  []evaluation.Finding
	TargetFindings    []evaluation.Finding
	BaselineSnapshots int
	TargetSnapshots   int
	SLAThreshold      time.Duration
	Now               time.Time
	Sanitizer         kernel.Sanitizer
}

// CompareResult holds the comparison outcome.
type CompareResult struct {
	Attestation     *report.Attestation
	OpenCount       int
	RegressionCount int
}

// Compare runs a baseline/target finding comparison and produces an
// attestation report. This is the shared logic used by both the
// fix-loop and verify commands.
func Compare(req CompareRequest) (CompareResult, error) {
	diff := evaluation.CompareVerificationFindings(req.BaselineFindings, req.TargetFindings)

	remediated := findingsToEntries(req.Sanitizer, diff.Resolved)
	open := findingsToEntries(req.Sanitizer, diff.Remaining)
	regressions := findingsToEntries(req.Sanitizer, diff.Introduced)

	v := report.NewAttestation(report.AttestationRequest{
		Run: report.AttestationRunInfo{
			ToolVersion:     staveversion.String,
			Offline:         true,
			Now:             req.Now,
			SLAThreshold:    req.SLAThreshold,
			BeforeSnapshots: req.BaselineSnapshots,
			AfterSnapshots:  req.TargetSnapshots,
		},
		Summary: report.AttestationSummary{
			PreviousViolations: len(req.BaselineFindings),
			CurrentViolations:  len(req.TargetFindings),
			Remediated:         len(remediated),
			Open:               len(open),
			Regressions:        len(regressions),
		},
		Remediated:  remediated,
		Open:        open,
		Regressions: regressions,
	})

	if err := report.ValidateAttestation(v); err != nil {
		return CompareResult{}, err
	}

	return CompareResult{
		Attestation:     v,
		OpenCount:       len(open),
		RegressionCount: len(regressions),
	}, nil
}

// findingsToEntries transforms domain findings into attestation entries,
// applying sanitization if configured.
func findingsToEntries(san kernel.Sanitizer, findings []evaluation.Finding) []report.AttestationEntry {
	if len(findings) == 0 {
		return nil
	}
	entries := make([]report.AttestationEntry, 0, len(findings))
	for i := range findings {
		f := &findings[i]
		assetID := f.AssetID
		if san != nil {
			assetID = asset.ID(san.ID(string(assetID)))
		}
		entries = append(entries, report.AttestationEntry{
			ControlID:   f.ControlID,
			ControlName: f.ControlName,
			AssetID:     assetID,
			AssetType:   f.AssetType,
		})
	}
	return entries
}
