// Package verify provides before/after evaluation comparison logic
// for remediation verification workflows.
package verify

import (
	"time"

	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
	staveversion "github.com/sufield/stave/internal/version"
)

// CompareRequest defines the inputs for a before/after comparison.
type CompareRequest struct {
	BeforeFindings    []evaluation.Finding
	AfterFindings     []evaluation.Finding
	BeforeSnapshots   int
	AfterSnapshots    int
	MaxUnsafeDuration time.Duration
	Now               time.Time
	Sanitizer         kernel.Sanitizer
}

// CompareResult holds the comparison outcome.
type CompareResult struct {
	Verification    *report.Attestation
	RemainingCount  int
	IntroducedCount int
}

// Compare runs a before/after finding comparison and produces a safety
// verification envelope. This is the shared logic used by both the
// fix-loop and verify commands.
func Compare(req CompareRequest) (CompareResult, error) {
	diff := evaluation.CompareVerificationFindings(req.BeforeFindings, req.AfterFindings)

	resolved := findingsToEntries(req.Sanitizer, diff.Resolved)
	remaining := findingsToEntries(req.Sanitizer, diff.Remaining)
	introduced := findingsToEntries(req.Sanitizer, diff.Introduced)

	v := report.NewAttestation(report.AttestationRequest{
		Run: report.AttestationRunInfo{
			ToolVersion:     staveversion.String,
			Offline:         true,
			Now:             req.Now,
			SLAThreshold:    req.MaxUnsafeDuration,
			BeforeSnapshots: req.BeforeSnapshots,
			AfterSnapshots:  req.AfterSnapshots,
		},
		Summary: report.AttestationSummary{
			PreviousViolations: len(req.BeforeFindings),
			CurrentViolations:  len(req.AfterFindings),
			Remediated:         len(resolved),
			Open:               len(remaining),
			Regressions:        len(introduced),
		},
		Remediated:  resolved,
		Open:        remaining,
		Regressions: introduced,
	})

	if err := report.ValidateAttestation(v); err != nil {
		return CompareResult{}, err
	}

	return CompareResult{
		Verification:    v,
		RemainingCount:  len(remaining),
		IntroducedCount: len(introduced),
	}, nil
}

// findingsToEntries transforms domain findings into safety envelope
// verification entries, applying sanitization if configured.
func findingsToEntries(san kernel.Sanitizer, findings []evaluation.Finding) []report.AttestationEntry {
	if len(findings) == 0 {
		return nil
	}
	entries := make([]report.AttestationEntry, 0, len(findings))
	for _, f := range findings {
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
