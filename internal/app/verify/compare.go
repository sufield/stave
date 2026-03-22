// Package verify provides before/after evaluation comparison logic
// for remediation verification workflows.
package verify

import (
	"time"

	"github.com/sufield/stave/internal/safetyenvelope"
	staveversion "github.com/sufield/stave/internal/version"
	"github.com/sufield/stave/pkg/alpha/domain/asset"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/kernel"
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
	Verification    safetyenvelope.Verification
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

	v := safetyenvelope.NewVerification(safetyenvelope.VerificationRequest{
		Run: safetyenvelope.VerificationRunInfo{
			StaveVersion:      staveversion.String,
			Offline:           true,
			Now:               req.Now,
			MaxUnsafeDuration: req.MaxUnsafeDuration,
			BeforeSnapshots:   req.BeforeSnapshots,
			AfterSnapshots:    req.AfterSnapshots,
		},
		Summary: safetyenvelope.VerificationSummary{
			BeforeViolations: len(req.BeforeFindings),
			AfterViolations:  len(req.AfterFindings),
			Resolved:         len(resolved),
			Remaining:        len(remaining),
			Introduced:       len(introduced),
		},
		Resolved:   resolved,
		Remaining:  remaining,
		Introduced: introduced,
	})

	if err := safetyenvelope.ValidateVerification(v); err != nil {
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
func findingsToEntries(san kernel.Sanitizer, findings []evaluation.Finding) []safetyenvelope.VerificationEntry {
	if len(findings) == 0 {
		return nil
	}
	entries := make([]safetyenvelope.VerificationEntry, 0, len(findings))
	for _, f := range findings {
		assetID := f.AssetID
		if san != nil {
			assetID = asset.ID(san.ID(string(assetID)))
		}
		entries = append(entries, safetyenvelope.VerificationEntry{
			ControlID:   f.ControlID,
			ControlName: f.ControlName,
			AssetID:     assetID,
			AssetType:   f.AssetType,
		})
	}
	return entries
}
