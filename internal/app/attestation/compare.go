package attestation

import (
	"fmt"
	"time"

	contractvalidator "github.com/sufield/stave/internal/contracts/validator"
	"github.com/sufield/stave/internal/core/asset"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/report"
	staveversion "github.com/sufield/stave/internal/version"
)

// SnapshotCount encapsulates a count of snapshots evaluated during attestation comparisons.
type SnapshotCount int

// Int returns the raw integer count value.
func (c SnapshotCount) Int() int {
	return int(c)
}

// IsEmpty reports whether the snapshot count is zero.
func (c SnapshotCount) IsEmpty() bool {
	return c == 0
}

// CompareRequest defines the inputs for a baseline/target comparison.
type CompareRequest struct {
	BaselineFindings  []evaluation.Finding
	TargetFindings    []evaluation.Finding
	BaselineSnapshots SnapshotCount
	TargetSnapshots   SnapshotCount
	SLAThreshold      time.Duration
	EvalTime          time.Time
	Sanitizer         kernel.Sanitizer
}

// CompareResult holds the comparison outcome.
type CompareResult struct {
	Attestation     *report.Attestation
	OpenCount       int
	RegressionCount int
}

// HasRegressions reports whether any regression findings were introduced.
func (cr CompareResult) HasRegressions() bool {
	return cr.RegressionCount > 0
}

// HasOpen reports whether any violations remain open.
func (cr CompareResult) HasOpen() bool {
	return cr.OpenCount > 0
}

// IsRegressionFree reports whether remediation introduced no regressions.
func (cr CompareResult) IsRegressionFree() bool {
	return !cr.HasRegressions()
}

// TotalOutstanding returns the sum of open and regression violations.
func (cr CompareResult) TotalOutstanding() int {
	return cr.OpenCount + cr.RegressionCount
}

// HasViolations reports whether any outstanding violations (open or regression) exist.
func (cr CompareResult) HasViolations() bool {
	return cr.TotalOutstanding() > 0
}

// RemediatedCount returns the number of successfully remediated findings.
func (cr CompareResult) RemediatedCount() int {
	if cr.Attestation != nil {
		return cr.Attestation.Summary.Remediated
	}
	return 0
}

// HasRemediated reports whether any findings were successfully remediated.
func (cr CompareResult) HasRemediated() bool {
	return cr.RemediatedCount() > 0
}

// PassLabel returns "PASS" if regression-free, or "FAIL" otherwise.
func (cr CompareResult) PassLabel() string {
	if cr.IsRegressionFree() {
		return "PASS"
	}
	return "FAIL"
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
			EvalTime:        req.EvalTime,
			SLAThreshold:    req.SLAThreshold,
			BeforeSnapshots: req.BaselineSnapshots.Int(),
			AfterSnapshots:  req.TargetSnapshots.Int(),
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

	if err := contractvalidator.ValidateAttestation(v); err != nil {
		return CompareResult{}, fmt.Errorf("validate attestation: %w", err)
	}

	return CompareResult{
		Attestation:     v,
		OpenCount:       len(open),
		RegressionCount: len(regressions),
	}, nil
}

// AttestationEntries is a domain collection of report.AttestationEntry items with query methods.
type AttestationEntries []report.AttestationEntry

// Len returns the number of attestation entries in the collection.
func (ae AttestationEntries) Len() int {
	return len(ae)
}

// findingsToEntries transforms domain findings into attestation entries,
// applying sanitization if configured.
func findingsToEntries(san kernel.Sanitizer, findings []evaluation.Finding) AttestationEntries {
	if len(findings) == 0 {
		return nil
	}
	entries := make(AttestationEntries, 0, len(findings))
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
