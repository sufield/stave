package stave

import (
	"context"
	"errors"
	"fmt"

	"github.com/sufield/stave/pkg/stave/internal/cmderr"
	"github.com/sufield/stave/pkg/stave/internal/compliancexport"
)

// ComplianceExportConfig parameterizes [ExportCompliance]. It mirrors the
// `stave export compliance` flags 1:1.
type ComplianceExportConfig = compliancexport.Config

// ComplianceOutcome is the compliance result the caller maps to an exit code.
type ComplianceOutcome = compliancexport.Outcome

// Compliance outcome values, worst-first.
const (
	// ComplianceSatisfied — all required requirements met (exit 0).
	ComplianceSatisfied = compliancexport.OutcomeSatisfied
	// ComplianceIncomplete — at least one requirement incomplete (exit 3).
	ComplianceIncomplete = compliancexport.OutcomeIncomplete
	// ComplianceFailed — at least one required requirement not met (exit 1).
	ComplianceFailed = compliancexport.OutcomeFailed
)

// ExportCompliance evaluates a snapshot against one or more compliance
// framework profiles and renders a per-requirement evidence package in the
// requested format (json / table / markdown / oscal, single or composite).
// It returns the rendered document bytes and the worst compliance outcome
// across the requested frameworks (the caller maps that to an exit code; the
// document is rendered regardless). Bad profiles, a missing/empty snapshot,
// and unknown formats wrap [ErrInvalidInput] (exit 2); evaluation/render
// failures stay plain (exit 4). It is the library entry point behind
// `stave export compliance` (the command owns the --out file write).
func ExportCompliance(ctx context.Context, cfg ComplianceExportConfig) (output []byte, outcome ComplianceOutcome, err error) {
	res, err := compliancexport.Run(ctx, &cfg)
	if err != nil {
		var ie *cmderr.InputError
		if errors.As(err, &ie) {
			return nil, ComplianceSatisfied, fmt.Errorf("%w: %w", ie.Err, ErrInvalidInput)
		}
		return nil, ComplianceSatisfied, err //nolint:wrapcheck // engine already wrapped; preserve exit 4.
	}
	return res.Output, res.Outcome, nil
}
