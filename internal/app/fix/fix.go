// Package fix provides the single-finding remediation and fix-loop
// verification workflows. Command handlers in cmd/ delegate to this package.
package fix

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/kernel"
	"github.com/sufield/stave/internal/core/ports"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// FindingsParser parses raw evaluation JSON into findings.
// Injected from the adapters layer by cmd/ callers.
type FindingsParser func(data []byte) ([]remediation.Finding, error)

// Service orchestrates finding remediation workflows.
type Service struct {
	Clock         ports.Clock
	Planner       *remediation.Planner
	Sanitizer     kernel.Sanitizer
	ParseFindings FindingsParser
	CELEvaluator  policy.PredicateEval
}

// NewService creates a Service. The caller must set ParseFindings
// before calling Fix.
func NewService(clock ports.Clock, planner *remediation.Planner) *Service {
	return &Service{
		Clock:   clock,
		Planner: planner,
	}
}

// FixRequest defines the parameters for a single-finding fix operation.
type FixRequest struct {
	InputPath  string
	FindingRef string // Format: <control_id>@<asset_id>
	Stdout     io.Writer
}

// Fix reads an evaluation artifact and generates a remediation plan for one finding.
func (s *Service) Fix(ctx context.Context, req FixRequest) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	needle := strings.TrimSpace(req.FindingRef)
	if needle == "" {
		return fmt.Errorf("finding reference selector cannot be empty")
	}

	path := filepath.Clean(req.InputPath)
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading input file: %w", err)
	}

	findings, err := s.ParseFindings(data)
	if err != nil {
		return fmt.Errorf("parsing evaluation results: %w", err)
	}
	if len(findings) == 0 {
		return fmt.Errorf("no findings found in %s", path)
	}

	selected, err := SelectFinding(findings, needle)
	if err != nil {
		return err
	}

	if selected.RemediationPlan == nil {
		selected.RemediationPlan = s.Planner.PlanFor(selected)
	}

	return WriteFixResult(req.Stdout, selected)
}

// SelectFinding locates a finding by its canonical key (<control_id>@<asset_id>).
// Delegates to remediation.SelectFinding in core.
func SelectFinding(findings []remediation.Finding, needle string) (remediation.Finding, error) {
	return remediation.SelectFinding(findings, needle)
}

// WriteFixResult writes the fix plan as JSON.
func WriteFixResult(w io.Writer, f remediation.Finding) error {
	out := struct {
		Finding     string                      `json:"finding"`
		ControlID   string                      `json:"control_id"`
		ControlName string                      `json:"control_name"`
		AssetID     string                      `json:"asset_id"`
		AssetType   string                      `json:"asset_type"`
		Remediation string                      `json:"remediation,omitempty"`
		FixPlan     *evaluation.RemediationPlan `json:"fix_plan"`
	}{
		Finding:     FindingKey(f),
		ControlID:   f.ControlID.String(),
		ControlName: f.ControlName,
		AssetID:     f.AssetID.String(),
		AssetType:   f.AssetType.String(),
		Remediation: strings.TrimSpace(f.RemediationSpec.Action),
		FixPlan:     f.RemediationPlan,
	}
	return jsonutil.WriteIndented(w, out)
}

// FindingKey returns the canonical string selector for a finding.
// Delegates to remediation.FindingKey in core.
func FindingKey(f remediation.Finding) string {
	return remediation.FindingKey(f)
}
