// Package fix provides the single-finding remediation and fix-loop
// verification workflows. Command handlers in cmd/ delegate to this package.
package fix

import (
	"context"
	"errors"
	"fmt"
	"io"
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
	ReadFile      func(string) ([]byte, error) // injected by cmd layer; must enforce size limits
}

// NewService creates a Service. The caller must set ParseFindings
// before calling Fix.
func NewService(clock ports.Clock, planner *remediation.Planner) *Service {
	return &Service{
		Clock:   clock,
		Planner: planner,
	}
}

// Request defines the parameters for a single-finding fix operation.
type Request struct {
	InputPath  string
	FindingRef string // Format: <control_id>@<asset_id>
	Stdout     io.Writer
}

// Fix reads an evaluation artifact and generates a remediation plan for one finding.
func (s *Service) Fix(ctx context.Context, req Request) error {
	if err := ctx.Err(); err != nil {
		return fmt.Errorf("err: %w", err)
	}
	needle := strings.TrimSpace(req.FindingRef)
	if needle == "" {
		return errors.New("finding reference selector cannot be empty")
	}

	path := filepath.Clean(req.InputPath)
	readFn := s.ReadFile
	if readFn == nil {
		return errors.New("readFile not configured on fix.Service")
	}
	data, err := readFn(path)
	if err != nil {
		return fmt.Errorf("reading input file: %w", err)
	}

	if s.ParseFindings == nil {
		// Match the ReadFile guard above: ParseFindings is a
		// foundational dependency. Hand-built Service instances
		// (tests, alternative composition roots) that forgot to
		// supply it would otherwise hit a nil-function-call panic
		// here. Surface as a wiring error so the call site sees
		// the missing dependency name instead of a runtime crash.
		return errors.New("parseFindings not configured on fix.Service")
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

	EnsurePlan(&selected)

	return WriteFixResult(req.Stdout, &selected)
}

// EnsurePlan mutates f in place to ensure it has a non-nil
// RemediationPlan, generating one via the default planner when
// missing. Centralises the "every finding needs a plan" business
// rule. Pointer receiver because remediation.Finding is a heavy
// value type and gocritic flags the by-value form (864 bytes).
func EnsurePlan(f *remediation.Finding) {
	if f == nil {
		return
	}
	if f.RemediationPlan == nil {
		f.RemediationPlan = remediation.NewPlanner().PlanFor(f)
	}
}

// SelectFinding locates a finding by its canonical key (<control_id>@<asset_id>).
// Delegates to remediation.SelectFinding in core.
func SelectFinding(findings []remediation.Finding, needle string) (remediation.Finding, error) {
	f, err := remediation.SelectFinding(findings, needle)
	if err != nil {
		return remediation.Finding{}, fmt.Errorf("select finding: %w", err)
	}
	return f, nil
}

// WriteFixResult writes the fix plan as JSON with structured changes.
func WriteFixResult(w io.Writer, f *remediation.Finding) error {
	changes := policy.DeriveChanges(f.Evidence.Misconfigurations)

	out := struct {
		FindingID   string                      `json:"finding_id"`
		Finding     string                      `json:"finding"`
		ControlID   string                      `json:"control_id"`
		ControlName string                      `json:"control_name"`
		AssetID     string                      `json:"asset_id"`
		AssetType   string                      `json:"asset_type"`
		Remediation string                      `json:"remediation,omitempty"`
		Confidence  float64                     `json:"confidence"`
		Changes     []policy.PropertyChange     `json:"changes"`
		FixPlan     *evaluation.RemediationPlan `json:"fix_plan"`
	}{
		FindingID:   string(f.FindingID),
		Finding:     FindingKey(f),
		ControlID:   f.ControlID.String(),
		ControlName: f.ControlName,
		AssetID:     f.AssetID.String(),
		AssetType:   f.AssetType.String(),
		Remediation: strings.TrimSpace(f.RemediationSpec.Action),
		Confidence:  deriveConfidence(changes),
		Changes:     changes,
		FixPlan:     f.RemediationPlan,
	}
	if err := jsonutil.WriteIndented(w, out); err != nil {
		return fmt.Errorf("write indented: %w", err)
	}
	return nil
}

// deriveConfidence returns a confidence score based on whether all
// changes have safe defaults.
func deriveConfidence(changes []policy.PropertyChange) float64 {
	if len(changes) == 0 {
		return policy.ConfidenceFloat("")
	}
	allSafe := true
	for i := range changes {
		if !changes[i].HasSafeDefault {
			allSafe = false
			break
		}
	}
	if allSafe {
		return policy.ConfidenceFloat("HIGH")
	}
	return policy.ConfidenceFloat("MEDIUM")
}

// FindingKey returns the canonical string selector for a finding.
// Delegates to remediation.FindingKey in core.
func FindingKey(f *remediation.Finding) string {
	return remediation.FindingKey(f)
}
