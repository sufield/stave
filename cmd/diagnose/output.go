package diagnose

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	appcontracts "github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/cli/ui"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/diagnosis"
	corereport "github.com/sufield/stave/internal/core/report"
)

// Presenter handles formatting and writing diagnostic results.
// The writer W must be pre-resolved by the caller (use io.Discard for quiet mode).
type Presenter struct {
	W        io.Writer
	Format   appcontracts.OutputFormat
	Template string
}

// RenderReport writes a standard diagnostic report.
func (p *Presenter) RenderReport(report *diagnosis.Report) error {
	if p.Template != "" {
		if err := ui.ExecuteTemplate(p.W, p.Template, corereport.NewReadiness(report)); err != nil {
			return fmt.Errorf("execute template: %w", err)
		}
		return nil
	}
	renderer, err := NewReportRenderer(p.Format)
	if err != nil {
		return err
	}
	if err := renderer.Render(p.W, report); err != nil {
		return fmt.Errorf("render output: %w", err)
	}
	return nil
}

// RenderDetail writes a single-finding deep-dive result.
func (p *Presenter) RenderDetail(detail *evaluation.FindingDetail) error {
	renderer, err := NewDetailRenderer(p.Format)
	if err != nil {
		return err
	}
	if err := renderer.Render(p.W, detail); err != nil {
		return fmt.Errorf("render output: %w", err)
	}
	return nil
}

// jsonTrace implements json.Marshaler for lazy trace rendering.
// The encoder calls MarshalJSON only when it reaches the field.
type jsonTrace struct {
	trace *evaluation.FindingTrace
}

func (jt jsonTrace) MarshalJSON() ([]byte, error) {
	if jt.trace == nil || jt.trace.Raw == nil {
		return []byte("null"), nil
	}
	var buf bytes.Buffer
	if err := jt.trace.Raw.RenderJSON(&buf); err != nil {
		return nil, fmt.Errorf("render trace JSON: %w", err)
	}
	return buf.Bytes(), nil
}

func writeFindingDetailJSON(w io.Writer, detail *evaluation.FindingDetail) error {
	type detailOutput struct {
		Control         evaluation.FindingControlSummary `json:"control"`
		Asset           evaluation.FindingAssetSummary   `json:"asset"`
		Evidence        evaluation.Evidence              `json:"evidence"`
		Trace           *jsonTrace                       `json:"trace,omitempty"`
		Remediation     *policy.RemediationSpec          `json:"remediation,omitempty"`
		RemediationPlan *evaluation.RemediationPlan      `json:"fix_plan,omitempty"`
		NextSteps       []string                         `json:"next_steps"`
	}
	out := detailOutput{
		Control:         detail.Control,
		Asset:           detail.Asset,
		Evidence:        detail.Evidence,
		Remediation:     detail.Remediation,
		RemediationPlan: detail.RemediationPlan,
		NextSteps:       detail.NextSteps,
	}
	if detail.Trace != nil {
		out.Trace = &jsonTrace{trace: detail.Trace}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
