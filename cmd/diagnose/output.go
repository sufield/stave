package diagnose

import (
	"bytes"
	"encoding/json"
	"io"

	outjson "github.com/sufield/stave/internal/adapters/output/json"
	outtext "github.com/sufield/stave/internal/adapters/output/text"
	"github.com/sufield/stave/internal/cli/ui"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/core/evaluation"
	"github.com/sufield/stave/internal/core/evaluation/diagnosis"
	"github.com/sufield/stave/internal/safetyenvelope"
)

// Presenter handles formatting and writing diagnostic results.
// The writer W must be pre-resolved by the caller (use io.Discard for quiet mode).
type Presenter struct {
	W        io.Writer
	Format   ui.OutputFormat
	Template string
}

// RenderReport writes a standard diagnostic report.
func (p *Presenter) RenderReport(report *diagnosis.Report) error {
	if p.Template != "" {
		return ui.ExecuteTemplate(p.W, p.Template, safetyenvelope.NewDiagnose(report))
	}
	if p.Format.IsJSON() {
		return outjson.WriteDiagnosis(p.W, report)
	}
	return outtext.WriteDiagnosisReport(p.W, report, func(level, msg string) string {
		return ui.SeverityLabel(level, msg, p.W)
	})
}

// RenderDetail writes a single-finding deep-dive result.
func (p *Presenter) RenderDetail(detail *evaluation.FindingDetail) error {
	if p.Format.IsJSON() {
		return writeFindingDetailJSON(p.W, detail)
	}
	return outtext.WriteFindingDetail(p.W, detail)
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
		return nil, err
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
