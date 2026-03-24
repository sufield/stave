package diagnose

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	outjson "github.com/sufield/stave/internal/adapters/output/json"
	outtext "github.com/sufield/stave/internal/adapters/output/text"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/pkg/jsonutil"
	"github.com/sufield/stave/internal/safetyenvelope"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation"
	"github.com/sufield/stave/pkg/alpha/domain/evaluation/diagnosis"
	"github.com/sufield/stave/pkg/alpha/domain/policy"
)

// Presenter handles formatting and writing diagnostic results.
type Presenter struct {
	Stdout   io.Writer
	Format   ui.OutputFormat
	Quiet    bool
	Template string
}

// RenderReport writes a standard diagnostic report.
func (p *Presenter) RenderReport(report *diagnosis.Report) error {
	if p.Template != "" {
		out := compose.ResolveStdout(p.Stdout, p.Quiet, "text")
		return ui.ExecuteTemplate(out, p.Template, safetyenvelope.NewDiagnose(report))
	}
	out := compose.ResolveStdout(p.Stdout, p.Quiet, p.Format)
	if p.Format.IsJSON() {
		return outjson.WriteDiagnosis(out, report)
	}
	return outtext.WriteDiagnosisReport(out, report, func(level, msg string) string {
		return ui.SeverityLabel(level, msg, out)
	})
}

// RenderDetail writes a single-finding deep-dive result.
func (p *Presenter) RenderDetail(detail *evaluation.FindingDetail) error {
	out := compose.ResolveStdout(p.Stdout, p.Quiet, p.Format)
	if p.Format.IsJSON() {
		return writeFindingDetailJSON(out, detail)
	}
	return outtext.WriteFindingDetail(out, detail)
}

func writeFindingDetailJSON(w io.Writer, detail *evaluation.FindingDetail) error {
	type detailOutput struct {
		Control         evaluation.FindingControlSummary `json:"control"`
		Asset           evaluation.FindingAssetSummary   `json:"asset"`
		Evidence        evaluation.Evidence              `json:"evidence"`
		Trace           json.RawMessage                  `json:"trace,omitempty"`
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
	if detail.Trace != nil && detail.Trace.Raw != nil {
		var buf bytes.Buffer
		if err := detail.Trace.Raw.RenderJSON(&buf); err == nil {
			out.Trace = buf.Bytes()
		}
	}
	return jsonutil.WriteIndented(w, out)
}
