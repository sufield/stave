package diagnose

import (
	"bytes"
	"encoding/json"
	"io"

	outjson "github.com/sufield/stave/internal/adapters/output/json"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/diagnosis"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/pkg/jsonutil"
)

// writeDiagnoseJSON outputs diagnostic report as JSON.
// If envelopeMode is true, wraps output in {"ok": true, "data": ...}.
func writeDiagnoseJSON(w io.Writer, report *diagnosis.Report, envelopeMode bool) error {
	return outjson.WriteDiagnosis(w, report, envelopeMode)
}

// writeFindingDetailJSON outputs a FindingDetail as JSON.
func writeFindingDetailJSON(w io.Writer, detail *evaluation.FindingDetail) error {
	type jsonFindingDetail struct {
		Control         evaluation.FindingControlSummary `json:"control"`
		Asset           evaluation.FindingAssetSummary   `json:"asset"`
		Evidence        evaluation.Evidence              `json:"evidence"`
		Trace           json.RawMessage                  `json:"trace,omitempty"`
		Remediation     *policy.RemediationSpec          `json:"remediation,omitempty"`
		RemediationPlan *evaluation.RemediationPlan      `json:"fix_plan,omitempty"`
		NextSteps       []string                         `json:"next_steps"`
	}
	out := jsonFindingDetail{
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
