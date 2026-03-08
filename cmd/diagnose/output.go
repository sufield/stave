package diagnose

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	outjson "github.com/sufield/stave/internal/adapters/output/json"
	outtext "github.com/sufield/stave/internal/adapters/output/text"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/domain/evaluation/diagnosis"
	"github.com/sufield/stave/internal/domain/policy"
	"github.com/sufield/stave/internal/safetyenvelope"
)

func diagnoseOutput(cmd *cobra.Command, quiet bool) io.Writer {
	if quiet {
		return io.Discard
	}
	return cmd.OutOrStdout()
}

func renderDiagnoseOutput(cmd *cobra.Command, opts diagnoseOptions, report *diagnosis.Report) error {
	if opts.Template != "" {
		return renderDiagnoseTemplate(cmd, opts, report)
	}
	format, err := ui.ParseOutputFormat(opts.Format)
	if err != nil {
		return err
	}
	out := diagnoseOutput(cmd, opts.Quiet)
	if err := writeDiagnoseReport(cmd, out, format, report); err != nil {
		return err
	}
	return diagnoseDiagnosisExit(report)
}

func renderDiagnoseTemplate(cmd *cobra.Command, opts diagnoseOptions, report *diagnosis.Report) error {
	out := diagnoseOutput(cmd, opts.Quiet)
	if err := ui.ExecuteTemplate(out, opts.Template, safetyenvelope.NewDiagnose(report)); err != nil {
		return err
	}
	return diagnoseDiagnosisExit(report)
}

func diagnoseDiagnosisExit(report *diagnosis.Report) error {
	if len(report.Entries) > 0 {
		return ui.ErrDiagnosticsFound
	}
	return nil
}

func writeDiagnoseReport(cmd *cobra.Command, out io.Writer, format ui.OutputFormat, report *diagnosis.Report) error {
	if format.IsJSON() || cmdutil.IsJSONMode(cmd) {
		return writeDiagnoseJSON(cmd, out, report)
	}
	return outtext.WriteDiagnosisReport(out, report, func(level, msg string) string {
		return ui.SeverityLabel(level, msg, out)
	})
}

// writeDiagnoseJSON outputs diagnostic report as JSON.
// If global JSON mode is set, wraps output in {"ok": true, "data": ...}.
func writeDiagnoseJSON(cmd *cobra.Command, w io.Writer, report *diagnosis.Report) error {
	return outjson.WriteDiagnosis(w, report, cmdutil.IsJSONMode(cmd))
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
	// Use the trace package's JSON format for consistency with `stave trace --format json`.
	if detail.Trace != nil && detail.Trace.Raw != nil {
		var buf bytes.Buffer
		if err := detail.Trace.Raw.RenderJSON(&buf); err == nil {
			out.Trace = buf.Bytes()
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
