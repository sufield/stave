package report

import (
	_ "embed"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/core/reporting"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/internal/platform/metadata"
	staveversion "github.com/sufield/stave/internal/version"
)

//go:embed templates/report_default.tmpl
var defaultReportTemplate string

// --- Cobra Command Constructor ---

// Deps groups the infrastructure implementations for the report command.
type Deps struct {
	UseCaseDeps reporting.ReportDeps
}

// NewReportCmd constructs the report command.
func NewReportCmd(deps Deps) *cobra.Command {
	reportDeps := deps.UseCaseDeps
	opts := &options{
		Format: "text",
	}

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate a plain-text report from evaluation output",
		Long: `Report reads evaluation JSON and renders a formatted summary of findings,
controls evaluated, and asset coverage.

Inputs:
  --in, -i            Path to evaluation JSON file (required)
  --format, -f        Output format: text or json (default: text)
  --template-file     Path to custom Go template for text output

Outputs:
  stdout              Rendered report (text or JSON)
  stderr              Error messages and git-dirty warnings (if any)

Exit Codes:
  0   - Report generated successfully
  2   - Invalid input (missing file, bad format)
  4   - Internal error
  130 - Interrupted (SIGINT)

Examples:
  # Render text report from evaluation output
  stave report --in output/evaluation.json

  # JSON report for scripting
  stave report --in output/evaluation.json --format json | jq .summary

  # Use a custom template
  stave report --in output/evaluation.json --template-file ./my-template.tmpl` + metadata.OfflineHelpSuffix,
		Example: `  stave report --in evaluation.json --format text`,
		Args:    cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return opts.Prepare(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			flags := cliflags.GetGlobalFlags(cmd)
			fmtValue, err := opts.resolveFormat()
			if err != nil {
				return err
			}

			renderer, err := NewRenderer(fmtValue)
			if err != nil {
				return err
			}

			// Use case: load evaluation
			ucReq := reporting.ReportRequest{
				InputFile:    opts.InputFile,
				TemplateFile: opts.TemplateFile,
				Format:       string(fmtValue),
				Quiet:        flags.Quiet,
			}
			ucResp, ucErr := reporting.Report(cmd.Context(), ucReq, reportDeps)
			if ucErr != nil {
				return fmt.Errorf("generate report: %w", ucErr)
			}

			// Adapter: render in requested format
			return renderer.Render(cmd.OutOrStdout(), reportPayload{
				Eval:            *ucResp.EvaluationData,
				StaveVersion:    staveversion.String,
				DefaultTemplate: defaultReportTemplate,
				TemplatePath:    fsutil.CleanUserPath(opts.TemplateFile),
				Quiet:           flags.Quiet,
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.BindFlags(cmd)

	return cmd
}
