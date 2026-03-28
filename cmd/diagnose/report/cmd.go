package report

import (
	_ "embed"
	"fmt"
	"log/slog"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	reportrender "github.com/sufield/stave/internal/adapters/output/report"
	"github.com/sufield/stave/internal/core/reporting"
	infrareport "github.com/sufield/stave/internal/infra/report"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
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
			fmtValue, err := opts.resolveFormat(cmd)
			if err != nil {
				return err
			}

			// Audit git state before running the report (CLI concern).
			res, resolverErr := projctx.NewResolver()
			if resolverErr != nil {
				slog.Warn("failed to resolve project context", "error", resolverErr)
			}
			if res != nil {
				gitInfo := compose.AuditGitStatus(res.ProjectRoot(), resolveAuditPaths(res))
				compose.WarnGitDirty(cmd.ErrOrStderr(), gitInfo, "report", flags.Quiet)
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
				return ucErr
			}

			// Adapter: render in requested format
			eval, ok := infrareport.TypedEvaluation(ucResp.EvaluationData)
			if !ok {
				return fmt.Errorf("unexpected evaluation data type")
			}
			if fmtValue.IsJSON() {
				return reportrender.RenderJSON(*eval, staveversion.String, cmd.OutOrStdout(), flags.Quiet)
			}
			return reportrender.RenderText(*eval, reportrender.RenderTextOptions{
				StaveVersion:    staveversion.String,
				DefaultTemplate: defaultReportTemplate,
				TemplatePath:    fsutil.CleanUserPath(opts.TemplateFile),
				Writer:          cmd.OutOrStdout(),
				Quiet:           flags.Quiet,
			})
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.BindFlags(cmd)

	return cmd
}

// resolveAuditPaths determines which files should be checked for uncommitted changes.
func resolveAuditPaths(res *projctx.Resolver) []string {
	var paths []string

	configRes, err := projconfig.NewResolver()
	if err == nil {
		_, cfgPath, cfgErr := configRes.FindProjectConfig("")
		if cfgErr == nil {
			paths = append(paths, cfgPath)
		}
	}

	sc, err := res.ResolveSelected()
	if err == nil && sc.Active && sc.Context != nil {
		if p := strings.TrimSpace(sc.Context.Defaults.ControlsDir); p != "" {
			paths = append(paths, sc.Context.AbsPath(p))
		}
	} else {
		paths = append(paths, "controls")
	}

	return paths
}
