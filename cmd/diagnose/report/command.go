package report

import (
	_ "embed"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/enforce/shared"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
	reportrender "github.com/sufield/stave/internal/report"
	staveversion "github.com/sufield/stave/internal/version"
)

var (
	reportInputFile    string
	reportFormat       string
	reportTemplateFile string
)

//go:embed templates/report_default.tmpl
var defaultReportTemplate string

var ReportCmd = &cobra.Command{
	Use:   "report",
	Short: "Generate a plain-text report from evaluation output",
	Long: `Report reads evaluation JSON and renders plaintext output.

By default it uses an embedded deterministic Go template.
You can provide a custom template via --template-file.

Template data model:
  .Metadata
  .Summary
  .Findings
  .SeverityGroups
  .Remediations

Supported template syntax:
  {{ .Field }}
  {{ .Nested.Field }}
  {{ range .Slice }}...{{ end }}
  {{ json .Field }}
  {{"\n"}}` + metadata.OfflineHelpSuffix,
	Args:          cobra.NoArgs,
	RunE:          runReport,
	SilenceUsage:  true,
	SilenceErrors: true,
}

func init() {
	ReportCmd.Flags().StringVarP(&reportInputFile, "in", "i", "", "Path to evaluation JSON file (required)")
	ReportCmd.Flags().StringVarP(&reportFormat, "format", "f", "text", "Output format: text or json")
	ReportCmd.Flags().StringVar(&reportTemplateFile, "template-file", "", "Path to custom Go template for text report output")
	_ = ReportCmd.MarkFlagRequired("in")
	_ = ReportCmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))
}

func runReport(cmd *cobra.Command, _ []string) error {
	if err := cmdutil.EnsureContextSelectionValid(); err != nil {
		return err
	}
	reportInputFile = fsutil.CleanUserPath(reportInputFile)
	reportTemplateFile = fsutil.CleanUserPath(reportTemplateFile)

	eval, err := shared.LoadEvaluationEnvelope(reportInputFile)
	if err != nil {
		return err
	}

	cmdutil.WarnIfGitDirty(cmd, collectReportGitAudit(), "report")

	format, err := cmdutil.ResolveFormatValue(cmd, reportFormat)
	if err != nil {
		return err
	}

	quiet := cmdutil.QuietEnabled(cmd)
	if format.IsJSON() {
		return reportrender.RenderJSON(*eval, staveversion.Version, cmd.OutOrStdout(), quiet)
	}
	return reportrender.RenderText(
		*eval,
		staveversion.Version,
		defaultReportTemplate,
		reportTemplateFile,
		cmd.OutOrStdout(),
		quiet,
	)
}

func collectReportGitAudit() *evaluation.GitInfo {
	cfg, _ := selectedContextConfigPath()
	ctl := selectedContextControlsPath()
	base := cmdutil.RootForContextName()
	return cmdutil.CollectGitAudit(base, []string{ctl, cfg})
}

func selectedContextConfigPath() (string, bool) {
	if sc, err := cmdutil.ResolveSelectedGlobalContext(); err == nil && sc.Active && sc.Context != nil {
		if p := strings.TrimSpace(sc.Context.ProjectConfig); p != "" {
			return sc.Context.AbsPath(p), true
		}
	}
	_, path, ok := cmdutil.FindProjectConfigWithPath()
	return path, ok
}

func selectedContextControlsPath() string {
	if sc, err := cmdutil.ResolveSelectedGlobalContext(); err == nil && sc.Active && sc.Context != nil {
		if p := strings.TrimSpace(sc.Context.Defaults.ControlsDir); p != "" {
			return sc.Context.AbsPath(p)
		}
	}
	return "controls"
}
