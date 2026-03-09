package report

import (
	_ "embed"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	"github.com/sufield/stave/cmd/enforce/shared"
	"github.com/sufield/stave/internal/domain/evaluation"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
	reportrender "github.com/sufield/stave/internal/report"
	staveversion "github.com/sufield/stave/internal/version"
)

type reportFlagsType struct {
	inputFile    string
	format       string
	templateFile string
}

//go:embed templates/report_default.tmpl
var defaultReportTemplate string

// NewReportCmd constructs the report command with closure-scoped flags.
func NewReportCmd() *cobra.Command {
	var flags reportFlagsType

	cmd := &cobra.Command{
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
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runReport(cmd, &flags)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&flags.inputFile, "in", "i", "", "Path to evaluation JSON file (required)")
	cmd.Flags().StringVarP(&flags.format, "format", "f", "text", "Output format: text or json")
	cmd.Flags().StringVar(&flags.templateFile, "template-file", "", "Path to custom Go template for text report output")
	_ = cmd.MarkFlagRequired("in")
	_ = cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))

	return cmd
}

func runReport(cmd *cobra.Command, flags *reportFlagsType) error {
	if err := projctx.EnsureContextSelectionValid(); err != nil {
		return err
	}
	inputFile := fsutil.CleanUserPath(flags.inputFile)
	templateFile := fsutil.CleanUserPath(flags.templateFile)

	eval, err := shared.LoadEvaluationEnvelope(inputFile)
	if err != nil {
		return err
	}

	compose.WarnIfGitDirty(cmd, collectReportGitAudit(), "report")

	format, err := compose.ResolveFormatValue(cmd, flags.format)
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
		templateFile,
		cmd.OutOrStdout(),
		quiet,
	)
}

func collectReportGitAudit() *evaluation.GitInfo {
	cfg, _ := selectedContextConfigPath()
	ctl := selectedContextControlsPath()
	base := projctx.RootForContextName()
	return compose.CollectGitAudit(base, []string{ctl, cfg})
}

func selectedContextConfigPath() (string, bool) {
	if sc, err := projctx.ResolveSelectedGlobalContext(); err == nil && sc.Active && sc.Context != nil {
		if p := strings.TrimSpace(sc.Context.ProjectConfig); p != "" {
			return sc.Context.AbsPath(p), true
		}
	}
	_, path, ok := projconfig.FindProjectConfigWithPath()
	return path, ok
}

func selectedContextControlsPath() string {
	if sc, err := projctx.ResolveSelectedGlobalContext(); err == nil && sc.Active && sc.Context != nil {
		if p := strings.TrimSpace(sc.Context.Defaults.ControlsDir); p != "" {
			return sc.Context.AbsPath(p)
		}
	}
	return "controls"
}
