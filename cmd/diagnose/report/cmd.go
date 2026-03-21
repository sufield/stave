package report

import (
	"context"
	_ "embed"
	"fmt"
	"io"
	"log/slog"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/projconfig"
	"github.com/sufield/stave/cmd/cmdutil/projctx"
	"github.com/sufield/stave/cmd/enforce/shared"
	reportrender "github.com/sufield/stave/internal/adapters/output/report"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
	"github.com/sufield/stave/internal/platform/fsutil"
	staveversion "github.com/sufield/stave/internal/version"
)

//go:embed templates/report_default.tmpl
var defaultReportTemplate string

// Request defines the parameters for generating a report.
type Request struct {
	InputFile    string
	TemplateFile string
	Format       ui.OutputFormat
	Quiet        bool
	Stdout       io.Writer
	Stderr       io.Writer

	// Metadata for Git auditing
	ProjectRoot string
	AuditPaths  []string
}

// Runner orchestrates the loading, auditing, and rendering of reports.
type Runner struct {
	Version         string
	DefaultTemplate string
}

// NewRunner initializes a report runner with default settings.
func NewRunner() *Runner {
	return &Runner{
		Version:         staveversion.String,
		DefaultTemplate: defaultReportTemplate,
	}
}

// Run executes the report generation process.
func (r *Runner) Run(_ context.Context, req Request) error {
	inputFile := fsutil.CleanUserPath(req.InputFile)
	eval, err := shared.NewLoader().Evaluation(inputFile)
	if err != nil {
		return fmt.Errorf("loading evaluation: %w", err)
	}

	if req.ProjectRoot != "" {
		gitInfo := compose.AuditGitStatus(req.ProjectRoot, req.AuditPaths)
		compose.WarnGitDirty(req.Stderr, gitInfo, "report", req.Quiet)
	}

	if req.Format.IsJSON() {
		return reportrender.RenderJSON(*eval, r.Version, req.Stdout, req.Quiet)
	}

	return reportrender.RenderText(*eval, reportrender.RenderTextOptions{
		StaveVersion:    r.Version,
		DefaultTemplate: r.DefaultTemplate,
		TemplatePath:    fsutil.CleanUserPath(req.TemplateFile),
		Writer:          req.Stdout,
		Quiet:           req.Quiet,
	})
}

// --- Cobra Command Constructor ---

// NewReportCmd constructs the report command.
func NewReportCmd() *cobra.Command {
	var (
		inputFile    string
		formatFlag   string
		templateFile string
	)

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate a plain-text report from evaluation output",
		Long:  `Report reads evaluation JSON and renders plaintext output.` + metadata.OfflineHelpSuffix,
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			flags := cmdutil.GetGlobalFlags(cmd)
			fmtValue, err := compose.ResolveFormatValue(cmd, formatFlag)
			if err != nil {
				return err
			}

			res, resolverErr := projctx.NewResolver()
			if resolverErr != nil {
				slog.Warn("failed to resolve project context", "error", resolverErr)
			}

			var projectRoot string
			var auditPaths []string
			if res != nil {
				projectRoot = res.ProjectRoot()
				auditPaths = resolveAuditPaths(res)
			}

			req := Request{
				InputFile:    inputFile,
				TemplateFile: templateFile,
				Format:       fmtValue,
				Quiet:        flags.Quiet,
				Stdout:       cmd.OutOrStdout(),
				Stderr:       cmd.ErrOrStderr(),
				ProjectRoot:  projectRoot,
				AuditPaths:   auditPaths,
			}

			return NewRunner().Run(cmd.Context(), req)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	cmd.Flags().StringVarP(&inputFile, "in", "i", "", "Path to evaluation JSON file (required)")
	cmd.Flags().StringVarP(&formatFlag, "format", "f", "text", "Output format (text|json)")
	cmd.Flags().StringVar(&templateFile, "template-file", "", "Path to custom Go template")
	_ = cmd.MarkFlagRequired("in")
	_ = cmd.RegisterFlagCompletionFunc("format", cmdutil.CompleteFixed("text", "json"))

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
