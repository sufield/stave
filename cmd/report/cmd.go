// Package report implements the 'stave report' command for executive
// report data export.
package report

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/app/contracts"
	er "github.com/sufield/stave/internal/app/execreport"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type options struct {
	HistoryDir    string
	SnapshotPath  string
	ControlsDir   string
	ChainsDir     string
	SLAFile       string
	TeamManifest  string
	Format        contracts.OutputFormat
	OutFile       string
	Title         string
	Period        string
	TeamBreakdown bool
}

// NewCmd constructs the report command with the given dependencies.
// cmd/commands.go is responsible for resolving the production factories.
func NewCmd(deps Deps) *cobra.Command {
	opts := &options{
		ControlsDir: "controls",
		ChainsDir:   "chains",
		Format:      contracts.FormatJSON,
		Title:       "Security Posture Report",
	}

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Generate executive security posture report",
		Long: `Aggregate all assessment dimensions into a single structured
report document: posture score, findings summary, SLA compliance,
top findings, active chains, ATT&CK coverage, framework readiness,
team attribution, and executive summary.

Consumers render the report however needed — Jinja template,
Python script, Pandoc, or direct API consumption.

Inputs:
  --history PATH          History directory (required)
  --snapshot PATH         Snapshot to assess (required)
  --sla-profile-file PATH SLA policy
  --team-manifest PATH    Team manifest
  --format STRING         json (default) | markdown
  --out PATH              Write to file
  --title STRING          Report title
  --period STRING         Reporting period label

Exit Codes:
  0   Report generated
  2   Invalid input
  4   Internal error`,
		Example: `  stave report --history ./history --snapshot latest.json
  stave report --history ./history --snapshot latest.json \
    --sla-profile-file sla.yaml --team-manifest teams.yaml \
    --format markdown --out report.md`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runReport(cmd.Context(), cmd.OutOrStdout(), opts, deps)
		},
	}

	cmd.Flags().StringVar(&opts.HistoryDir, "history", "", "history directory (required)")
	cmd.Flags().StringVar(&opts.SnapshotPath, "snapshot", "", "snapshot to assess (required)")
	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "controls", "controls directory")
	cmd.Flags().StringVar(&opts.ChainsDir, "chains", "chains", "chains directory")
	cmd.Flags().StringVar(&opts.SLAFile, "sla-profile-file", "", "SLA policy file")
	cmd.Flags().StringVar(&opts.TeamManifest, "team-manifest", "", "team manifest")
	cmd.Flags().VarP(&opts.Format, "format", "f", "output format: json | markdown")
	cmd.Flags().StringVar(&opts.OutFile, "out", "", "write to file")
	cmd.Flags().StringVar(&opts.Title, "title", "Security Posture Report", "report title")
	cmd.Flags().StringVar(&opts.Period, "period", "", "reporting period label")
	cmd.Flags().BoolVar(&opts.TeamBreakdown, "team-breakdown", false, "Include per-team findings breakdown in report")

	cliflags.MustMarkRequired(cmd, "history")
	cliflags.MustMarkRequired(cmd, "snapshot")

	return cmd
}

func runReport(ctx context.Context, stdout io.Writer, opts *options, deps Deps) error {
	builder, err := buildReportBuilder(deps)
	if err != nil {
		return err
	}
	report, err := builder.Build(ctx, er.BuilderInput{
		HistoryDir:       opts.HistoryDir,
		SnapshotPath:     opts.SnapshotPath,
		ControlsDir:      opts.ControlsDir,
		ChainsDir:        opts.ChainsDir,
		SLAFile:          opts.SLAFile,
		TeamManifestPath: opts.TeamManifest,
		Title:            opts.Title,
		Period:           opts.Period,
		Now:              time.Now().UTC(),
	})
	if err != nil {
		return &ui.UserError{Err: err}
	}

	return writeReport(stdout, opts, report)
}

// buildReportBuilder instantiates the app-layer Builder by resolving
// every port from the cmd-supplied factory closures. Each factory
// call produces an independent loader; errors here surface as
// configuration / wiring failures.
func buildReportBuilder(deps Deps) (*er.Builder, error) {
	artifactLoader, err := deps.NewArtifactLoader()
	if err != nil {
		return nil, fmt.Errorf("create artifact loader: %w", err)
	}
	chainLoader, err := deps.NewChainLoader()
	if err != nil {
		return nil, fmt.Errorf("create chain loader: %w", err)
	}
	slaProvider, err := deps.NewSLALoader()
	if err != nil {
		return nil, fmt.Errorf("create sla provider: %w", err)
	}
	bundleLoader, err := deps.NewSnapshotBundleLoader()
	if err != nil {
		return nil, fmt.Errorf("create snapshot bundle loader: %w", err)
	}
	ctlRepo, err := deps.NewCtlRepo()
	if err != nil {
		return nil, fmt.Errorf("create control loader: %w", err)
	}
	return &er.Builder{
		Deps: er.BuilderDeps{
			ArtifactLoader:       artifactLoader,
			ChainLoader:          chainLoader,
			SLAProvider:          slaProvider,
			SnapshotBundleLoader: bundleLoader,
			ControlRepo:          ctlRepo,
		},
	}, nil
}

// writeReport handles the format dispatch + file/stdout sink and
// preserves the close-error-after-write rule (write errors win
// over close errors so partial-output failures aren't masked).
func writeReport(stdout io.Writer, opts *options, report *er.Report) error {
	w := stdout
	var f *os.File
	if opts.OutFile != "" {
		// SafeCreateFile applies symlink rejection and 0o600 perms
		// — a report contains finding IDs and may carry sensitive
		// asset identifiers, so a world-readable file (the default
		// os.Create behaviour) is the wrong default. Mirrors the
		// cmd/evaluate output-write pattern.
		writeOpts := fsutil.DefaultWriteOpts()
		writeOpts.Overwrite = true
		var fErr error
		f, fErr = fsutil.SafeCreateFile(opts.OutFile, writeOpts)
		if fErr != nil {
			return fmt.Errorf("create output file: %w", fErr)
		}
		w = f
	}

	renderer, rendErr := NewRenderer(opts.Format)
	if rendErr != nil {
		if f != nil {
			_ = f.Close()
		}
		return rendErr
	}
	writeErr := renderer.Render(w, report)

	if f != nil {
		closeErr := f.Close()
		if writeErr == nil {
			writeErr = closeErr
		}
	}
	return writeErr
}
