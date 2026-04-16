// Package plan implements the 'stave plan' command for team-routed
// remediation plan export.
package plan

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/app/plan"
	"github.com/sufield/stave/internal/app/teams"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type options struct {
	Assessment   string
	TeamManifest string
	SLAFile      string
	Format       string
	OutPath      string
	Severity     string
	Team         string
	Title        string
}

// NewCmd constructs the plan command.
func NewCmd() *cobra.Command {
	opts := &options{
		Format:   "markdown",
		Severity: "medium",
		Title:    "Remediation Plan",
	}

	cmd := &cobra.Command{
		Use:   "plan",
		Short: "Generate team-routed remediation plans",
		Long: `Group assessment findings by team ownership and produce
remediation plans with SLA deadlines, remediation commands,
and compliance citations.

Outputs one document per team or a combined document.

Inputs:
  --assessment PATH      stave apply JSON output (required)
  --team-manifest PATH   team manifest YAML (required)
  --sla-profile-file PATH SLA policy for deadline display
  --format STRING        markdown (default) | json | text
  --out PATH             file or directory for output
  --severity STRING      minimum severity: critical|high|medium|low
  --team STRING          specific team only

Exit Codes:
  0   Plan generated
  2   Invalid input`,
		Example: `  # One file per team
  stave plan --assessment findings.json \
    --team-manifest teams.yaml --out ./plans/

  # Combined markdown
  stave plan --assessment findings.json \
    --team-manifest teams.yaml --out plan.md

  # JSON for ticketing automation
  stave plan --assessment findings.json \
    --team-manifest teams.yaml --format json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPlan(cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.Assessment, "assessment", "", "stave apply JSON output (required)")
	cmd.Flags().StringVar(&opts.TeamManifest, "team-manifest", "", "team manifest YAML (required)")
	cmd.Flags().StringVar(&opts.SLAFile, "sla-profile-file", "", "SLA policy file")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "markdown", "output format: markdown | json | text")
	cmd.Flags().StringVar(&opts.OutPath, "out", "", "output file or directory")
	cmd.Flags().StringVar(&opts.Severity, "severity", "medium", "minimum severity to include")
	cmd.Flags().StringVar(&opts.Team, "team", "", "specific team only")
	cmd.Flags().StringVar(&opts.Title, "title", "Remediation Plan", "document title prefix")

	_ = cmd.MarkFlagRequired("assessment")
	_ = cmd.MarkFlagRequired("team-manifest")

	return cmd
}

func runPlan(stdout io.Writer, opts *options) error {
	// Load assessment.
	data, err := fsutil.ReadFileLimited(opts.Assessment)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("read assessment: %w", err)}
	}
	var assessment struct {
		Findings []remediation.Finding `json:"findings"`
	}
	if unmarshalErr := json.Unmarshal(data, &assessment); unmarshalErr != nil {
		return &ui.UserError{Err: fmt.Errorf("parse assessment: %w", unmarshalErr)}
	}

	// Load manifest.
	manifest, err := teams.LoadManifest(opts.TeamManifest)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("load manifest: %w", err)}
	}

	slaProfile := ""
	if opts.SLAFile != "" {
		slaProfile = filepath.Base(opts.SLAFile)
	}

	p := plan.Group(plan.GroupInput{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Assessment:  opts.Assessment,
		SLAProfile:  slaProfile,
		Findings:    assessment.Findings,
		Manifest:    manifest,
		MinSeverity: opts.Severity,
		TeamFilter:  opts.Team,
	})

	// Determine output mode.
	if opts.OutPath != "" {
		fi, statErr := os.Stat(opts.OutPath)
		if statErr == nil && fi.IsDir() {
			return writePerTeam(opts.OutPath, p, opts.Format)
		}
		f, createErr := os.Create(opts.OutPath)
		if createErr != nil {
			return fmt.Errorf("create output: %w", createErr)
		}
		defer f.Close()
		return writeFormat(f, p, opts.Format)
	}

	return writeFormat(stdout, p, opts.Format)
}

func writeFormat(w io.Writer, p *plan.Plan, format string) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(p)
	case "text":
		plan.WriteText(w, p)
		return nil
	case "csv":
		return plan.WriteCSV(w, p)
	default:
		plan.WriteMarkdown(w, p)
		return nil
	}
}

func writePerTeam(dir string, p *plan.Plan, format string) error {
	var ext string
	switch format {
	case "json":
		ext = ".json"
	case "text":
		ext = ".txt"
	default:
		ext = ".md"
	}

	for i := range p.Teams {
		tp := &p.Teams[i]
		filename := strings.ReplaceAll(tp.TeamID, " ", "-") + "-remediation-plan" + ext
		path := filepath.Join(dir, filename)
		f, err := os.Create(path) //nolint:gosec // user-specified output directory
		if err != nil {
			return fmt.Errorf("create %s: %w", path, err)
		}
		single := &plan.Plan{
			GeneratedAt: p.GeneratedAt,
			Assessment:  p.Assessment,
			SLAProfile:  p.SLAProfile,
			Teams:       []plan.TeamPlan{*tp},
		}
		writeErr := writeFormat(f, single, format)
		_ = f.Close()
		if writeErr != nil {
			return writeErr
		}
	}
	return nil
}
