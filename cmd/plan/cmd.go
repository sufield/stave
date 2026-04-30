// Package plan implements the 'stave plan' command for team-routed
// remediation plan export.
package plan

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/app/compliancepath"
	"github.com/sufield/stave/internal/app/plan"
	"github.com/sufield/stave/internal/app/teams"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/compliance"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type options struct {
	Assessment        string
	TeamManifest      string
	SLAFile           string
	Format            string
	OutPath           string
	Severity          string
	Team              string
	Title             string
	Threshold         float64
	ComplianceProfile string
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
	cmd.Flags().Float64Var(&opts.Threshold, "threshold", 0, "Target readiness percentage for compliance path calculation")
	cmd.Flags().StringVar(&opts.ComplianceProfile, "compliance-profile", "", "Compliance profile for path calculation")

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

	// Compliance path mode: compute minimum-effort path to target readiness.
	if opts.Threshold > 0 && opts.ComplianceProfile != "" {
		// TotalControls must reflect the actual size of the requested
		// framework's control set, not the count of findings. The old
		// `max(len(Findings), 1)` produced absurd readiness scores —
		// 1 finding and a 50-control framework reported as 0%-ready
		// against a 1-control denominator.
		totalControls := len(compliance.ControlRegistry.ByProfile(opts.ComplianceProfile))
		if totalControls == 0 {
			return &ui.UserError{Err: fmt.Errorf("compliance profile %q has no controls in the catalog; check the profile name", opts.ComplianceProfile)}
		}
		result, computeErr := compliancepath.Compute(compliancepath.Input{
			Findings:        assessment.Findings,
			TargetFramework: opts.ComplianceProfile,
			TargetReadiness: opts.Threshold,
			TotalControls:   totalControls,
		})
		if computeErr != nil {
			return &ui.UserError{Err: fmt.Errorf("compute compliance path: %w", computeErr)}
		}

		if opts.OutPath != "" {
			f, fErr := os.Create(opts.OutPath)
			if fErr != nil {
				return fmt.Errorf("create output: %w", fErr)
			}
			enc := json.NewEncoder(f)
			enc.SetIndent("", "  ")
			encErr := enc.Encode(result)
			closeErr := f.Close()
			if encErr != nil {
				return encErr
			}
			// A successful Encode followed by a failing Close is the
			// silent-corruption window: the buffered write may not
			// have reached disk, and the previous `defer f.Close()`
			// dropped that error so callers saw success. Mirror the
			// writePerTeam pattern below — propagate the close error.
			if closeErr != nil {
				return fmt.Errorf("close %s: %w", opts.OutPath, closeErr)
			}
			return nil
		}

		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	}

	// Load manifest.
	manifest, err := teams.LoadManifest(opts.TeamManifest)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("load manifest: %w", err)}
	}

	// Preserve the operator-supplied path verbatim — relative paths
	// stay relative-to-cwd, absolute paths stay absolute. Recording
	// only the basename made the SLA file unlocatable: a downstream
	// consumer reading the plan output had no way to find
	// "production-sla.yaml" if the operator originally supplied
	// "/policies/sla/production-sla.yaml".
	slaProfile := opts.SLAFile

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
		writeErr := writeFormat(f, p, opts.Format)
		closeErr := f.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return fmt.Errorf("close %s: %w", opts.OutPath, closeErr)
		}
		return nil
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
		// TeamID flows from the input plan's manifest. A malicious
		// or buggy upstream could supply "../../etc/passwd" here;
		// filepath.Join would clean the .. and write outside dir.
		// Reject any TeamID containing path-separator-like sequences.
		if err := validateTeamIDForFilename(tp.TeamID); err != nil {
			return fmt.Errorf("team %q: %w", tp.TeamID, err)
		}
		filename := strings.ReplaceAll(tp.TeamID, " ", "-") + "-remediation-plan" + ext
		path := filepath.Join(dir, filename)
		f, err := os.Create(path) //nolint:gosec // user-specified output directory; filename validated above
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
		closeErr := f.Close()
		if writeErr != nil {
			return writeErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

// validateTeamIDForFilename rejects TeamID values that would let an
// attacker control the output path. A TeamID like "../../etc/passwd"
// would survive filepath.Join (which cleans ..) and write outside the
// caller-chosen output directory. We reject any forward slash,
// backslash, "..", or NUL byte; legitimate team IDs are alphanumerics,
// hyphens, underscores, and spaces.
func validateTeamIDForFilename(id string) error {
	if id == "" {
		return errors.New("team_id is empty")
	}
	if strings.ContainsAny(id, `/\`) {
		return errors.New("team_id contains path separators")
	}
	if strings.Contains(id, "..") {
		return errors.New("team_id contains parent-directory traversal")
	}
	if strings.ContainsRune(id, 0) {
		return errors.New("team_id contains NUL byte")
	}
	return nil
}
