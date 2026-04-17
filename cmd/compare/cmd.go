// Package compare implements the 'stave compare' command for
// compliance posture gap analysis between two frameworks.
package compare

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

	artifact "github.com/sufield/stave/internal/adapters/artifacts"
	appcompare "github.com/sufield/stave/internal/app/compare"
	"github.com/sufield/stave/internal/app/remediationimpact"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type options struct {
	From       string
	To         string
	Assessment string
	Format     string
	OutFile    string
	Mode       string
	Before     string
	After      string
	Simulated  string
}

// NewCmd constructs the compare command.
func NewCmd() *cobra.Command {
	opts := &options{Format: "table"}

	cmd := &cobra.Command{
		Use:   "compare",
		Short: "Compare compliance posture between two frameworks",
		Long: `Analyze the gap between a baseline framework (e.g. HIPAA) and a
target framework (e.g. FedRAMP Moderate). Identifies shared
violations (fix once, satisfy both), marginal work (target-only),
and free coverage (already passing).

Answers: "What is the marginal cost to adopt framework B given
we already comply with framework A?"

Inputs:
  --from STRING       Baseline framework key (required)
  --to STRING         Target framework key (required)
  --assessment PATH   stave apply JSON output (required)
  --format STRING     table (default) | json | markdown

Framework keys: hipaa, nist_800_53_r5, fedramp_moderate,
  soc2, pci_dss_v4.0, cis_aws_v3.0, gdpr, iso_27001_2022

Exit Codes:
  0   Gap analysis produced
  2   Invalid input`,
		Example: `  stave compare --from hipaa --to fedramp_moderate \
    --assessment findings.json

  stave compare --from hipaa --to soc2 \
    --assessment findings.json --format markdown`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCompare(cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.From, "from", "", "baseline framework key (required)")
	cmd.Flags().StringVar(&opts.To, "to", "", "target framework key (required)")
	cmd.Flags().StringVar(&opts.Assessment, "assessment", "", "stave apply JSON output (required)")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "table", "output format: table | json | markdown")
	cmd.Flags().StringVar(&opts.OutFile, "out", "", "write to file")
	cmd.Flags().StringVar(&opts.Mode, "mode", "", "Comparison mode: remediation")
	cmd.Flags().StringVar(&opts.Before, "before", "", "Before assessment path (--mode remediation)")
	cmd.Flags().StringVar(&opts.After, "after", "", "After assessment path (--mode remediation)")
	cmd.Flags().StringVar(&opts.Simulated, "simulated", "", "Simulated output for efficiency comparison")

	return cmd
}

func runCompare(stdout io.Writer, opts *options) error {
	// Remediation impact mode.
	if opts.Mode == "remediation" {
		return runRemediationImpact(stdout, opts)
	}

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

	result := appcompare.Analyze(appcompare.Input{
		GeneratedAt:  time.Now().UTC().Format(time.RFC3339),
		BaselineName: opts.From,
		TargetName:   opts.To,
		BaselineKey:  opts.From,
		TargetKey:    opts.To,
		Findings:     assessment.Findings,
	})

	w := stdout
	if opts.OutFile != "" {
		f, fErr := os.Create(opts.OutFile)
		if fErr != nil {
			return fmt.Errorf("create output: %w", fErr)
		}
		defer f.Close()
		w = f
	}

	switch opts.Format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	case "markdown":
		appcompare.WriteMarkdown(w, result)
	default:
		appcompare.WriteTable(w, result)
	}
	return nil
}

func runRemediationImpact(stdout io.Writer, opts *options) error {
	if opts.Before == "" || opts.After == "" {
		return &ui.UserError{Err: errors.New("--before and --after are required for remediation mode")}
	}

	loader := artifact.NewLoader()

	before, err := loader.Evaluation(context.Background(), opts.Before)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("load before assessment: %w", err)}
	}

	after, err := loader.Evaluation(context.Background(), opts.After)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("load after assessment: %w", err)}
	}

	result := remediationimpact.Analyze(remediationimpact.Input{
		Before: before,
		After:  after,
	})

	w := stdout
	if opts.OutFile != "" {
		f, fErr := os.Create(opts.OutFile)
		if fErr != nil {
			return fmt.Errorf("create output: %w", fErr)
		}
		defer f.Close()
		w = f
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}
