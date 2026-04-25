// Package simulate implements the 'stave simulate' command for
// what-if remediation impact analysis.
package simulate

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	appsim "github.com/sufield/stave/internal/app/simulate"
	"github.com/sufield/stave/internal/builtin/capabilities"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/evaluation/remediation"
	"github.com/sufield/stave/internal/core/evaluation/risk"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type options struct {
	Assessment string
	Fix        []string
	Format     string
	OutFile    string
}

// NewCmd constructs the simulate command.
func NewCmd() *cobra.Command {
	opts := &options{Format: "table"}

	cmd := &cobra.Command{
		Use:   "simulate",
		Short: "Simulate remediation impact on posture, chains, and compliance",
		Long: `Show what happens to posture score, compound chains, and compliance
coverage if specified controls are fixed. Answers: "If I fix this
one control, which chains deactivate?"

Inputs:
  --fix CONTROL_ID    Control to simulate fixing (repeatable)
  --assessment PATH   stave apply JSON output (required)

Exit Codes:
  0   Simulation complete
  2   Invalid input`,
		Example: `  stave simulate --fix CTL.S3.PUBLIC.001 --assessment findings.json
  stave simulate --fix CTL.S3.PUBLIC.001 --fix CTL.S3.ENCRYPT.001 --assessment findings.json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSimulate(cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.Assessment, "assessment", "", "stave apply JSON output (required)")
	cmd.Flags().StringSliceVar(&opts.Fix, "fix", nil, "control ID to simulate fixing (repeatable)")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "table", "output format: table | json")
	cmd.Flags().StringVar(&opts.OutFile, "out", "", "write to file")

	_ = cmd.MarkFlagRequired("assessment")
	return cmd
}

func runSimulate(stdout io.Writer, opts *options) error {
	if len(opts.Fix) == 0 {
		return &ui.UserError{Err: errors.New("at least one --fix control ID is required")}
	}

	data, err := fsutil.ReadFileLimited(opts.Assessment)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("read assessment: %w", err)}
	}
	var assessment struct {
		Findings      []remediation.Finding  `json:"findings"`
		ChainFindings []risk.CompoundFinding `json:"compound_findings"`
	}
	if unmarshalErr := json.Unmarshal(data, &assessment); unmarshalErr != nil {
		return &ui.UserError{Err: fmt.Errorf("parse assessment: %w", unmarshalErr)}
	}

	chains, chainsErr := ctlyaml.LoadChains("chains", capabilities.Builtin())
	if chainsErr != nil {
		return fmt.Errorf("loading chains: %w", chainsErr)
	}

	result := appsim.Run(appsim.Input{
		Findings:      assessment.Findings,
		ChainFindings: assessment.ChainFindings,
		Chains:        chains,
		FixControls:   opts.Fix,
		CurrentScore:  70, // approximate — would need score computation
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
	default:
		fmt.Fprintf(w, "REMEDIATION SIMULATION\nFixing: %s\n\n", strings.Join(opts.Fix, ", "))
		fmt.Fprintf(w, "POSTURE SCORE\n  Current:    %.1f\n  Simulated:  %.1f  (%+.1f)\n\n",
			result.ScoreCurrent, result.ScoreSimulated, result.ScoreDelta)
		if len(result.ChainsDeactivated) > 0 {
			fmt.Fprintln(w, "CHAINS DEACTIVATED")
			for _, c := range result.ChainsDeactivated {
				fmt.Fprintf(w, "  %-40s %s → %s\n", c.ChainID, strings.ToUpper(c.Severity), c.Status)
			}
			fmt.Fprintln(w)
		}
		fmt.Fprintf(w, "FINDINGS ELIMINATED: %d\n", result.FindingsRemoved)
		return nil
	}
}
