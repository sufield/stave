package sla

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	infraSLA "github.com/sufield/stave/internal/adapters/sla"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type simulateOptions struct {
	OutputFile     string
	SLAProfileFile string
	CompareFile    string
}

func newSimulateCmd() *cobra.Command {
	opts := &simulateOptions{}

	cmd := &cobra.Command{
		Use:   "simulate",
		Short: "Show posture score impact of an SLA policy",
		Long: `Show how an SLA policy affects findings from an existing assessment.

Reads a stave apply JSON output and applies SLA deadlines to each
finding, reporting which findings are within SLA, approaching
deadline, or breached.

Inputs:
  --output PATH           Path to stave apply JSON (required)
  --sla-profile-file PATH SLA policy file to simulate (required)
  --compare PATH          Compare against a second SLA policy

Exit Codes:
  0   Simulation complete
  2   Invalid input`,
		Example: `  # Simulate SLA policy against assessment
  stave sla simulate \
    --output findings.json \
    --sla-profile-file hipaa-sla.yaml

  # Compare two policies
  stave sla simulate \
    --output findings.json \
    --sla-profile-file hipaa-sla.yaml \
    --compare strict-sla.yaml`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSimulate(cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.OutputFile, "output", "", "path to stave apply JSON (required)")
	cmd.Flags().StringVar(&opts.SLAProfileFile, "sla-profile-file", "", "SLA policy file to simulate (required)")
	cmd.Flags().StringVar(&opts.CompareFile, "compare", "", "second SLA policy for comparison")

	cliflags.MustMarkRequired(cmd, "output")
	cliflags.MustMarkRequired(cmd, "sla-profile-file")

	return cmd
}

// assessmentFindings is the minimal subset of assessment JSON we need.
type assessmentFindings struct {
	Findings []simFinding `json:"findings"`
	Summary  struct {
		Violations int `json:"violations"`
	} `json:"summary"`
}

type simFinding struct {
	ControlID        string   `json:"control_id"`
	Severity         string   `json:"control_severity"`
	DwellHours       float64  `json:"unsafe_duration_hours"`
	AssetID          string   `json:"asset_id"`
	SLABreached      bool     `json:"sla_breached"`
	SLADeadlineHours *float64 `json:"sla_deadline_hours"`
}

type simResult struct {
	policyName  string
	within      []simEntry
	approaching []simEntry
	breached    []simEntry
}

type simEntry struct {
	controlID     string
	severity      string
	assetID       string
	dwellHours    float64
	deadlineHours float64
	burnRate      float64
}

func runSimulate(stdout io.Writer, opts *simulateOptions) error {
	data, err := fsutil.ReadFileLimited(opts.OutputFile)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("read assessment: %w", err)}
	}
	var assessment assessmentFindings
	if unmarshalErr := json.Unmarshal(data, &assessment); unmarshalErr != nil {
		return &ui.UserError{Err: fmt.Errorf("parse assessment: %w", unmarshalErr)}
	}

	pol, err := infraSLA.LoadFromFile(opts.SLAProfileFile)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("load SLA policy: %w", err)}
	}

	result := simulate(pol, assessment.Findings)
	if writeErr := writeSimResult(stdout, opts.SLAProfileFile, opts.OutputFile, result); writeErr != nil {
		return fmt.Errorf("render simulation: %w", writeErr)
	}

	if opts.CompareFile != "" {
		pol2, err := infraSLA.LoadFromFile(opts.CompareFile)
		if err != nil {
			return &ui.UserError{Err: fmt.Errorf("load compare policy: %w", err)}
		}
		result2 := simulate(pol2, assessment.Findings)
		if _, err := fmt.Fprintln(stdout); err != nil {
			return fmt.Errorf("render simulation: %w", err)
		}
		if writeErr := writeComparison(stdout, result, opts.SLAProfileFile, result2, opts.CompareFile); writeErr != nil {
			return fmt.Errorf("render comparison: %w", writeErr)
		}
	}

	return nil
}

func simulate(pol *infraSLA.Policy, findings []simFinding) simResult {
	res := simResult{policyName: pol.Name}
	for _, f := range findings {
		deadline := pol.DeadlineHoursFor(f.Severity)
		if deadline <= 0 {
			continue
		}
		burn := f.DwellHours / deadline
		entry := simEntry{
			controlID:     f.ControlID,
			severity:      f.Severity,
			assetID:       f.AssetID,
			dwellHours:    f.DwellHours,
			deadlineHours: deadline,
			burnRate:      burn,
		}
		switch ClassifyBurnRate(burn) {
		case BurnRateBreached:
			res.breached = append(res.breached, entry)
		case BurnRateApproaching:
			res.approaching = append(res.approaching, entry)
		default:
			res.within = append(res.within, entry)
		}
	}
	// Sort breached by overdue desc.
	sort.Slice(res.breached, func(i, j int) bool {
		return res.breached[i].burnRate > res.breached[j].burnRate
	})
	sort.Slice(res.approaching, func(i, j int) bool {
		return res.approaching[i].burnRate > res.approaching[j].burnRate
	})
	return res
}

// stickyWriter captures the first I/O error and turns subsequent
// writes into no-ops. The simulation formatters emit a couple dozen
// Fprintf/Fprintln calls; threading errors inline would balloon the
// body and obscure the layout. The sticky pattern keeps the
// formatters readable while still surfacing a real I/O failure
// (closed pipe, full disk) to the caller via Err().
type stickyWriter struct {
	w   io.Writer
	err error
}

func (s *stickyWriter) Write(p []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	n, err := s.w.Write(p)
	if err != nil {
		s.err = err
	}
	return n, err
}

func writeSimResult(w io.Writer, policyPath, assessmentPath string, r simResult) error {
	sw := &stickyWriter{w: w}
	total := len(r.within) + len(r.approaching) + len(r.breached)

	fmt.Fprintln(sw, "SLA POLICY SIMULATION")
	fmt.Fprintf(sw, "Policy:     %s (%s)\n", r.policyName, policyPath)
	fmt.Fprintf(sw, "Assessment: %s\n\n", assessmentPath)

	fmt.Fprintf(sw, "FINDINGS SUMMARY\n")
	fmt.Fprintf(sw, "  %d findings within SLA deadline (on track)\n", len(r.within))
	fmt.Fprintf(sw, "  %d findings approaching deadline (>70%% burn rate)\n", len(r.approaching))
	fmt.Fprintf(sw, "  %d findings past deadline (SLA breached)\n", len(r.breached))
	fmt.Fprintf(sw, "  %d total findings with SLA deadlines\n\n", total)

	if len(r.breached) > 0 {
		fmt.Fprintln(sw, "SLA BREACHED:")
		for _, e := range r.breached {
			overdue := e.dwellHours - e.deadlineHours
			fmt.Fprintf(sw, "  %-30s %-8s dwell: %.0fh  deadline: %.0fh  overdue: %.0fh\n",
				e.controlID, e.severity, e.dwellHours, e.deadlineHours, overdue)
		}
		fmt.Fprintln(sw)
	}

	if len(r.approaching) > 0 {
		fmt.Fprintln(sw, "APPROACHING (>70% burn rate):")
		for _, e := range r.approaching {
			fmt.Fprintf(sw, "  %-30s %-8s dwell: %.0fh  deadline: %.0fh  burn: %.1f%%\n",
				e.controlID, e.severity, e.dwellHours, e.deadlineHours, e.burnRate*100)
		}
		fmt.Fprintln(sw)
	}
	return sw.err
}

func writeComparison(w io.Writer, r1 simResult, _ string, r2 simResult, _ string) error {
	sw := &stickyWriter{w: w}
	total1 := len(r1.within) + len(r1.approaching) + len(r1.breached)
	total2 := len(r2.within) + len(r2.approaching) + len(r2.breached)

	fmt.Fprintln(sw, "POLICY COMPARISON")
	fmt.Fprintf(sw, "  %-20s %-12s %-12s\n", "Metric", r1.policyName, r2.policyName)
	fmt.Fprintf(sw, "  %-20s %-12s %-12s\n", strings.Repeat("-", 20), strings.Repeat("-", 12), strings.Repeat("-", 12))
	fmt.Fprintf(sw, "  %-20s %-12s %-12s\n", "Findings in SLA",
		fmt.Sprintf("%d/%d", len(r1.within), total1),
		fmt.Sprintf("%d/%d", len(r2.within), total2))
	fmt.Fprintf(sw, "  %-20s %-12d %-12d\n", "Approaching", len(r1.approaching), len(r2.approaching))
	fmt.Fprintf(sw, "  %-20s %-12d %-12d\n", "Breached", len(r1.breached), len(r2.breached))
	return sw.err
}
