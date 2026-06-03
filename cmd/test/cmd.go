// Package test implements the 'stave test' command for running
// embedded control test cases.
package test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/pkg/stave"
)

type options struct {
	ControlPath string
	ControlsDir string
	Format      string
	FailFast    bool
	Filter      string
	Verbose     bool
}

// NewCmd constructs the test command.
func NewCmd() *cobra.Command {
	opts := &options{Format: "table"}

	cmd := &cobra.Command{
		Use:   "test",
		Short: "Run embedded control test cases",
		Long: `Run test cases embedded in control YAML files. Each control can
define a tests: block with inline test assets and expected verdicts.

The test runner uses the exact same CEL evaluation path as stave apply
— same property normalization, same isMissing behavior.

Verdicts: PASS, VIOLATION, INCONCLUSIVE

Inputs:
  --control PATH    Test a single control YAML file
  --controls PATH   Test all controls in a directory (default: controls)
  --format STRING   Output format: table (default) | json | tap
  --fail-fast       Stop on first failure
  --filter STRING   Run only tests matching pattern (e.g. CTL.S3.*)
  --verbose         Show passing tests (default: failures only)

Exit Codes:
  0   All tests passed
  2   Invalid input
  3   One or more tests failed`,
		Example: `  # Test all controls
  stave test --controls ./controls

  # Test a single control
  stave test --control controls/s3/access/CTL.S3.PUBLIC.001.yaml

  # TAP output for CI
  stave test --controls ./controls --format tap

  # Filter to S3 controls only
  stave test --controls ./controls --filter "CTL.S3.*"`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runTest(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.ControlPath, "control", "", "test a single control YAML file")
	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "", "test all controls in directory")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "table", "output format: table | json | tap")
	cmd.Flags().BoolVar(&opts.FailFast, "fail-fast", false, "stop on first failure")
	cmd.Flags().StringVar(&opts.Filter, "filter", "", "run only controls matching pattern")
	cmd.Flags().BoolVarP(&opts.Verbose, "verbose", "v", false, "show passing tests")

	return cmd
}

func runTest(ctx context.Context, stdout io.Writer, opts *options) error {
	if opts.ControlPath == "" && opts.ControlsDir == "" {
		opts.ControlsDir = "controls"
	}

	results, summary, runErr := stave.RunControlTests(ctx, stave.TestConfig{
		ControlsDir: opts.ControlsDir,
		ControlPath: opts.ControlPath,
		Filter:      opts.Filter,
		FailFast:    opts.FailFast,
	})
	// runErr is non-nil for any failure, including
	// stave.ErrFailingTests (the expected "tests ran, some failed"
	// signal). Renderers always print results + summary even on
	// runErr so the operator sees the failing cases; the error
	// propagates after for the exit-code shim to act on.
	if results == nil && runErr != nil {
		// Load / evaluator-init failure — no results to render.
		return fmt.Errorf("run control tests: %w", runErr)
	}

	renderer, rendErr := NewRenderer(opts.Format, opts.Verbose)
	if rendErr != nil {
		return rendErr
	}
	if err := renderer.Render(stdout, results, summary); err != nil {
		return fmt.Errorf("render test results: %w", err)
	}
	if runErr != nil {
		return fmt.Errorf("control tests: %w", runErr)
	}
	return nil
}

func writeTable(w io.Writer, results []stave.TestResult, summary stave.TestSummary, verbose bool) error {
	fmt.Fprintf(w, "STAVE CONTROL TEST\n")
	fmt.Fprintf(w, "Controls with tests: %d  (%d test cases)\n\n", summary.ControlsTested, summary.TotalCases)

	if summary.TotalCases == 0 {
		fmt.Fprintln(w, "No test cases found. Add tests: block to control YAML files.")
		return nil
	}

	// Show failures.
	failures := 0
	for i := range results {
		r := &results[i]
		for j := range r.Cases {
			c := &r.Cases[j]
			if !c.IsPassing() {
				if failures == 0 {
					fmt.Fprintf(w, "FAILURES\n%s\n\n", strings.Repeat("-", 60))
				}
				failures++
				fmt.Fprintf(w, "%s\n", r.ControlID)
				fmt.Fprintf(w, "  FAIL: %q\n", c.Name)
				fmt.Fprintf(w, "    Expected: %s\n", c.ExpectedVerdict)
				fmt.Fprintf(w, "    Got:      %s\n", c.ActualVerdict)
				if c.Diagnosis != "" {
					fmt.Fprintf(w, "    Diagnosis: %s\n", c.Diagnosis)
				}
				if c.Hint != "" {
					fmt.Fprintf(w, "    Hint: %s\n", c.Hint)
				}
				fmt.Fprintln(w)
			} else if verbose {
				fmt.Fprintf(w, "  ok  %s :: %s\n", r.ControlID, c.Name)
			}
		}
	}

	fmt.Fprintf(w, "RESULTS\n")
	fmt.Fprintf(w, "  Total:   %d test cases across %d controls\n", summary.TotalCases, summary.ControlsTested)
	fmt.Fprintf(w, "  Passed:  %d\n", summary.Passed)
	fmt.Fprintf(w, "  Failed:  %d\n", summary.Failed)

	if summary.Failed == 0 && summary.TotalCases > 0 {
		fmt.Fprintf(w, "\nAll %d tests passed.\n", summary.TotalCases)
	}
	return nil
}

func writeJSON(w io.Writer, results []stave.TestResult, summary stave.TestSummary) error {
	output := struct {
		Summary  stave.TestSummary      `json:"summary"`
		Failures []stave.TestCaseResult `json:"failures,omitempty"`
	}{
		Summary: summary,
	}
	for i := range results {
		for j := range results[i].Cases {
			if !results[i].Cases[j].IsPassing() {
				output.Failures = append(output.Failures, results[i].Cases[j])
			}
		}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}

func writeTAP(w io.Writer, results []stave.TestResult, summary stave.TestSummary) error {
	fmt.Fprintf(w, "TAP version 14\n1..%d\n", summary.TotalCases)
	n := 0
	for i := range results {
		r := &results[i]
		for j := range r.Cases {
			n++
			c := &r.Cases[j]
			if c.IsPassing() {
				fmt.Fprintf(w, "ok %d - %s :: %s\n", n, r.ControlID, c.Name)
			} else {
				fmt.Fprintf(w, "not ok %d - %s :: %s\n", n, r.ControlID, c.Name)
				fmt.Fprintf(w, "  ---\n")
				fmt.Fprintf(w, "  expected: %s\n", c.ExpectedVerdict)
				fmt.Fprintf(w, "  got: %s\n", c.ActualVerdict)
				if c.Hint != "" {
					fmt.Fprintf(w, "  hint: %s\n", c.Hint)
				}
				fmt.Fprintf(w, "  ...\n")
			}
		}
	}
	return nil
}
