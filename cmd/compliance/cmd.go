// Package compliance implements `stave compliance` — evaluate a configuration
// snapshot against a compliance framework (e.g. CSA AICM v1.1) by running the
// Stave controls mapped to each framework control, and report three
// actionable lists: covered (PASS/FAIL), gaps (in scope, no control yet), and
// out of scope (organizational/runtime/physical).
package compliance

import (
	"errors"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/compliancemapping"
)

var errSnapshotRequired = errors.New("--snapshot is required (path to an observation snapshot directory, or - for stdin)")

// NewCmd constructs the `stave compliance` command.
func NewCmd() *cobra.Command {
	opts := &options{}
	cmd := &cobra.Command{
		Use:   "compliance",
		Short: "Evaluate a snapshot against a compliance framework and report coverage",
		Long: `Evaluate a configuration snapshot against a compliance framework.

For each framework control, Stave runs the mapped Stave controls against the
snapshot and reports one of three actionable lists:

  COVERED      framework control has Stave verification — PASS or FAIL
  GAPS         in scope, but no Stave control exists yet (build one)
  OUT OF SCOPE organizational / runtime / physical — a different team's job

A coverage percentage (verified ÷ in-scope) makes progress visible: add a
control, re-run, watch it climb.

Inputs:
  --framework   compliance framework to evaluate (default: aicm-v1.1)
  --snapshot    observation snapshot directory, or - for stdin
  --controls    control directory (default: built-in catalog)
  --format      text | json | markdown (default: text)
  --now         override current time (RFC3339) for deterministic output

Outputs:
  stdout        the three-list report in the chosen format
  exit code     0 = no failures, 3 = a covered control failed,
                2 = input error, 4 = internal error

Examples:
  stave compliance --framework aicm-v1.1 --snapshot ./my-config/
  stave compliance --snapshot ./snap --format json > coverage.json
  stave compliance --snapshot ./snap --format markdown > COMPLIANCE.md`,
		Example: `  # Coverage report against the default framework
  stave compliance --snapshot ./my-config/

  # Machine-readable output for an auditor
  stave compliance --framework aicm-v1.1 --snapshot ./snap --format json > coverage.json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return opts.Prepare(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd, opts)
		},
	}

	f := cmd.Flags()
	f.StringVar(&opts.framework, "framework", "aicm-v1.1", "compliance framework: "+compliancemapping.SupportedFrameworks())
	f.StringVar(&opts.snapshot, "snapshot", "", "observation snapshot directory (or - for stdin)")
	f.StringVarP(&opts.controls, "controls", "i", "controls", "control definitions directory (default: built-in catalog)")
	f.StringVarP(&opts.format, "format", "f", "text", "output format: text, json, markdown")
	f.StringVar(&opts.now, "now", "", "override current time (RFC3339) for deterministic output")

	return cmd
}
