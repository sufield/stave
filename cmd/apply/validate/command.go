package validate

import (
	"github.com/spf13/cobra"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
)

// NewCmd builds the validate command.
func NewCmd(rt *ui.Runtime) *cobra.Command {
	if rt == nil {
		rt = ui.DefaultRuntime()
	}
	opts := defaultOptions()

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate inputs without evaluation",
		Long: `Validate checks controls, observations, and configuration for correctness
without running the full evaluation. Use this to verify inputs before evaluation.

Purpose: Verify inputs are sound before running apply
(intent evaluation preflight stage).

Inputs:
  --controls    Directory containing YAML control definitions (ctrl.v1)
  --observations  Directory containing JSON observation snapshots (obs.v0.1)
  --max-unsafe    Duration value to validate format

Outputs:
  stdout          Validation report (text or JSON with --format json)
  stderr          Error messages (if any)

What it checks:
  - Control schema and required fields (id, name, description)
  - Observation schema and timestamps
  - Cross-file consistency (predicates reference valid properties)
  - Time sanity (snapshots sorted, no duplicates)
  - Duration feasibility (snapshot span vs max-unsafe)

Exit Codes:
  0   - All inputs valid, ready for evaluation
  2   - Validation failed (errors or warnings found)
  130 - Interrupted (SIGINT)

Examples:
  # Basic validation
  stave validate --controls ./controls --observations ./obs

  # Treat warnings as errors (CI mode)
  stave validate --controls ./controls --observations ./obs --strict

  # Troubleshooting with remediation hints
  stave validate --controls ./controls --observations ./obs --fix-hints

  # JSON output for scripting
  stave validate --controls ./controls --observations ./obs --format json

  # Validate a single file (--in uses content detection:
  # JSON object/array => observation, everything else => control YAML)
  stave validate --in snapshot.json

  # Validate a file against the canonical control contract schema
  stave validate --in ./control.yaml --kind control --schema-version v1 --strict

  # Validate from stdin
  cat control.yaml | stave validate --in -` + metadata.OfflineHelpSuffix,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runValidateWithOptions(cmd, rt, opts)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.BindFlags(cmd)
	return cmd
}
