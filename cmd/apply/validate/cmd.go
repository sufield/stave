// Package validate implements the validate command.
package validate

import (
	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/metadata"
)

const validateLongHelp = `Validate controls, observations, and configuration for correctness without evaluation.

Validate checks structural and semantic correctness of all evaluation inputs
before running the full apply pipeline. It catches schema violations, invalid
timestamps, and cross-file inconsistencies early, reducing time spent debugging
failed evaluations.

What it checks:
  - Control schema (id, name, description)
  - Observation schema and timestamps
  - Cross-file consistency and time sanity
  - Duration format and feasibility

Inputs:
  --controls, -i       Path to control definitions (default: controls)
  --observations, -o   Path to observation snapshots (default: observations)
  --in                 Single input file or '-' for stdin
  --kind               Contract kind: control|observation|finding (requires --in)
  --schema-version     Contract schema version override
  --max-unsafe         Maximum allowed unsafe duration
  --now                Override current time (RFC3339) for deterministic output
  --format, -f         Output format: text or json (default: text)
  --strict             Treat warnings as errors (exit 2)
  --fix-hints          Print remediation hints after issues
  --quiet              Suppress output
  --template           Custom output template

Outputs:
  stdout               Validation report listing issues found (text or JSON)
  stderr               Error messages (if any)

Exit Codes:
  0   - All inputs are valid; no issues found
  2   - Invalid input or validation failure (also used in --strict mode for warnings)
  130 - Interrupted (SIGINT)

Examples:
  # Validate project controls and observations
  stave validate

  # Validate with JSON output
  stave validate --format json

  # Validate a single file from stdin
  cat control.yaml | stave validate --in - --kind control

  # Strict mode: treat warnings as errors
  stave validate --strict` + metadata.OfflineHelpSuffix

// NewCmd builds the validate command.
// Returns nil if rt is nil — the caller (WireCommands) must provide a valid runtime.
func NewCmd(newObsRepo compose.ObsRepoFactory, newCtlRepo compose.CtlRepoFactory, newCELEvaluator compose.CELEvaluatorFactory, rt *ui.Runtime) *cobra.Command {
	if rt == nil {
		return nil
	}

	opts := newOptions()

	cmd := &cobra.Command{
		Use:     "validate",
		Short:   "Validate inputs without evaluation",
		Long:    validateLongHelp,
		Example: `  stave validate --controls controls/s3 --observations observations`,
		Args:    cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return opts.Prepare(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runValidate(cmd, validateDeps{
				NewObsRepo: newObsRepo, NewCtlRepo: newCtlRepo, NewCELEvaluator: newCELEvaluator,
			}, rt, opts)
		},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.BindFlags(cmd)
	return cmd
}
