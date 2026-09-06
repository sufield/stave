// Package lint implements the lint command.
package lint

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/metadata"
)

const lintLongHelp = `Lint controls, observations, and configuration for correctness without evaluation.

Lint checks structural and semantic correctness of all evaluation inputs
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
  --eval-time                Evaluation reference timestamp (RFC3339) for deterministic output
  --format, -f         Output format: text or json (default: text)
  --strict             Treat warnings as errors (exit 2)
  --fix-hints          Print remediation hints after issues
  --check              Additional checks: collector-contract
  --quiet              Suppress output
  --template           Custom output template

Outputs:
  stdout               Lint report listing issues found (text or JSON)
  stderr               Error messages (if any)

Exit Codes:
  0   - All inputs are valid; no issues found
  2   - Invalid input or lint failure (also used in --strict mode for warnings)
  130 - Interrupted (SIGINT)

Examples:
  # Lint project controls and observations
  stave lint

  # Lint with JSON output
  stave lint --format json

  # Lint a single file from stdin
  cat control.yaml | stave lint --in - --kind control

  # Strict mode: treat warnings as errors
  stave lint --strict` + metadata.OfflineHelpSuffix

// NewCmd builds the lint command.
// Returns nil if rt is nil — the caller (WireCommands) must provide a valid runtime.
func NewCmd(rt *ui.Runtime) *cobra.Command {
	if rt == nil {
		return nil
	}

	opts := newOptions()

	cmd := &cobra.Command{
		Use:     "lint",
		Short:   "Lint inputs without evaluation",
		Long:    lintLongHelp,
		Example: `  stave lint --controls controls/s3 --observations observations`,
		Args:    cobra.NoArgs,
		PreRunE: func(cmd *cobra.Command, _ []string) error {
			return opts.Prepare(cmd)
		},
		RunE: func(cmd *cobra.Command, _ []string) error {
			resolvedFormat, fmtErr := compose.ResolveFormatValue(opts.Format)
			if fmtErr != nil {
				return fmt.Errorf("resolve output format: %w", fmtErr)
			}
			gf := cliflags.GetGlobalFlags(cmd)
			out := compose.ResolveStdout(cmd.OutOrStdout(), gf.Quiet, resolvedFormat)
			return runValidate(compose.CommandContext(cmd), Input{
				Stdin:    cmd.InOrStdin(),
				Out:      out,
				Stderr:   cmd.ErrOrStderr(),
				Format:   string(resolvedFormat),
				Quiet:    gf.Quiet,
				Sanitize: gf.Sanitize,
				Rt:       rt,
				Opts:     opts,
			})
		},
		Annotations:   map[string]string{cmdutil.AnnotationSanitizeAware: "true"},
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	opts.BindFlags(cmd)
	return cmd
}
