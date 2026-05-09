// Package exportinvariants implements the `stave export-invariants`
// command. The command projects Stave's control catalog as a list
// of solver-ready invariants — each carrying the predicate tree,
// authored intent rationale, and the optional forbidden_state
// block external Z3 / SMT compilers consume.
//
// The output format is a stable JSON document. The same controls
// produce byte-identical output across runs, so downstream
// compilers (e.g. examples/z3-forbidden-state/compile.py) can be
// pinned with goldens.
package exportinvariants

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

type options struct {
	ControlsDir string
	Format      string
}

// NewCmd constructs the export-invariants command. The command
// reads the control catalog (built-in by default, YAML directory
// when --controls is set) and writes the invariant export to
// stdout.
func NewCmd() *cobra.Command {
	opts := &options{}

	cmd := &cobra.Command{
		Use:   "export-invariants",
		Short: "Export control catalog as solver-ready invariants",
		Long: `Export the control catalog as a list of solver-ready invariants.

Each invariant carries the control's predicate tree, authored intent
rationale, and the optional forbidden_state block — the high-level
"this configuration must never exist" claim external SMT compilers
consume to generate Z3 satisfiability queries.

The export is metadata-only: no observation reads, no findings, no
clock. External solvers receive a pure description of "the rules
Stave checks" without inheriting any of Stave's evaluation
semantics.

Inputs:
  --controls, -i      Control definitions directory (default: built-in catalog)
  --format, -f        Output format: json (default: json)

Outputs:
  stdout: invariant export as a JSON array (sorted by control ID).
  stderr: errors.

Exit codes:
  0   success
  2   input error (bad flag)
  4   internal error (load failure, projection error)
  130 SIGINT
`,
		Example: `  # Built-in catalog → JSON to stdout
  stave export-invariants > invariants.json

  # Filter to controls that author a forbidden_state block
  stave export-invariants | jq '[.invariants[] | select(.forbidden_state.combine != "")]'

  # Custom controls directory
  stave export-invariants --controls ./my-controls > invariants.json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}

	flags := cmd.Flags()
	flags.StringVarP(&opts.ControlsDir, cliflags.FlagControls, cliflags.FlagControlsShort, "", "control definitions directory (empty = built-in catalog)")
	flags.StringVarP(&opts.Format, cliflags.FlagFormat, "f", "json", "output format: json")

	return cmd
}

// run is the testable command body. UserError wraps input
// problems (mapped to exit code 2 by ui.ExitCode); plain errors
// fall through to exit code 4.
func run(ctx context.Context, w io.Writer, opts *options) error {
	format := strings.ToLower(strings.TrimSpace(opts.Format))
	switch format {
	case "", "json":
		// supported
	default:
		return &ui.UserError{Err: fmt.Errorf("--format must be json (got %q)", opts.Format)}
	}

	out, err := stave.ExportInvariants(ctx, stave.InvariantExportConfig{
		ControlsDir: opts.ControlsDir,
	})
	if err != nil {
		return fmt.Errorf("export invariants: %w", err)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("encode invariants: %w", err)
	}
	return nil
}
