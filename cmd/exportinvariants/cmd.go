// Package exportinvariants implements the `stave export-controls`
// command. The command projects Stave's control catalog as a JSON document —
// each entry carries the predicate tree, authored intent rationale,
// and the optional forbidden_state block external Z3 / SMT
// compilers consume.
//
// The output format is a stable JSON document; the top-level array
// is keyed `invariants` as the solver-side data contract (separate
// from Stave's user-facing "control" vocabulary). The same controls
// produce byte-identical output across runs, so downstream
// compilers (e.g. examples/z3-forbidden-state/compile.py) can be
// pinned with goldens. The Go package keeps its historical name to
// preserve import paths.
package exportinvariants

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/pkg/stave"
)

type options struct {
	ControlsDir string
	Format      string
}

// NewCmd constructs the export-controls command. The command
// reads the control catalog (built-in by default, YAML directory
// when --controls is set) and writes the export to stdout.
func NewCmd() *cobra.Command {
	opts := &options{}

	cmd := &cobra.Command{
		Use:   "export-controls",
		Short: "Export the control catalog for external solver consumption",
		Long: `Export the control catalog as a JSON document — each entry carries the
control's predicate tree, authored intent rationale, and the optional
forbidden_state block (the high-level "this configuration must never
exist" claim external SMT compilers consume to generate Z3
satisfiability queries).

The export is metadata-only: no observation reads, no findings, no
clock. External solvers receive a pure description of "the controls
Stave evaluates" without inheriting any of Stave's evaluation
semantics. The JSON shape itself is the stable solver-import format,
so the top-level array is keyed ` + "`invariants`" + ` — that name is the
solver-side data contract, not Stave's user-facing vocabulary.

Inputs:
  --controls, -i      Control definitions directory (default: built-in catalog)
  --format, -f        Output format: json (default: json)

Outputs:
  stdout: control export as a JSON document (sorted by control ID).
  stderr: errors.

Exit codes:
  0   success
  2   input error (bad flag)
  4   internal error (load failure, projection error)
  130 SIGINT
`,
		Example: `  # Built-in catalog → JSON to stdout
  stave export-controls > controls.json

  # Filter to controls that author a forbidden_state block
  stave export-controls | jq '[.invariants[] | select(.forbidden_state.combine != "")]'

  # Custom controls directory
  stave export-controls --controls ./my-controls > controls.json`,
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

// run is the testable command body. Flag-validation errors wrap
// stave.ErrInvalidInput so ui.ExitCode (via root.go) maps them to
// exit code 2; other errors fall through to exit code 4. Both
// paths are pure pkg/stave consumption — no internal/cli/ui
// import needed to keep the standard exit-code contract.
func run(ctx context.Context, w io.Writer, opts *options) error {
	format := strings.ToLower(strings.TrimSpace(opts.Format))
	switch format {
	case "", "json":
		// supported
	default:
		return fmt.Errorf("--format must be json (got %q): %w", opts.Format, stave.ErrInvalidInput)
	}

	out, err := stave.ExportInvariants(ctx, stave.InvariantExportConfig{
		ControlsDir: opts.ControlsDir,
	})
	if err != nil {
		return fmt.Errorf("export controls: %w", err)
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		return fmt.Errorf("encode controls: %w", err)
	}
	return nil
}
