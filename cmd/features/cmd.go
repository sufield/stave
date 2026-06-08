// Package features implements the `stave features` command: it reports
// what Stave does (discovered live from the build's registries) and what
// it deliberately does not do (read from the versioned features/scope.yaml
// manifest).
package features

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

// NewCmd constructs the `stave features` command.
func NewCmd() *cobra.Command {
	var format string
	var noPager bool

	cmd := &cobra.Command{
		Use:   "features",
		Short: "Show what Stave does and deliberately does not do",
		Long: `Report Stave's capability scope.

IN SCOPE is discovered live from this build's registries (control
catalog, packs, compliance frameworks, observation schemas, ATT&CK
tactics) — it cannot drift from what the binary can actually do. OUT OF
SCOPE is read from the versioned features/scope.yaml manifest, which is
reviewed in PRs: capabilities Stave delegates to upstream collectors or
downstream tools.

Output is paged through $PAGER (then 'less -R', then 'more') when stdout is a
terminal, and written plain and unpaged when piped, redirected, or in CI — so
'... | grep' and '... > file' are unaffected. JSON is never paged. Use
--no-pager to force plain output on a terminal.

Inputs:
  --format, -f   Output format: auto (default; paged on a TTY) | text | wide | json.
  --no-pager     Never page, even on a terminal.

Outputs:
  stdout         The scope report (text table, wide table, or JSON).

Exit codes:
  0  report rendered
  2  invalid flag / unknown format
  4  internal error reading the embedded manifest

Examples:
  stave features
  stave features --format wide
  stave features --format json`,
		Example:       "  stave features\n  stave features --format wide\n  stave features --format json",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			out, err := stave.RenderFeatures(format)
			if err != nil {
				if errors.Is(err, stave.ErrInvalidInput) {
					return &ui.UserError{Err: err}
				}
				return err //nolint:wrapcheck // facade already wrapped ("load scope manifest"); preserve exit 4.
			}

			// Page human output on a TTY; never page JSON, and never when
			// --no-pager is set or stdout is not a terminal. NewPager returns
			// the writer unchanged with a no-op close in the unpaged cases.
			pageable := format != "json" && !noPager
			pw, closePager := ui.NewPager(cmd.Context(), cmd.OutOrStdout(), pageable)
			_, writeErr := pw.Write(out)
			closeErr := closePager()
			if writeErr != nil {
				return fmt.Errorf("write features: %w", writeErr)
			}
			return closeErr //nolint:wrapcheck // already wrapped ("wait for pager: …") by NewPager's closer.
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "auto", "Output format: auto | text | wide | json")
	cmd.Flags().BoolVar(&noPager, "no-pager", false, "never page output, even on a terminal")
	return cmd
}
