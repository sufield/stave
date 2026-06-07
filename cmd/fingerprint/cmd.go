package fingerprint

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

type options struct {
	ControlsDir string
	Format      string
}

// NewCmd constructs the fingerprint command tree.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "fingerprint",
		Short: "Policy fingerprint diagnostics",
		Long:  "Inspect and diagnose the policy fingerprint that certifies reproducibility.",
		Args:  cobra.NoArgs,
	}
	cmd.AddCommand(newExplainCmd())
	return cmd
}

func newExplainCmd() *cobra.Command {
	opts := &options{}
	cmd := &cobra.Command{
		Use:   "explain",
		Short: "Show the policy fingerprint preimage and diagnosis",
		Long: `Print the exact bytes that feed the policy fingerprint SHA256,
plus diagnostic flags for each component. Use this to verify
that the fingerprint certifies what you expect.

Text mode (default): prints the preimage lines verbatim, then
the sha256 fingerprint.

JSON mode: machine-readable with diagnosis flags:
  eval_version_present  — is the engine version in the hashed bytes?
  asset_types_hashed    — per control, did scope contribute to the hash?

Exit codes:
  0   success
  2   input error (bad flag, missing controls directory)
  4   internal error (control load failure)`,
		Example: `  stave fingerprint explain
  stave fingerprint explain --controls ./my-controls --format json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runExplain(cmd.Context(), cmd.OutOrStdout(), opts)
		},
	}
	cmd.Flags().StringVarP(&opts.ControlsDir, cliflags.FlagControls, cliflags.FlagControlsShort, "", "control definitions directory (empty = built-in catalog)")
	cmd.Flags().StringVarP(&opts.Format, cliflags.FlagFormat, "f", "text", "output format: text | json")
	return cmd
}

func runExplain(ctx context.Context, w io.Writer, opts *options) error {
	result, err := stave.FingerprintExplain(ctx, stave.Config{
		ControlsDir: opts.ControlsDir,
	})
	if err != nil {
		return fmt.Errorf("fingerprint explain: %w", err)
	}

	r, rerr := NewRenderer(opts.Format)
	if rerr != nil {
		return &ui.UserError{Err: rerr}
	}
	if err := r.Render(w, result); err != nil {
		return fmt.Errorf("render output: %w", err)
	}
	return nil
}
