package export

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
)

type regoOptions struct {
	ControlsDir string
	Package     string
}

func newRegoCmd(newCtlRepo compose.CtlRepoFactory) *cobra.Command {
	opts := regoOptions{
		ControlsDir: "controls",
		Package:     "stave",
	}

	cmd := &cobra.Command{
		Use:   "rego",
		Short: "Export controls to OPA Rego policy rules",
		Long: `Export Stave controls to OPA Rego rules for use with Conftest,
OPA, or other policy engines.

Reads ctrl.v1 YAML controls and translates unsafe_predicate logic
to equivalent Rego deny rules. Controls using predicate aliases
(no inline predicate) are skipped with a comment.

Outputs:
  stdout    Rego policy file

Exit Codes:
  0   Success
  2   Invalid input or no controls found
  4   Internal error

Examples:
  stave export rego --controls controls/s3
  stave export rego --controls controls/ --package myorg.stave`,
		Example: `  stave export rego --controls controls/s3
  stave export rego --controls controls/ --package myorg.stave`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runRego(cmd.Context(), newCtlRepo, &opts, cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", opts.ControlsDir, "Path to control definitions directory")
	cmd.Flags().StringVar(&opts.Package, "package", opts.Package, "Rego package name")

	return cmd
}

func runRego(ctx context.Context, newCtlRepo compose.CtlRepoFactory, opts *regoOptions, w io.Writer) error {
	repo, err := newCtlRepo()
	if err != nil {
		return fmt.Errorf("create control loader: %w", err)
	}

	controls, err := repo.LoadControls(ctx, opts.ControlsDir)
	if err != nil {
		return fmt.Errorf("load controls from %q: %w", opts.ControlsDir, err)
	}

	if len(controls) == 0 {
		return fmt.Errorf("no controls found in %q", opts.ControlsDir)
	}

	output := GenerateRego(controls, opts.Package)
	_, err = fmt.Fprint(w, output)
	return err
}
