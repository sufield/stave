// Package export translates Stave controls to external policy formats.
package export

import (
	"context"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
)

type options struct {
	ControlsDir string
	Format      string
	Package     string
}

// NewCmd creates the export command.
func NewCmd(newCtlRepo compose.CtlRepoFactory) *cobra.Command {
	opts := options{
		ControlsDir: "controls",
		Format:      "rego",
		Package:     "stave",
	}

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export controls to external policy formats",
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
  # Export all S3 controls
  stave export --format rego --controls controls/s3

  # Export with custom package name
  stave export --format rego --controls controls/ --package myorg.stave

  # Use with conftest
  stave export --format rego --controls controls/ > policy/stave.rego
  conftest test terraform.json --policy policy/`,
		Example: `  stave export --format rego --controls controls/s3
  stave export --format rego --controls controls/ --package myorg.stave`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runExport(cmd.Context(), newCtlRepo, &opts, cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", opts.ControlsDir, "Path to control definitions directory")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", opts.Format, "Output format (rego)")
	cmd.Flags().StringVar(&opts.Package, "package", opts.Package, "Rego package name")

	return cmd
}

func runExport(ctx context.Context, newCtlRepo compose.CtlRepoFactory, opts *options, w io.Writer) error {
	if opts.Format != "rego" {
		return fmt.Errorf("unsupported export format: %q (supported: rego)", opts.Format)
	}

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
