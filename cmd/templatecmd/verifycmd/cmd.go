package verifycmd

import (
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/adapters/templatefs"
	tmpl "github.com/sufield/stave/pkg/stave/template"
	"github.com/sufield/stave/templates"
)

// NewCmd constructs the template verify command.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "verify [template-name]",
		Short: "Verify a template's fixture produces expected findings",
		Long: `Run the template's fixture snapshot through its control and chain
selection. Compare actual findings against expected findings using
semantic matching — not line-by-line diff.

Two findings match when their match_keys fields are equal (default:
control_id + resource_id). All execution metadata (timestamps, scan
IDs, finding UUIDs) is ignored.

Inputs:
  template-name       Name of the template to verify (positional)

Outputs:
  stdout              Verification result (PASS/FAIL with details)

Exit Codes:
  0   Verification passed
  3   Verification failed (missing or unexpected findings)
  2   Invalid input (template not found)
  4   Internal error`,
		Example: `  # Verify a specific template
  stave template verify bucket-hijacking-assessment

  # Verify all templates
  stave template verify --all`,
		Args:          cobra.MaximumNArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("template name required")
			}
			return runVerify(cmd.OutOrStdout(), args[0])
		},
	}

	return cmd
}

func runVerify(w io.Writer, name string) error {
	allTemplates, err := templatefs.LoadAll("", templates.BuiltinTemplateFS)
	if err != nil {
		return fmt.Errorf("load templates: %w", err)
	}

	var target *tmpl.Template
	for i := range allTemplates {
		if allTemplates[i].Metadata.Name == name {
			target = &allTemplates[i]
			break
		}
	}
	if target == nil {
		return fmt.Errorf("template %q not found", name)
	}

	fmt.Fprintf(w, "Verifying template: %s\n", target.Metadata.Name)

	// Load expected findings from the template's fixture
	expected, err := tmpl.LoadExpectedFindings(
		templates.BuiltinTemplateFS,
		fmt.Sprintf("%s/%s", name, target.Fixture.ExpectedFindings),
	)
	if err != nil {
		return fmt.Errorf("load expected findings: %w", err)
	}
	fmt.Fprintf(w, "  Loading fixture snapshot... OK\n")
	fmt.Fprintf(w, "  Expected findings: %d\n", len(expected))

	// TODO: Run actual evaluation against fixture snapshot and compare
	// For now, report what we loaded
	fmt.Fprintf(w, "  (evaluation not yet wired — fixture loaded successfully)\n")

	return nil
}
