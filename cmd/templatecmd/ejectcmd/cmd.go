package ejectcmd

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/adapters/templatefs"
	tmpl "github.com/sufield/stave/pkg/stave/template"
	"github.com/sufield/stave/templates"
)

type options struct {
	Output string
}

// NewCmd constructs the template eject command.
func NewCmd() *cobra.Command {
	opts := &options{}

	cmd := &cobra.Command{
		Use:   "eject [template-name]",
		Short: "Fork a template for local customization",
		Long: `Eject a template to a local directory for full customization.
The ejected template is your copy — it will not receive catalog
updates. To return to managed mode, delete the local copy.

Inputs:
  template-name       Name of the template to eject (positional)
  --output DIR        Output directory (default: ./stave-templates/<name>)

Outputs:
  Local template directory with template.yaml and fixtures

Exit Codes:
  0   Template ejected
  2   Invalid input
  4   Internal error`,
		Example: `  # Eject to default location
  stave template eject bucket-hijacking-assessment

  # Eject to custom location
  stave template eject bucket-hijacking-assessment --output ./my-templates/hijack`,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runEject(cmd.OutOrStdout(), args[0], opts)
		},
	}

	cmd.Flags().StringVar(&opts.Output, "output", "", "output directory (default: ./stave-templates/<name>)")

	return cmd
}

func runEject(w io.Writer, name string, opts *options) error {
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

	outDir := opts.Output
	if outDir == "" {
		outDir = filepath.Join(".", "stave-templates", name)
	}

	// Copy the template directory from embedded FS
	err = fs.WalkDir(templates.BuiltinTemplateFS, name, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		rel, _ := filepath.Rel(name, path)
		dest := filepath.Join(outDir, rel)

		if d.IsDir() {
			return os.MkdirAll(dest, 0o750)
		}

		data, err := fs.ReadFile(templates.BuiltinTemplateFS, path)
		if err != nil {
			return fmt.Errorf("read %s: %w", path, err)
		}
		if err := os.WriteFile(dest, data, 0o600); err != nil {
			return fmt.Errorf("write %s: %w", dest, err)
		}
		return nil
	})
	if err != nil {
		return fmt.Errorf("eject template: %w", err)
	}

	fmt.Fprintf(w, "Ejected template to %s/\n", outDir)
	fmt.Fprintln(w, "WARNING: This template is now your copy. It will not receive catalog updates.")
	fmt.Fprintln(w, "To return to managed mode, delete the local copy and re-init.")

	return nil
}
