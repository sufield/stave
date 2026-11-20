package initcmd

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	tmpl "github.com/sufield/stave/pkg/stave/template"
)

type options struct {
	Params []string
	Output string
}

// NewCmd constructs the template init command.
func NewCmd() *cobra.Command {
	opts := &options{}

	cmd := &cobra.Command{
		Use:   "init [template-name]",
		Short: "Instantiate a template with parameters",
		Long: `Instantiate a template by resolving parameters. In non-interactive
mode (when --param flags are provided), all required parameters must
be supplied via flags.

Inputs:
  template-name       Name of the template to instantiate (positional)
  --param KEY=VALUE   Parameter value (repeatable)
  --output PATH       Output path for values file (default: ./stave-values.yaml)

Outputs:
  stave-values.yaml   Instantiated values file

Exit Codes:
  0   Values file written
  2   Invalid input or missing required parameter
  4   Internal error`,
		Example: `  # Non-interactive with explicit params
  stave template init bucket-hijacking-assessment \
    --param target_accounts=123456789012,987654321098 \
    --param regions=us-east-1 \
    --output ./stave-values.yaml`,
		Args:          cobra.ExactArgs(1),
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runInit(cmd.OutOrStdout(), args[0], opts)
		},
	}

	cmd.Flags().StringArrayVar(&opts.Params, "param", nil, "parameter value as KEY=VALUE (repeatable)")
	cmd.Flags().StringVar(&opts.Output, "output", "./stave-values.yaml", "output path for values file")

	return cmd
}

func runInit(w io.Writer, name string, opts *options) error {
	allTemplates, err := tmpl.LoadAll("", tmpl.BuiltinFS())
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

	paramMap, err := resolveParams(opts.Params, target.Parameters)
	if err != nil {
		return err
	}

	// Build values file
	values := map[string]any{
		"template":   target.Metadata.Name,
		"version":    target.Metadata.Version,
		"parameters": paramMap,
		"overrides":  map[string]any{},
	}

	data, err := yaml.Marshal(values)
	if err != nil {
		return fmt.Errorf("marshal values: %w", err)
	}

	if err := os.WriteFile(opts.Output, data, 0o600); err != nil {
		return fmt.Errorf("write values file: %w", err)
	}

	fmt.Fprintf(w, "Template: %s v%s\n", target.Metadata.Name, target.Metadata.Version)
	fmt.Fprintf(w, "Job: %s\n", target.Metadata.Job)
	fmt.Fprintf(w, "\nWritten: %s\n", opts.Output)
	fmt.Fprintf(w, "To run: stave apply --values %s --snapshot ./observations\n", opts.Output)

	return nil
}

func resolveParams(raw []string, defs []tmpl.Parameter) (map[string]any, error) {
	paramMap := make(map[string]any, len(raw))
	for _, p := range raw {
		k, v, ok := strings.Cut(p, "=")
		if !ok {
			return nil, fmt.Errorf("invalid --param %q: must be KEY=VALUE", p)
		}
		for _, param := range defs {
			if param.Name == k && param.Type == "list" {
				paramMap[k] = strings.Split(v, ",")
				goto next
			}
		}
		paramMap[k] = v
	next:
	}

	if err := validateParamOptions(paramMap, defs); err != nil {
		return nil, err
	}

	for _, p := range defs {
		if p.Required {
			if _, ok := paramMap[p.Name]; !ok {
				return nil, fmt.Errorf("required parameter %q not provided (use --param %s=VALUE)", p.Name, p.Name)
			}
		}
	}

	for _, p := range defs {
		if _, ok := paramMap[p.Name]; !ok && p.Default != nil {
			paramMap[p.Name] = p.Default
		}
	}
	return paramMap, nil
}

func validateParamOptions(paramMap map[string]any, defs []tmpl.Parameter) error {
	for _, p := range defs {
		val, ok := paramMap[p.Name]
		if !ok || len(p.Options) == 0 {
			continue
		}
		s, isStr := val.(string)
		if !isStr {
			continue
		}
		valid := false
		for _, opt := range p.Options {
			if strings.EqualFold(s, opt) {
				valid = true
				break
			}
		}
		if !valid {
			return fmt.Errorf("invalid value %q for parameter %s\n  Allowed values: %s",
				s, p.Name, strings.Join(p.Options, ", "))
		}
	}
	return nil
}
