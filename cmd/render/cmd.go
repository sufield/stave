package render

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"text/template"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
)

type options struct {
	Data     string
	Template string
}

// NewCmd constructs the `render` command.
func NewCmd() *cobra.Command {
	opts := &options{}
	cmd := &cobra.Command{
		Use:   "render",
		Short: "Render JSON data through a Go text/template",
		Long: `Render pipes JSON data through a Go text/template file and writes
the result to stdout. The data comes from any stave command that
produces --format json output; the template is a file on disk.

This separates data (code owns) from presentation (content owns).
Each changes independently — adding a control changes the JSON,
editing the template changes the output format, neither touches
the other.

Inputs:
  --data FILE       JSON input file (or - for stdin)
  --template FILE   Go text/template file

Exit codes:
  0   Success
  2   Invalid input (missing flags, bad JSON, bad template)
  4   Internal error

Examples:
  stave catalog --kind chain --format json | stave render --data - --template templates/chain-catalog.md.tmpl
  stave render --data catalog.json --template templates/chain-catalog.md.tmpl > docs/chain-catalog.md`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.OutOrStdout(), opts)
		},
	}
	cmd.Flags().StringVar(&opts.Data, "data", "", "JSON input file (- for stdin)")
	cmd.Flags().StringVar(&opts.Template, "template", "", "Go text/template file")
	return cmd
}

func run(w io.Writer, opts *options) error {
	if opts.Data == "" {
		return &ui.UserError{Err: errors.New("--data is required")}
	}
	if opts.Template == "" {
		return &ui.UserError{Err: errors.New("--template is required")}
	}

	var dataReader io.Reader
	if opts.Data == "-" {
		dataReader = os.Stdin
	} else {
		f, err := os.Open(opts.Data)
		if err != nil {
			return &ui.UserError{Err: fmt.Errorf("open data file: %w", err)}
		}
		defer f.Close()
		dataReader = f
	}

	var data any
	if err := json.NewDecoder(dataReader).Decode(&data); err != nil {
		return &ui.UserError{Err: fmt.Errorf("parse JSON: %w", err)}
	}

	tmplBytes, err := os.ReadFile(opts.Template)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("read template: %w", err)}
	}

	tmpl, err := template.New(opts.Template).Parse(string(tmplBytes))
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("parse template: %w", err)}
	}

	if err := tmpl.Execute(w, data); err != nil {
		return fmt.Errorf("execute template: %w", err)
	}
	return nil
}
