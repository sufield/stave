// Package features implements the `stave features` command: it reports
// what Stave does (discovered live from the build's registries) and what
// it deliberately does not do (read from the versioned features/scope.yaml
// manifest).
package features

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	scopemanifest "github.com/sufield/stave/features"
	"github.com/sufield/stave/internal/cli/ui"
)

// payload is the rendered document: live IN SCOPE discovery plus the
// versioned OUT OF SCOPE manifest.
type payload struct {
	InScope    []InScopeFeature                `json:"in_scope"`
	OutOfScope []scopemanifest.OutOfScopeEntry `json:"out_of_scope"`
}

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
			renderer, err := newRenderer(format)
			if err != nil {
				return err
			}
			outOfScope, err := scopemanifest.OutOfScope()
			if err != nil {
				return fmt.Errorf("load scope manifest: %w", err)
			}
			doc := payload{InScope: discoverInScope(), OutOfScope: outOfScope}

			// Page human output on a TTY; never page JSON (keeps JSON-to-pipe
			// clean) and never when --no-pager is set or stdout is not a
			// terminal. NewPager returns the writer unchanged with a no-op close
			// in the unpaged cases, so piped/redirected output is unaffected.
			pageable := format != "json" && !noPager
			pw, closePager := ui.NewPager(cmd.Context(), cmd.OutOrStdout(), pageable)
			renderErr := renderer.render(pw, doc)
			closeErr := closePager()
			if renderErr != nil {
				return renderErr
			}
			return closeErr
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "auto", "Output format: auto | text | wide | json")
	cmd.Flags().BoolVar(&noPager, "no-pager", false, "never page output, even on a terminal")
	return cmd
}

// renderer maps a payload to bytes in a specific format.
type renderer interface {
	render(w io.Writer, p payload) error
}

func newRenderer(format string) (renderer, error) {
	switch format {
	case "text", "auto", "":
		return textRenderer{}, nil
	case "wide":
		return wideRenderer{}, nil
	case "json":
		return jsonRenderer{}, nil
	default:
		return nil, &ui.UserError{Err: fmt.Errorf("--format must be auto | text | wide | json (got %q)", format)}
	}
}

type jsonRenderer struct{}

func (jsonRenderer) render(w io.Writer, p payload) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(p)
}

type textRenderer struct{}

func (textRenderer) render(w io.Writer, p payload) error {
	if _, err := fmt.Fprint(w, "\nIN SCOPE (discovered from this build)\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "─────────────────────────────────────"); err != nil {
		return err
	}
	for _, f := range p.InScope {
		if _, err := fmt.Fprintf(w, "  ✓ %-22s %s\n", f.Label, f.Detail); err != nil {
			return err
		}
	}

	if _, err := fmt.Fprint(w, "\nOUT OF SCOPE (by design — see features/scope.yaml)\n"); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "──────────────────────────────────────────────────"); err != nil {
		return err
	}
	for _, e := range p.OutOfScope {
		detail := e.Reason
		if len(e.Alternatives) > 0 {
			detail = fmt.Sprintf("%s: %s", e.Reason, strings.Join(e.Alternatives, ", "))
		}
		if _, err := fmt.Fprintf(w, "  → %-22s %s\n", e.Label, detail); err != nil {
			return err
		}
	}
	return nil
}

// wideRenderer is the columnar variant of the text view: each section is
// tab-aligned, and OUT OF SCOPE gets its own Reason / Alternatives columns
// instead of the compact inline "reason: alts" the default view uses.
type wideRenderer struct{}

func (wideRenderer) render(w io.Writer, p payload) error {
	if _, err := fmt.Fprint(w, "\nIN SCOPE (discovered from this build)\n"); err != nil {
		return err
	}
	in := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(in, "  CAPABILITY\tDETAIL"); err != nil {
		return err
	}
	for _, f := range p.InScope {
		if _, err := fmt.Fprintf(in, "  ✓ %s\t%s\n", f.Label, f.Detail); err != nil {
			return err
		}
	}
	if err := in.Flush(); err != nil {
		return fmt.Errorf("flush in-scope table: %w", err)
	}

	if _, err := fmt.Fprint(w, "\nOUT OF SCOPE (by design — see features/scope.yaml)\n"); err != nil {
		return err
	}
	out := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	if _, err := fmt.Fprintln(out, "  CAPABILITY\tREASON\tALTERNATIVES"); err != nil {
		return err
	}
	for _, e := range p.OutOfScope {
		if _, err := fmt.Fprintf(out, "  → %s\t%s\t%s\n", e.Label, e.Reason, strings.Join(e.Alternatives, ", ")); err != nil {
			return err
		}
	}
	if err := out.Flush(); err != nil {
		return fmt.Errorf("flush out-of-scope table: %w", err)
	}
	return nil
}
