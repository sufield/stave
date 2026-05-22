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

Inputs:
  --format, -f   Output format: text (default) or json.

Outputs:
  stdout         The scope report (text table or JSON).

Exit codes:
  0  report rendered
  2  invalid flag / unknown format
  4  internal error reading the embedded manifest

Examples:
  stave features
  stave features --format json`,
		Example:       "  stave features\n  stave features --format json",
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
			return renderer.render(cmd.OutOrStdout(), payload{
				InScope:    discoverInScope(),
				OutOfScope: outOfScope,
			})
		},
	}

	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text or json")
	return cmd
}

// renderer maps a payload to bytes in a specific format.
type renderer interface {
	render(w io.Writer, p payload) error
}

func newRenderer(format string) (renderer, error) {
	switch format {
	case "text", "":
		return textRenderer{}, nil
	case "json":
		return jsonRenderer{}, nil
	default:
		return nil, &ui.UserError{Err: fmt.Errorf("unknown format %q (want text or json)", format)}
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
