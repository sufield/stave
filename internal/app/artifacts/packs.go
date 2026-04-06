package artifacts

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	packs "github.com/sufield/stave/internal/builtin/pack"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// PolicyInspector manages the discovery and inspection of pre-defined
// security control packs embedded within the tool.
type PolicyInspector struct {
	Library *packs.Index
}

// NewInspector initializes an inspector with the built-in policy library.
func NewInspector() (*PolicyInspector, error) {
	lib, err := packs.NewEmbeddedRegistry()
	if err != nil {
		return nil, fmt.Errorf("load policy library: %w", err)
	}
	return &PolicyInspector{Library: lib}, nil
}

// AvailablePacks returns the full collection of embedded security control sets.
func (i *PolicyInspector) AvailablePacks() []packs.Pack {
	return i.Library.ListPacks()
}

// Inspect retrieves the detailed technical definition of a specific security pack.
func (i *PolicyInspector) Inspect(name string) (packs.Pack, error) {
	name = strings.TrimSpace(name)
	pack, ok := i.Library.LookupPack(name)
	if !ok {
		available := i.Library.PackNames()
		return packs.Pack{}, fmt.Errorf("policy pack %q not found (available: %s)", name, strings.Join(available, ", "))
	}
	return pack, nil
}

// RenderSummary renders a high-level list of available policy packs as a table.
func RenderSummary(w io.Writer, items []packs.Pack) error {
	if len(items) == 0 {
		_, err := fmt.Fprintln(w, "No security policy packs discovered in the library.")
		return err
	}

	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "POLICY PACK\tDESCRIPTION")

	for _, p := range items {
		fmt.Fprintf(tw, "%s\t%s\n", p.Name, p.Description)
	}

	return tw.Flush()
}

// ExportManifest renders a policy pack definition as a raw JSON manifest.
func ExportManifest(w io.Writer, p packs.Pack) error {
	return jsonutil.WriteIndented(w, p)
}
