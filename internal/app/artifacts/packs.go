package artifacts

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	packs "github.com/sufield/stave/internal/builtin/pack"
	"github.com/sufield/stave/internal/pkg/jsonutil"
)

// PackRunner handles the inspection of built-in control packs.
type PackRunner struct {
	Registry *packs.Registry
}

// NewPackRunner initializes a runner with an embedded pack registry.
func NewPackRunner() (*PackRunner, error) {
	reg, err := packs.NewEmbeddedRegistry()
	if err != nil {
		return nil, fmt.Errorf("load pack registry: %w", err)
	}
	return &PackRunner{Registry: reg}, nil
}

// List returns all available built-in packs.
func (r *PackRunner) List() []packs.Pack {
	return r.Registry.ListPacks()
}

// Show returns the detailed configuration of a specific pack.
func (r *PackRunner) Show(name string) (packs.Pack, error) {
	name = strings.TrimSpace(name)
	pack, ok := r.Registry.LookupPack(name)
	if !ok {
		available := r.Registry.PackNames()
		return packs.Pack{}, fmt.Errorf("unknown pack %q (available: %s)", name, strings.Join(available, ", "))
	}
	return pack, nil
}

// WritePackList renders pack items as a formatted table.
func WritePackList(w io.Writer, items []packs.Pack) error {
	if len(items) == 0 {
		_, err := fmt.Fprintln(w, "No built-in packs available.")
		return err
	}

	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tDESCRIPTION")

	for _, p := range items {
		fmt.Fprintf(tw, "%s\t%s\n", p.Name, p.Description)
	}

	return tw.Flush()
}

// WritePackJSON renders a pack as indented JSON.
func WritePackJSON(w io.Writer, pack packs.Pack) error {
	return jsonutil.WriteIndented(w, pack)
}
