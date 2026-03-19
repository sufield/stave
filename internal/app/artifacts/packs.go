package artifacts

import (
	"context"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	packs "github.com/sufield/stave/internal/builtin/pack"
	"github.com/sufield/stave/internal/pkg/jsonutil"
)

// PackRunner handles the inspection of built-in control packs.
type PackRunner struct {
	Stdout   io.Writer
	Registry *packs.Registry
}

// NewPackRunner initializes a runner with the provided output stream
// and an embedded pack registry.
func NewPackRunner(stdout io.Writer) (*PackRunner, error) {
	reg, err := packs.NewEmbeddedRegistry()
	if err != nil {
		return nil, fmt.Errorf("load pack registry: %w", err)
	}
	return &PackRunner{Stdout: stdout, Registry: reg}, nil
}

// List prints all available built-in packs in a formatted table.
func (r *PackRunner) List(_ context.Context) error {
	items := r.Registry.ListPacks()

	if len(items) == 0 {
		_, err := fmt.Fprintln(r.Stdout, "No built-in packs available.")
		return err
	}

	tw := tabwriter.NewWriter(r.Stdout, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tDESCRIPTION")

	for _, p := range items {
		fmt.Fprintf(tw, "%s\t%s\n", p.Name, p.Description)
	}

	return tw.Flush()
}

// Show prints the detailed configuration of a specific pack as JSON.
func (r *PackRunner) Show(_ context.Context, name string) error {
	name = strings.TrimSpace(name)
	pack, ok := r.Registry.LookupPack(name)

	if !ok {
		available := r.Registry.PackNames()
		return fmt.Errorf("unknown pack %q (available: %s)", name, strings.Join(available, ", "))
	}

	return jsonutil.WriteIndented(r.Stdout, pack)
}
