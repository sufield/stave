package artifacts

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/sufield/stave/internal/app/contracts"
	"github.com/sufield/stave/internal/util/jsonutil"
)

// PolicyInspector manages the discovery and inspection of pre-defined
// security control packs through the contracts.PolicyLibrary
// abstraction. The concrete embedded-pack adapter lives in
// internal/builtin/pack and is wired at the cmd composition layer.
type PolicyInspector struct {
	Library contracts.PolicyLibrary
}

// NewInspector constructs a PolicyInspector around the given
// library. Returns an error if lib is nil so the missing wiring
// surfaces at the composition boundary instead of via a nil-deref
// at first use.
func NewInspector(lib contracts.PolicyLibrary) (*PolicyInspector, error) {
	if lib == nil {
		return nil, errors.New("artifacts.NewInspector: PolicyLibrary is required")
	}
	return &PolicyInspector{Library: lib}, nil
}

// AvailablePacks returns the full collection of embedded security control sets.
func (i *PolicyInspector) AvailablePacks() ([]contracts.PolicyPack, error) {
	packs, err := i.Library.ListPacks()
	if err != nil {
		return nil, fmt.Errorf("list policy packs: %w", err)
	}
	return packs, nil
}

// Inspect retrieves the detailed technical definition of a specific security pack.
func (i *PolicyInspector) Inspect(name string) (contracts.PolicyPack, error) {
	name = strings.TrimSpace(name)
	pack, ok := i.Library.LookupPack(name)
	if !ok {
		available := i.Library.PackNames()
		return contracts.PolicyPack{}, fmt.Errorf("policy pack %q not found (available: %s)", name, strings.Join(available, ", "))
	}
	return pack, nil
}

// RenderSummary renders a high-level list of available policy packs as a table.
func RenderSummary(w io.Writer, items []contracts.PolicyPack) error {
	if len(items) == 0 {
		_, err := fmt.Fprintln(w, "No security policy packs discovered in the library.")
		return err
	}

	tw := tabwriter.NewWriter(w, 0, 8, 2, ' ', 0)
	fmt.Fprintln(tw, "POLICY PACK\tDESCRIPTION")

	for _, p := range items {
		fmt.Fprintf(tw, "%s\t%s\n", p.Name, p.Description)
	}

	if err := tw.Flush(); err != nil {
		return fmt.Errorf("flush policy pack table: %w", err)
	}
	return nil
}

// ExportManifest renders a policy pack definition as a raw JSON manifest.
func ExportManifest(w io.Writer, p contracts.PolicyPack) error {
	if err := jsonutil.WriteIndented(w, p); err != nil {
		return fmt.Errorf("write policy pack manifest: %w", err)
	}
	return nil
}
