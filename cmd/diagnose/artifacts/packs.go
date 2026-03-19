//go:build stavedev

package artifacts

import (
	"context"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	packs "github.com/sufield/stave/internal/builtin/pack"
	"github.com/sufield/stave/internal/metadata"
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

// --- Cobra Command Tree ---

// NewPacksCmd constructs the packs command tree.
func NewPacksCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "packs",
		Short: "Inspect built-in control packs",
		Long:  "Packs lists and shows embedded control packs available for deterministic offline evaluation." + metadata.OfflineHelpSuffix,
		Args:  cobra.NoArgs,
	}

	cmd.AddCommand(newPacksListCmd())
	cmd.AddCommand(newPacksShowCmd())

	return cmd
}

func newPacksListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List available built-in packs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			runner, err := NewPackRunner(cmd.OutOrStdout())
			if err != nil {
				return err
			}
			return runner.List(cmd.Context())
		},
	}
}

func newPacksShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show one built-in pack and its control IDs",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runner, err := NewPackRunner(cmd.OutOrStdout())
			if err != nil {
				return err
			}
			return runner.Show(cmd.Context(), args[0])
		},
	}
}
