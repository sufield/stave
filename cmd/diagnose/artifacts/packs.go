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
	Stdout io.Writer
}

// NewPackRunner initializes a runner with the provided output stream.
func NewPackRunner(stdout io.Writer) *PackRunner {
	return &PackRunner{Stdout: stdout}
}

// List prints all available built-in packs in a formatted table.
func (r *PackRunner) List(_ context.Context) error {
	items, err := packs.ListPacks()
	if err != nil {
		return fmt.Errorf("listing packs: %w", err)
	}

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
	pack, ok, err := packs.LookupPack(name)
	if err != nil {
		return fmt.Errorf("lookup pack %q: %w", name, err)
	}

	if !ok {
		available, listErr := packs.PackNames()
		if listErr != nil {
			return fmt.Errorf("pack %q not found", name)
		}
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
			return NewPackRunner(cmd.OutOrStdout()).List(cmd.Context())
		},
	}
}

func newPacksShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show one built-in pack and its control IDs",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			return NewPackRunner(cmd.OutOrStdout()).Show(cmd.Context(), args[0])
		},
	}
}
