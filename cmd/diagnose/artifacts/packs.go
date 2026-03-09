package artifacts

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	packs "github.com/sufield/stave/internal/builtin/pack"
	"github.com/sufield/stave/internal/metadata"
)

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
		RunE: func(cmd *cobra.Command, args []string) error {
			items, err := packs.ListPacks()
			if err != nil {
				return err
			}
			for _, p := range items {
				if _, err := fmt.Fprintf(cmd.OutOrStdout(), "%s\t%s\n", p.Name, p.Description); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

func newPacksShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Show one built-in pack and its control IDs",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pack, ok, err := packs.LookupPack(strings.TrimSpace(args[0]))
			if err != nil {
				return err
			}
			if !ok {
				names, listErr := packs.PackNames()
				if listErr != nil {
					return listErr
				}
				return fmt.Errorf("unknown pack %q (available: %s)", args[0], strings.Join(names, ", "))
			}
			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(pack)
		},
	}
}
