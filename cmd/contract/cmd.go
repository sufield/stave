// Package contract implements the `stave contract show` command —
// a single-source view of what an agent needs to produce a valid
// observation for an asset type: the per-asset JSON Schema, the
// property paths the catalog reads, control + chain counts per path,
// and (if any) the matching Steampipe mapping file.
//
// The command joins three sources that exist independently in the
// codebase:
//
//   - internal/contracts/schema/        — per-asset JSON Schemas
//   - internal/core/predindex/          — path -> controls / chains reverse index
//   - contracts/steampipe/<type>.yaml   — agent-side ingest mapping
//
// No new data is computed; everything is a runtime query against
// the embedded catalog and the workspace. Output changes when the
// catalog changes, without regeneration.
package contract

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/pkg/stave"
)

type options struct {
	AssetType    string
	List         bool
	Format       string
	ControlsDir  string
	ChainsDir    string
	SteampipeDir string
	NoPager      bool
}

// NewCmd constructs the `contract` parent command. Today it ships
// one subcommand (`show`); future siblings can add per-type lint or
// validate operations without reshuffling the parent shape.
func NewCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "contract",
		Short: "Inspect Stave's per-asset-type input contracts",
		Long: `Contract commands expose the data an agent needs to produce a valid
observation snapshot for a given asset type: the per-asset JSON Schema,
the property paths the catalog reads, control + chain counts per path,
and the Steampipe ingest mapping when one ships.

Subcommands:
  show     Show contract details for one asset type (or --list for all)
`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	cmd.AddCommand(newShowCmd())
	return cmd
}

func newShowCmd() *cobra.Command {
	opts := &options{
		Format:       "text",
		ControlsDir:  "controls",
		ChainsDir:    "chains",
		SteampipeDir: "contracts/steampipe",
	}

	cmd := &cobra.Command{
		Use:   "show",
		Short: "Show the agent-facing contract for an asset type",
		Long: `Show emits everything an agent needs to populate observations for
one asset type:

  - the per-asset JSON Schema path
  - the property paths the catalog reads, with type, control count,
    chain count, and a "required vs optional" hint
  - any Steampipe mapping under contracts/steampipe/

Use --list to enumerate every asset type with at least one
applicable_asset_types declaration in the catalog, showing whether
each has a schema and a Steampipe mapping.

Inputs:
  --asset-type T     Asset type to show (e.g. aws_s3_bucket)
  --list             List every asset type with controls (no --asset-type)
  --controls DIR     Control catalog (default: controls)
  --chains DIR       Chain catalog (default: chains)
  --steampipe DIR    Directory of Steampipe mappings (default: contracts/steampipe)
  --format F         text (default) | json

Exit codes:
  0   Success
  2   Invalid input (missing flag, unknown asset type)
  4   Internal error (catalog load failure)
`,
		Example: `  # Detailed view for one type
  stave contract show --asset-type aws_s3_bucket

  # All types with at-a-glance schema + mapping presence
  stave contract show --list

  # Machine-readable
  stave contract show --asset-type aws_iam_role --format json`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			pageable := !opts.NoPager && opts.Format != "json"
			pw, closePager := ui.NewPager(cmd.Context(), cmd.OutOrStdout(), pageable)
			err := run(cmd.Context(), pw, opts)
			if cerr := closePager(); cerr != nil && err == nil {
				err = cerr
			}
			return err
		},
	}

	cmd.Flags().StringVar(&opts.AssetType, "asset-type", "", "asset type to inspect (e.g. aws_s3_bucket)")
	cmd.Flags().BoolVar(&opts.List, "list", false, "list every asset type with controls")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "text", "output format: text | json")
	cmd.Flags().BoolVar(&opts.NoPager, "no-pager", false, "never page output, even on a terminal")
	cmd.Flags().StringVarP(&opts.ControlsDir, "controls", "i", "", "control catalog directory (default: embedded catalog)")
	cmd.Flags().StringVar(&opts.ChainsDir, "chains", "", "chain catalog directory (default: embedded chains)")
	cmd.Flags().StringVar(&opts.SteampipeDir, "steampipe", "contracts/steampipe", "Steampipe mapping directory")

	return cmd
}

func run(ctx context.Context, w io.Writer, opts *options) error {
	if !opts.List && opts.AssetType == "" {
		return &ui.UserError{Err: errors.New("either --asset-type or --list is required")}
	}
	if opts.List && opts.AssetType != "" {
		return &ui.UserError{Err: errors.New("--asset-type and --list are mutually exclusive")}
	}
	// Validate the format up front (guard, not a render dispatch — the
	// rendering lives in pkg/stave — so this does not trip the
	// inline-format-switch lint).
	if opts.Format != "text" && opts.Format != "json" && opts.Format != "" {
		return &ui.UserError{Err: fmt.Errorf("--format must be text | json (got %q)", opts.Format)}
	}

	var out []byte
	var err error
	if opts.List {
		out, err = stave.ContractList(ctx, opts.ControlsDir, opts.ChainsDir, opts.SteampipeDir, opts.Format)
	} else {
		out, err = stave.ContractShowType(ctx, opts.AssetType, opts.ControlsDir, opts.ChainsDir, opts.SteampipeDir, opts.Format)
	}
	if err != nil {
		if errors.Is(err, stave.ErrInvalidInput) {
			return &ui.UserError{Err: err}
		}
		return err //nolint:wrapcheck // facade already wrapped ("load controls"/"render contract"); preserve exit 4.
	}
	if _, werr := w.Write(out); werr != nil {
		return fmt.Errorf("write contract: %w", werr)
	}
	return nil
}
