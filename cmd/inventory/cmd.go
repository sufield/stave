// Package inventory implements the 'stave inventory' command for
// versioned asset export enabling external CVE correlation.
package inventory

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/adapters/observations"
	appinv "github.com/sufield/stave/internal/app/inventory"
	"github.com/sufield/stave/internal/cli/ui"
)

type options struct {
	Snapshot string
	Format   string
	OutFile  string
}

// NewCmd constructs the inventory command.
func NewCmd() *cobra.Command {
	opts := &options{Format: "json"}

	cmd := &cobra.Command{
		Use:   "inventory",
		Short: "Export versioned asset inventory for CVE correlation",
		Long: `Extract version information from snapshot assets and produce a
structured inventory with CPE strings suitable for external CVE
correlation tools (Grype, Trivy, OSV-Scanner, NVD join scripts).

Stave provides the join key. External tools provide CVE data.

Exit Codes:
  0   Inventory exported
  2   Invalid input`,
		Example: `  stave inventory --snapshot snapshot.json
  stave inventory --snapshot snapshot.json --format csv --out inventory.csv`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runInventory(cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.Snapshot, "snapshot", "", "path to snapshot JSON (required)")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", "json", "output format: json | csv")
	cmd.Flags().StringVar(&opts.OutFile, "out", "", "write to file")

	_ = cmd.MarkFlagRequired("snapshot")
	return cmd
}

func runInventory(stdout io.Writer, opts *options) error {
	snapshots, err := observations.LoadBundle(opts.Snapshot)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("load snapshot: %w", err)}
	}

	versions := appinv.Extract(snapshots)
	report := appinv.Report{
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
		Snapshot:    opts.Snapshot,
		Assets:      versions,
	}

	return cmdutil.WriteTo(stdout, opts.OutFile, func(w io.Writer) error {
		return writeInventory(w, opts.Format, versions, report)
	})
}

func writeInventory(w io.Writer, format string, versions []appinv.AssetVersion, report appinv.Report) error {
	switch format {
	case "csv":
		// csv.Writer buffers internally; a per-row Write returns the
		// first deferred error encountered, but subsequent calls will
		// keep returning the same sticky error and the user just
		// sees a truncated file. Fail fast on the header and each row
		// so partial output is impossible — the previous shape
		// silently dropped both the header and the row writes.
		cw := csv.NewWriter(w)
		if err := cw.Write([]string{"asset_id", "asset_type", "version_field", "version", "cpe", "package_ecosystem"}); err != nil {
			return fmt.Errorf("write csv header: %w", err)
		}
		for i := range versions {
			v := &versions[i]
			if err := cw.Write([]string{v.AssetID, v.AssetType, v.VersionField, v.Version, v.CPE, v.PackageEcosystem}); err != nil {
				return fmt.Errorf("write csv row %d (asset %q): %w", i, v.AssetID, err)
			}
		}
		cw.Flush()
		return cw.Error()
	default:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
}
