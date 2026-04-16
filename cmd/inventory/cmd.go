// Package inventory implements the 'stave inventory' command for
// versioned asset export enabling external CVE correlation.
package inventory

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/spf13/cobra"

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

	w := stdout
	if opts.OutFile != "" {
		f, fErr := os.Create(opts.OutFile)
		if fErr != nil {
			return fmt.Errorf("create output: %w", fErr)
		}
		defer f.Close()
		w = f
	}

	switch opts.Format {
	case "csv":
		cw := csv.NewWriter(w)
		_ = cw.Write([]string{"asset_id", "asset_type", "version_field", "version", "cpe", "package_ecosystem"})
		for i := range versions {
			v := &versions[i]
			_ = cw.Write([]string{v.AssetID, v.AssetType, v.VersionField, v.Version, v.CPE, v.PackageEcosystem})
		}
		cw.Flush()
		return cw.Error()
	default:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(report)
	}
}
