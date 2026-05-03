// Package enrich implements the 'stave enrich' command for local
// CVE/NVD enrichment of inventory data.
package enrich

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	appenrich "github.com/sufield/stave/internal/app/enrich"
	"github.com/sufield/stave/internal/app/inventory"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type options struct {
	InventoryPath string
	NVDFeedPath   string
	MinCVSS       float64
	OutPath       string
	Stdin         bool
}

// NewCmd constructs the enrich command.
func NewCmd() *cobra.Command {
	opts := &options{}

	cmd := &cobra.Command{
		Use:   "enrich",
		Short: "Enrich inventory with local CVE/NVD data",
		Long: `Match CPE strings from stave inventory against a locally-provided
NVD feed to annotate assets with known vulnerabilities. Purely local
file processing — no network calls required.

Inputs:
  --inventory PATH   Inventory JSON from stave inventory (or --stdin)
  --nvd-feed PATH    Local NVD feed JSON file (required)
  --min-cvss SCORE   Minimum CVSS score to include (default: 0)
  --out PATH         Output file path (default: stdout)
  --stdin            Read inventory from stdin

Exit Codes:
  0   Enrichment complete
  2   Invalid input`,
		Example: `  stave enrich --inventory inventory.json --nvd-feed nvd-2024.json --min-cvss 7.0
  stave inventory --snapshot snap.json --format json | stave enrich --nvd-feed nvd.json --stdin`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(cmd.OutOrStdout(), opts)
		},
	}

	cmd.Flags().StringVar(&opts.InventoryPath, "inventory", "", "path to inventory JSON from stave inventory")
	cmd.Flags().StringVar(&opts.NVDFeedPath, "nvd-feed", "", "path to local NVD feed JSON (required)")
	cmd.Flags().Float64Var(&opts.MinCVSS, "min-cvss", 0, "minimum CVSS score to include")
	cmd.Flags().StringVar(&opts.OutPath, "out", "", "output file path (default: stdout)")
	cmd.Flags().BoolVar(&opts.Stdin, "stdin", false, "read inventory from stdin")
	_ = cmd.MarkFlagRequired("nvd-feed")

	return cmd
}

func run(stdout io.Writer, opts *options) error {
	// Load inventory.
	var invData []byte
	var err error
	if opts.Stdin {
		invData, err = io.ReadAll(os.Stdin)
		if err != nil {
			return fmt.Errorf("read stdin: %w", err)
		}
	} else if opts.InventoryPath != "" {
		invData, err = fsutil.ReadFileLimited(opts.InventoryPath)
		if err != nil {
			return &ui.UserError{Err: fmt.Errorf("read inventory: %w", err)}
		}
	} else {
		return &ui.UserError{Err: errors.New("one of --inventory or --stdin is required")}
	}

	var invReport inventory.Report
	if jsonErr := json.Unmarshal(invData, &invReport); jsonErr != nil {
		return &ui.UserError{Err: fmt.Errorf("parse inventory: %w", jsonErr)}
	}

	// Load NVD feed.
	feedData, err := fsutil.ReadFileLimited(opts.NVDFeedPath)
	if err != nil {
		return &ui.UserError{Err: fmt.Errorf("read NVD feed: %w", err)}
	}

	var feed appenrich.NVDFeed
	if jsonErr := json.Unmarshal(feedData, &feed); jsonErr != nil {
		return &ui.UserError{Err: fmt.Errorf("parse NVD feed: %w", jsonErr)}
	}

	result := appenrich.Enrich(appenrich.Input{
		Inventory: invReport.Assets,
		Feed:      feed,
		MinCVSS:   opts.MinCVSS,
	})

	// Write output. cmdutil.WriteTo handles os.Create + Close-error
	// propagation in one place — see cmd/cmdutil/output.go.
	return cmdutil.WriteTo(stdout, opts.OutPath, func(w io.Writer) error {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(result)
	})
}
