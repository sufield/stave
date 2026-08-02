package graph

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/cliflags"
	"github.com/sufield/stave/internal/platform/metadata"
	"github.com/sufield/stave/pkg/stave"
)

type silosOptions struct {
	ChainsDir   string
	Format      string
	MinControls int
}

func newSilosCmd() *cobra.Command {
	opts := &silosOptions{
		ChainsDir:   "",
		Format:      "text",
		MinControls: 1,
	}

	cmd := &cobra.Command{
		Use:   "silos",
		Short: "Find services with controls but zero compound chains",
		Long: `Silos analyzes the control/chain graph topology to find services with
controls but zero compound chains connecting them to other services.

These "silent" services have atomic detection but no cross-service risk
composition — the gap where compound chains add value over single-resource
scanners.

Output includes a ranked silo list, the most-connected services, and a
connectivity distribution histogram.

Inputs:
  --chains          Chains directory (default: chains)
  --format, -f      Output format: text (default) or json
  --min-controls    Only show silos with >= N controls (default: 1)

Exit Codes:
  0   Analysis completed
  2   Input error
  4   Internal error
  130 Interrupted (SIGINT)

Examples:
  stave graph silos
  stave graph silos --format json
  stave graph silos --min-controls 5` + metadata.OfflineHelpSuffix,
		Example:       `  stave graph silos --format json | jq '.silos[:5]'`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runSilos(opts, cmd.OutOrStdout())
		},
	}

	cmd.Flags().StringVar(&opts.ChainsDir, "chains", opts.ChainsDir, "Path to chain definitions directory")
	cmd.Flags().StringVarP(&opts.Format, "format", "f", opts.Format, "Output format: text or json")
	cmd.Flags().IntVar(&opts.MinControls, "min-controls", opts.MinControls, "Only show silos with at least N controls")
	_ = cmd.RegisterFlagCompletionFunc("format", cliflags.CompleteFixed("text", "json"))

	return cmd
}

func runSilos(opts *silosOptions, w io.Writer) error {
	cfg := stave.SiloConfig{
		ChainsDir:   opts.ChainsDir,
		MinControls: opts.MinControls,
	}

	if opts.Format == "json" {
		data, err := stave.GraphSilosJSON(cfg)
		if err != nil {
			return fmt.Errorf("graph silos: %w", err)
		}
		_, werr := w.Write(append(data, '\n'))
		return werr
	}

	report, err := stave.GraphSilos(cfg)
	if err != nil {
		return fmt.Errorf("graph silos: %w", err)
	}

	return renderSilosText(w, report)
}

func renderSilosText(w io.Writer, r *stave.SiloReport) error {
	fmt.Fprintf(w, "Structural Silence Detection\n")
	fmt.Fprintf(w, "============================\n\n")

	fmt.Fprintf(w, "Catalog: %d controls, %d chains, %d services\n\n", r.TotalControls, r.TotalChains, r.TotalServices)

	if len(r.Silos) == 0 {
		fmt.Fprintf(w, "No silos found — every service with controls participates in at least one chain.\n")
	} else {
		fmt.Fprintf(w, "Silos (%d services with controls but zero compound chains):\n\n", r.SiloCount)
		for _, s := range r.Silos {
			fmt.Fprintf(w, "  %-20s %3d controls    0 chains\n", s.Service, s.Controls)
			if s.Question != "" {
				fmt.Fprintf(w, "    %s\n\n", s.Question)
			}
		}
	}

	if len(r.MostConnected) > 0 {
		fmt.Fprintf(w, "Most connected:\n\n")
		for _, s := range r.MostConnected {
			peers := strings.Join(s.ConnectedTo, ", ")
			fmt.Fprintf(w, "  %-20s %3d chains    connected to: %s\n", s.Service, s.Chains, peers)
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintf(w, "Distribution:\n")
	fmt.Fprintf(w, "  0 chains:    %d\n", r.Distribution["0_chains"])
	fmt.Fprintf(w, "  1-5 chains:  %d\n", r.Distribution["1-5_chains"])
	fmt.Fprintf(w, "  6-20 chains: %d\n", r.Distribution["6-20_chains"])
	fmt.Fprintf(w, "  21+ chains:  %d\n\n", r.Distribution["21+_chains"])

	fmt.Fprintf(w, "Silo count: %d (target: 0)\n\n", r.SiloCount)

	fmt.Fprintf(w, "Asset Type Coverage:\n")
	fmt.Fprintf(w, "  Schema types:    %d\n", r.SchemaAssetTypeCount)
	fmt.Fprintf(w, "  Evaluated:       %d\n", r.EvaluatedAssetTypeCount)
	fmt.Fprintf(w, "  Unevaluated:     %d\n", r.UnevaluatedCount)
	if len(r.UnevaluatedAssetTypes) > 0 {
		fmt.Fprintln(w)
		fmt.Fprintf(w, "Unevaluated asset types (schema defined, zero controls):\n\n")
		for _, u := range r.UnevaluatedAssetTypes {
			fmt.Fprintf(w, "  %s\n", u.AssetType)
		}
	}

	return nil
}
