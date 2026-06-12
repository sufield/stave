package diff

import (
	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/platform/fsutil"
)

// Options holds the raw input from CLI flags.
type Options struct {
	ObservationsDir string
	Format          string
	ChangeTypes     []string
	AssetTypes      []string
	AssetID         string
}

// DefaultOptions returns the standard defaults for the diff command.
func DefaultOptions() Options {
	return Options{
		ObservationsDir: "observations",
		Format:          "text",
	}
}

// BindFlags attaches the options to a Cobra command.
func (o *Options) BindFlags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVarP(&o.ObservationsDir, "observations", "o", o.ObservationsDir, "Path to observation snapshots directory")
	f.StringVarP(&o.Format, "format", "f", o.Format, "Output format (text|json)")
	f.StringSliceVar(&o.ChangeTypes, "change-type", nil, "Filter changes: PROVISIONED, DECOMMISSIONED, RECONFIGURED")
	f.StringSliceVar(&o.AssetTypes, "asset-type", nil, "Filter by asset type")
	f.StringVar(&o.AssetID, "asset-id", "", "Filter by asset ID substring")
}

// Prepare normalizes paths. Called from PreRunE.
func (o *Options) Prepare(_ *cobra.Command) error {
	o.ObservationsDir = fsutil.CleanUserPath(o.ObservationsDir)
	return nil
}
