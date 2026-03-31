package diff

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/convert"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/core/asset"
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
	f.StringSliceVar(&o.ChangeTypes, "change-type", nil, "Filter changes: added, removed, modified")
	f.StringSliceVar(&o.AssetTypes, "asset-type", nil, "Filter by asset type")
	f.StringVar(&o.AssetID, "asset-id", "", "Filter by asset ID substring")
}

// Prepare normalizes paths. Called from PreRunE.
func (o *Options) Prepare(_ *cobra.Command) error {
	o.ObservationsDir = fsutil.CleanUserPath(o.ObservationsDir)
	return nil
}

// toConfig converts raw CLI options into a validated logic configuration.
// Standalone function — does not depend on cobra.
func toConfig(o *Options, formatChanged bool) (config, error) {
	format, err := compose.ResolveFormatValuePure(o.Format, formatChanged, false)
	if err != nil {
		return config{}, err
	}

	filter, err := buildFilter(o)
	if err != nil {
		return config{}, err
	}

	return config{
		ObservationsDir: o.ObservationsDir,
		Format:          format,
		Filter:          filter,
	}, nil
}

func buildFilter(o *Options) (asset.FilterOptions, error) {
	changeTypes, err := parseChangeTypes(o.ChangeTypes)
	if err != nil {
		return asset.FilterOptions{}, err
	}
	return asset.FilterOptions{
		ChangeTypes: changeTypes,
		AssetTypes:  convert.ToAssetTypes(o.AssetTypes),
		AssetID:     strings.TrimSpace(o.AssetID),
	}, nil
}

// parseChangeTypes validates and converts raw strings to asset.ChangeType values.
func parseChangeTypes(raw []string) ([]asset.ChangeType, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	out := make([]asset.ChangeType, 0, len(raw))
	for _, s := range raw {
		val := strings.ToLower(strings.TrimSpace(s))
		if val == "" {
			continue
		}
		ct := asset.ChangeType(val)
		if !ct.IsValid() {
			return nil, &ui.UserError{
				Err: fmt.Errorf("invalid --change-type %q (supported: added, removed, modified)", s),
			}
		}
		out = append(out, ct)
	}
	return out, nil
}
