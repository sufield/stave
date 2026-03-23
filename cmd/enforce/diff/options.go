package diff

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/cmd/cmdutil/compose"
	"github.com/sufield/stave/cmd/cmdutil/convert"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/platform/fsutil"
	"github.com/sufield/stave/pkg/alpha/domain/asset"
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

// ToConfig converts raw CLI options into a validated logic configuration.
func (o *Options) ToConfig(cmd *cobra.Command) (Config, error) {
	obsDir := o.ObservationsDir
	format, err := compose.ResolveFormatValue(cmd, o.Format)
	if err != nil {
		return Config{}, err
	}

	filter, err := o.buildFilter()
	if err != nil {
		return Config{}, err
	}

	gf := cmdutil.GetGlobalFlags(cmd)
	return Config{
		ObservationsDir: obsDir,
		Format:          format,
		Filter:          filter,
		Quiet:           gf.Quiet,
		Sanitizer:       gf.GetSanitizer(),
		Stdout:          cmd.OutOrStdout(),
		Stderr:          cmd.ErrOrStderr(),
	}, nil
}

func (o *Options) buildFilter() (asset.FilterOptions, error) {
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
		switch val {
		case "added", "removed", "modified":
			out = append(out, asset.ChangeType(val))
		default:
			return nil, &ui.UserError{
				Err: fmt.Errorf("invalid --change-type %q (supported: added, removed, modified)", s),
			}
		}
	}
	return out, nil
}
