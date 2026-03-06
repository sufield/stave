package diff

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
	"github.com/sufield/stave/internal/platform/fsutil"
)

type options struct {
	ObservationsDir string
	Format          string
	ChangeTypes     []string
	AssetTypes      []string
	AssetID         string
}

func defaultOptions() *options {
	return &options{ObservationsDir: "observations", Format: "text"}
}

func (o *options) bindFlags(cmd *cobra.Command) {
	cmd.Flags().StringVarP(&o.ObservationsDir, "observations", "o", o.ObservationsDir, "Path to observation snapshots directory")
	cmd.Flags().StringVarP(&o.Format, "format", "f", o.Format, "Output format: text or json")
	cmd.Flags().StringSliceVar(&o.ChangeTypes, "change-type", nil, "Filter change types: added, removed, modified")
	cmd.Flags().StringSliceVar(&o.AssetTypes, "asset-type", nil, "Filter asset type values")
	cmd.Flags().StringVar(&o.AssetID, "asset-id", "", "Filter by resource ID substring")
}

func (o *options) normalize() {
	o.ObservationsDir = fsutil.CleanUserPath(o.ObservationsDir)
}

func (o *options) resolveFormat(cmd *cobra.Command) (ui.OutputFormat, error) {
	return cmdutil.ResolveFormatValue(cmd, o.Format)
}

func (o *options) buildFilter() (asset.FilterOptions, error) {
	filter := asset.FilterOptions{
		ChangeTypes:   make([]asset.ChangeType, 0, len(o.ChangeTypes)),
		AssetTypes: make([]string, 0, len(o.AssetTypes)),
		AssetID:       strings.TrimSpace(o.AssetID),
	}
	for _, raw := range o.ChangeTypes {
		ct := strings.ToLower(strings.TrimSpace(raw))
		if ct == "" {
			continue
		}
		switch ct {
		case "added", "removed", "modified":
			filter.ChangeTypes = append(filter.ChangeTypes, asset.ChangeType(ct))
		default:
			return asset.FilterOptions{}, fmt.Errorf("invalid --change-type %q (use: added, removed, modified)", raw)
		}
	}
	for _, raw := range o.AssetTypes {
		rt := strings.TrimSpace(raw)
		if rt == "" {
			continue
		}
		filter.AssetTypes = append(filter.AssetTypes, rt)
	}
	return filter, nil
}

// kept for local tests
func newDiffFilter(changeTypes, resourceTypes []string, assetID string) (asset.FilterOptions, error) {
	return (&options{ChangeTypes: changeTypes, AssetTypes: resourceTypes, AssetID: assetID}).buildFilter()
}
