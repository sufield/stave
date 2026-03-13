package diff

import (
	"fmt"
	"strings"

	"github.com/sufield/stave/cmd/cmdutil"
	"github.com/sufield/stave/internal/cli/ui"
	"github.com/sufield/stave/internal/domain/asset"
)

// buildFilter converts raw CLI string slices into a validated domain filter.
func buildFilter(changeTypes, assetTypes []string, assetID string) (asset.FilterOptions, error) {
	ct, err := parseChangeTypes(changeTypes)
	if err != nil {
		return asset.FilterOptions{}, err
	}
	return asset.FilterOptions{
		ChangeTypes: ct,
		AssetTypes:  cmdutil.ToAssetTypes(assetTypes),
		AssetID:     strings.TrimSpace(assetID),
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
				Err: fmt.Errorf("invalid --change-type %q (use: added, removed, modified)", s),
			}
		}
	}
	return out, nil
}

// newDiffFilter is a test helper that constructs a filter from raw flag values.
func newDiffFilter(changeTypes, assetTypes []string, assetID string) (asset.FilterOptions, error) {
	return buildFilter(changeTypes, assetTypes, assetID)
}
