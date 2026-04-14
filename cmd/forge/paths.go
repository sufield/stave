package forge

import (
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/sufield/stave/internal/adapters/observations"
	"github.com/sufield/stave/internal/core/asset"
)

func newPathsCmd() *cobra.Command {
	var snapshot, assetType, filter string

	cmd := &cobra.Command{
		Use:   "paths",
		Short: "List available observation property paths from a snapshot",
		Long: `Lists all observation property paths for a given asset type in a snapshot,
with types and presence counts. Map entries (like tags) are expanded to
show individual keys present in the snapshot.

Exit Codes:
  0   Paths listed successfully
  2   Invalid input or snapshot not found
  4   Internal error

Examples:
  stave forge paths --snapshot obs.json --asset-type aws_s3_bucket
  stave forge paths --snapshot obs.json --asset-type aws_s3_bucket --filter tags`,
		Example:       `  stave forge paths --snapshot obs.json --asset-type aws_s3_bucket`,
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPaths(cmd.OutOrStdout(), snapshot, assetType, filter)
		},
	}

	cmd.Flags().StringVar(&snapshot, "snapshot", "", "path to snapshot file (required)")
	cmd.Flags().StringVar(&assetType, "asset-type", "", "filter to a specific asset type")
	cmd.Flags().StringVar(&filter, "filter", "", "substring filter on path names")
	_ = cmd.MarkFlagRequired("snapshot")

	return cmd
}

// pathInfo tracks a property path's type and presence count.
type pathInfo struct {
	path     string
	typeName string
	count    int
	total    int
	values   map[string]int // distinct values for string fields
}

func runPaths(w io.Writer, snapshotPath, assetType, filter string) error {
	snapshots, err := observations.LoadBundle(snapshotPath)
	if err != nil {
		return fmt.Errorf("load snapshot: %w", err)
	}
	if len(snapshots) == 0 {
		return errors.New("snapshot file contains no observations")
	}
	snap := &snapshots[len(snapshots)-1]

	// Collect assets matching the type filter.
	var assets []asset.Asset
	for i := range snap.Assets {
		if assetType == "" || string(snap.Assets[i].Type) == assetType {
			assets = append(assets, snap.Assets[i])
		}
	}

	if len(assets) == 0 {
		fmt.Fprintf(w, "No assets of type %q found in snapshot.\n", assetType)
		return nil
	}

	// Walk all properties and collect paths.
	paths := make(map[string]*pathInfo)
	for i := range assets {
		walkProperties(assets[i].Properties, "properties", paths, len(assets))
	}

	// Sort and filter.
	var sorted []string
	for p := range paths {
		if filter == "" || strings.Contains(p, filter) {
			sorted = append(sorted, p)
		}
	}
	sort.Strings(sorted)

	// Render.
	label := assetType
	if label == "" {
		label = "all types"
	}
	fmt.Fprintf(w, "%s observation properties (from %d resources in snapshot):\n", label, len(assets))
	fmt.Fprintln(w, strings.Repeat("-", 80))

	for _, p := range sorted {
		info := paths[p]
		line := fmt.Sprintf("%-60s %-10s", p, info.typeName)
		if info.count < info.total {
			line += fmt.Sprintf("  (%d/%d present)", info.count, info.total)
		}
		if len(info.values) > 0 && len(info.values) <= 5 {
			var vals []string
			for v := range info.values {
				vals = append(vals, v)
			}
			sort.Strings(vals)
			line += fmt.Sprintf("  %v", vals)
		}
		fmt.Fprintln(w, line)
	}

	return nil
}

func walkProperties(props map[string]any, prefix string, paths map[string]*pathInfo, total int) {
	for key, val := range props {
		fullPath := prefix + "." + key
		switch v := val.(type) {
		case map[string]any:
			// Check if this looks like a tags map (string keys → string values).
			isTagMap := true
			for _, mv := range v {
				if _, ok := mv.(string); !ok {
					isTagMap = false
					break
				}
			}
			if isTagMap && len(v) > 0 {
				ensurePath(paths, fullPath, "map", total)
				for mk, mv := range v {
					tagPath := fullPath + "[" + mk + "]"
					info := ensurePath(paths, tagPath, "string", total)
					if s, ok := mv.(string); ok {
						info.values[s]++
					}
				}
			} else {
				ensurePath(paths, fullPath, "object", total)
				walkProperties(v, fullPath, paths, total)
			}
		case bool:
			ensurePath(paths, fullPath, "bool", total)
		case float64:
			ensurePath(paths, fullPath, "number", total)
		case string:
			info := ensurePath(paths, fullPath, "string", total)
			info.values[v]++
		case []any:
			ensurePath(paths, fullPath, "array", total)
		default:
			if val == nil {
				continue
			}
			ensurePath(paths, fullPath, fmt.Sprintf("%T", val), total)
		}
	}
}

func ensurePath(paths map[string]*pathInfo, path, typeName string, total int) *pathInfo {
	info, ok := paths[path]
	if !ok {
		info = &pathInfo{
			path:     path,
			typeName: typeName,
			total:    total,
			values:   make(map[string]int),
		}
		paths[path] = info
	}
	info.count++
	return info
}
