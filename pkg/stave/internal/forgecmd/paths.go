package forgecmd

import (
	"bytes"
	"fmt"
	"slices"
	"strings"

	"github.com/sufield/stave/internal/adapters/observations"
	"github.com/sufield/stave/internal/core/asset"
)

// SnapshotAssetCount loads the bundle and reports the most-recent snapshot's
// asset count. loaded is false when the bundle parsed but holds no snapshots
// (the wizard treats that distinctly from a load error). Used by the wizard's
// "Loaded snapshot with N assets" banner.
func SnapshotAssetCount(path string) (count int, loaded bool, err error) {
	snapshots, err := observations.LoadBundle(path)
	if err != nil {
		return 0, false, fmt.Errorf("load snapshot: %w", err)
	}
	if len(snapshots) == 0 {
		return 0, false, nil
	}
	return len(snapshots[len(snapshots)-1].Assets), true, nil
}

// SnapshotAssetTypes loads the bundle and returns the distinct asset types in
// its most-recent snapshot. Used by the wizard's asset-type step.
func SnapshotAssetTypes(path string) ([]string, error) {
	snap, err := loadLatestSnapshot(path)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool)
	for _, a := range snap.Assets {
		seen[string(a.Type)] = true
	}
	var types []string
	for t := range seen {
		types = append(types, t)
	}
	return types, nil
}

// pathInfo tracks a property path's type and presence count.
type pathInfo struct {
	path     string
	typeName string
	count    int
	total    int
	values   map[string]int
}

// Paths lists the observation property paths (with types + presence counts)
// for assets of the given type in a snapshot, filtered by substring. It is the
// library entry point behind `stave forge paths` (and the wizard's path step).
func Paths(snapshotPath, assetType, filter string) ([]byte, error) {
	snap, err := loadLatestSnapshot(snapshotPath)
	if err != nil {
		return nil, err
	}

	var assets []asset.Asset
	for i := range snap.Assets {
		if assetType == "" || string(snap.Assets[i].Type) == assetType {
			assets = append(assets, snap.Assets[i])
		}
	}

	var buf bytes.Buffer
	if len(assets) == 0 {
		fmt.Fprintf(&buf, "No assets of type %q found in snapshot.\n", assetType)
		return buf.Bytes(), nil
	}

	paths := make(map[string]*pathInfo)
	for i := range assets {
		walkProperties(assets[i].Properties, "properties", paths, len(assets))
	}

	var sorted []string
	for p := range paths {
		if filter == "" || strings.Contains(p, filter) {
			sorted = append(sorted, p)
		}
	}
	slices.Sort(sorted)

	label := assetType
	if label == "" {
		label = "all types"
	}
	fmt.Fprintf(&buf, "%s observation properties (from %d resources in snapshot):\n", label, len(assets))
	fmt.Fprintln(&buf, strings.Repeat("-", 80))

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
			slices.Sort(vals)
			line += fmt.Sprintf("  %v", vals)
		}
		fmt.Fprintln(&buf, line)
	}

	return buf.Bytes(), nil
}

func walkProperties(props map[string]any, prefix string, paths map[string]*pathInfo, total int) {
	for key, val := range props {
		fullPath := prefix + "." + key
		switch v := val.(type) {
		case map[string]any:
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
