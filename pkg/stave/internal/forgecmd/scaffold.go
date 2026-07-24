package forgecmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/adapters/observations"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
	"github.com/sufield/stave/internal/platform/fsutil"
)

// Scaffold generates minimal pass/fail fixture files (extracting only the
// properties the control's predicate references) under outDir, and returns the
// status output. It is the library entry point behind `stave forge scaffold`.
func Scaffold(controlPath, snapshotPath, outDir string) ([]byte, error) {
	data, err := fsutil.ReadFileLimited(fsutil.CleanUserPath(controlPath))
	if err != nil {
		return nil, fmt.Errorf("read control: %w", err)
	}
	ctl, err := ctlyaml.UnmarshalControlDefinition(data)
	if err != nil {
		return nil, fmt.Errorf("parse control: %w", err)
	}

	snaps, err := observations.LoadBundle(snapshotPath)
	if err != nil {
		return nil, fmt.Errorf("load snapshot: %w", err)
	}
	if len(snaps) == 0 {
		return nil, fmt.Errorf("no snapshots in %s", snapshotPath)
	}
	snap := snaps[len(snaps)-1]

	paths := extractPredicatePaths(ctl.UnsafePredicate)

	var buf bytes.Buffer
	var matchingAssets []asset.Asset
	for i := range snap.Assets {
		if hasAnyPath(snap.Assets[i].Properties, paths) {
			matchingAssets = append(matchingAssets, snap.Assets[i])
		}
	}
	if len(matchingAssets) == 0 {
		fmt.Fprintf(&buf, "No assets match predicate paths in snapshot. Using empty fixture.\n")
		matchingAssets = []asset.Asset{{
			ID:         "fixture-asset",
			Properties: map[string]any{},
		}}
	}

	if outDir == "" {
		outDir = filepath.Join("testdata", string(ctl.ID))
	}
	if mkErr := os.MkdirAll(outDir, 0o750); mkErr != nil {
		return nil, fmt.Errorf("create dir: %w", mkErr)
	}

	var resources []fixtureResource
	for _, a := range matchingAssets {
		filtered := filterProperties(a.Properties, paths)
		resources = append(resources, fixtureResource{
			AssetID:    string(a.ID),
			Properties: filtered,
		})
	}

	fixture := fixtureFile{Resources: resources}

	passPath := filepath.Join(outDir, "fixture-pass.json")
	if writeErr := writeFixtureFile(passPath, fixture); writeErr != nil {
		return nil, writeErr
	}
	fmt.Fprintf(&buf, "Wrote %s\n", passPath)

	failResources := make([]fixtureResource, len(resources))
	for i, r := range resources {
		failResources[i] = fixtureResource{
			AssetID:    r.AssetID,
			Properties: map[string]any{},
		}
	}
	failPath := filepath.Join(outDir, "fixture-fail.json")
	if writeErr := writeFixtureFile(failPath, fixtureFile{Resources: failResources}); writeErr != nil {
		return nil, writeErr
	}
	fmt.Fprintf(&buf, "Wrote %s\n", failPath)
	fmt.Fprintf(&buf, "Edit %s to set property values that trigger the control.\n", failPath)

	return buf.Bytes(), nil
}

func writeFixtureFile(path string, f fixtureFile) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal fixture: %w", err)
	}
	if err = fsutil.SafeWriteFile(path, append(data, '\n'), fsutil.ConfigWriteOpts()); err != nil {
		return fmt.Errorf("write fixture: %w", err)
	}
	return nil
}

func extractPredicatePaths(pred policy.UnsafePredicate) []string {
	var paths []string
	for i := range pred.All {
		if p := pred.All[i].Field.String(); p != "" {
			paths = append(paths, p)
		}
		paths = append(paths, extractPredicatePaths(policy.UnsafePredicate{All: pred.All[i].All, Any: pred.All[i].Any})...)
	}
	for i := range pred.Any {
		if p := pred.Any[i].Field.String(); p != "" {
			paths = append(paths, p)
		}
		paths = append(paths, extractPredicatePaths(policy.UnsafePredicate{All: pred.Any[i].All, Any: pred.Any[i].Any})...)
	}
	return paths
}

func hasAnyPath(props map[string]any, paths []string) bool {
	for _, p := range paths {
		if resolvePropertyPath(props, p) != nil {
			return true
		}
	}
	return false
}

func resolvePropertyPath(props map[string]any, dotPath string) any {
	parts := splitDotPath(dotPath)
	var current any = props
	for _, part := range parts {
		m, ok := current.(map[string]any)
		if !ok {
			return nil
		}
		current, ok = m[part]
		if !ok {
			return nil
		}
	}
	return current
}

func splitDotPath(path string) []string {
	path = trimPrefix(path, "properties.")
	var parts []string
	for _, p := range splitOn(path, '.') {
		if p != "" {
			parts = append(parts, p)
		}
	}
	return parts
}

func trimPrefix(s, prefix string) string {
	if len(s) >= len(prefix) && s[:len(prefix)] == prefix {
		return s[len(prefix):]
	}
	return s
}

func splitOn(s string, sep byte) []string {
	var parts []string
	start := 0
	for i := range len(s) {
		if s[i] == sep {
			parts = append(parts, s[start:i])
			start = i + 1
		}
	}
	parts = append(parts, s[start:])
	return parts
}

func filterProperties(props map[string]any, paths []string) map[string]any {
	result := make(map[string]any)
	for _, p := range paths {
		parts := splitDotPath(p)
		val := resolvePropertyPath(props, p)
		if val == nil {
			continue
		}
		setNestedProperty(result, parts, val)
	}
	return result
}

func setNestedProperty(m map[string]any, parts []string, val any) {
	for i, part := range parts {
		if i == len(parts)-1 {
			m[part] = val
			return
		}
		next, ok := m[part].(map[string]any)
		if !ok {
			next = make(map[string]any)
			m[part] = next
		}
		m = next
	}
}
