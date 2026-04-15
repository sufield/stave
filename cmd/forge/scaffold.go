package forge

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/spf13/cobra"

	ctlyaml "github.com/sufield/stave/internal/adapters/controls/yaml"
	"github.com/sufield/stave/internal/adapters/observations"
	"github.com/sufield/stave/internal/core/asset"
	policy "github.com/sufield/stave/internal/core/controldef"
)

func newScaffoldCmd() *cobra.Command {
	var controlPath, snapshotPath, outDir string

	cmd := &cobra.Command{
		Use:   "scaffold",
		Short: "Generate test fixtures from a real snapshot",
		Long: `Generate minimal pass and fail fixture files for use with
stave forge test. Extracts only properties referenced by the
control's predicate.

Exit Codes:
  0   Fixtures generated
  2   Invalid input
  4   Internal error`,
		Example: `  stave forge scaffold \
    --control controls/ad/CTL.AD.PASS.MINLEN.001.yaml \
    --snapshot snapshots/acme-dc.json`,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runScaffold(cmd.OutOrStdout(), controlPath, snapshotPath, outDir)
		},
	}

	cmd.Flags().StringVar(&controlPath, "control", "", "path to control YAML file (required)")
	cmd.Flags().StringVar(&snapshotPath, "snapshot", "", "path to snapshot file (required)")
	cmd.Flags().StringVar(&outDir, "out-dir", "", "output directory (default: testdata/<control_id>/)")
	_ = cmd.MarkFlagRequired("control")
	_ = cmd.MarkFlagRequired("snapshot")

	return cmd
}

func runScaffold(w io.Writer, controlPath, snapshotPath, outDir string) error {
	// Load control.
	data, err := os.ReadFile(controlPath) //nolint:gosec // user path
	if err != nil {
		return fmt.Errorf("read control: %w", err)
	}
	ctl, err := ctlyaml.UnmarshalControlDefinition(data)
	if err != nil {
		return fmt.Errorf("parse control: %w", err)
	}

	// Load snapshot.
	snaps, err := observations.LoadBundle(snapshotPath)
	if err != nil {
		return fmt.Errorf("load snapshot: %w", err)
	}
	if len(snaps) == 0 {
		return fmt.Errorf("no snapshots in %s", snapshotPath)
	}
	snap := snaps[len(snaps)-1]

	// Extract property paths from predicate.
	paths := extractPredicatePaths(ctl.UnsafePredicate)

	// Find matching assets.
	var matchingAssets []asset.Asset
	for i := range snap.Assets {
		if hasAnyPath(snap.Assets[i].Properties, paths) {
			matchingAssets = append(matchingAssets, snap.Assets[i])
		}
	}
	if len(matchingAssets) == 0 {
		fmt.Fprintf(w, "No assets match predicate paths in snapshot. Using empty fixture.\n")
		matchingAssets = []asset.Asset{{
			ID:         "fixture-asset",
			Properties: map[string]any{},
		}}
	}

	// Determine output directory.
	if outDir == "" {
		outDir = filepath.Join("testdata", string(ctl.ID))
	}
	if mkErr := os.MkdirAll(outDir, 0o750); mkErr != nil {
		return fmt.Errorf("create dir: %w", mkErr)
	}

	// Build fixture resources.
	var resources []fixtureResource
	for _, a := range matchingAssets {
		filtered := filterProperties(a.Properties, paths)
		resources = append(resources, fixtureResource{
			AssetID:    string(a.ID),
			Properties: filtered,
		})
	}

	fixture := fixtureFile{Resources: resources}

	// Write pass fixture (as-is from snapshot).
	passPath := filepath.Join(outDir, "fixture-pass.json")
	if writeErr := writeFixtureFile(passPath, fixture); writeErr != nil {
		return writeErr
	}
	fmt.Fprintf(w, "Wrote %s\n", passPath)

	// Write fail fixture (same structure, empty properties for manual editing).
	failResources := make([]fixtureResource, len(resources))
	for i, r := range resources {
		failResources[i] = fixtureResource{
			AssetID:    r.AssetID,
			Properties: map[string]any{},
		}
	}
	failPath := filepath.Join(outDir, "fixture-fail.json")
	if writeErr := writeFixtureFile(failPath, fixtureFile{Resources: failResources}); writeErr != nil {
		return writeErr
	}
	fmt.Fprintf(w, "Wrote %s\n", failPath)
	fmt.Fprintf(w, "Edit %s to set property values that trigger the control.\n", failPath)

	return nil
}

func writeFixtureFile(path string, f fixtureFile) error {
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal fixture: %w", err)
	}
	return os.WriteFile(path, append(data, '\n'), 0o644) //nolint:gosec // user file
}

// extractPredicatePaths extracts property field paths from a predicate.
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

// hasAnyPath checks if properties contain any of the given dot-separated paths.
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
	// Strip "properties." prefix if present (predicates use it).
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

// filterProperties returns only properties at the given paths.
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
