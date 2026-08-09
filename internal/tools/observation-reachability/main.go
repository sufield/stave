// observation-reachability checks whether every observation in every fixture
// is evaluated by at least one typed control. Untyped controls (no
// applicable_asset_types) are excluded — they match everything and mask gaps.
//
// Categories:
//
//	REACHABLE:   at least one typed control targets this asset type
//	UNREACHABLE: no typed control targets this asset type (catalog gap)
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type control struct {
	ID                   string   `yaml:"id"`
	ApplicableAssetTypes []string `yaml:"applicable_asset_types"`
}

type asset struct {
	ID   string `json:"id"`
	Type string `json:"type"`
}

type snapshot struct {
	Assets []asset `json:"assets"`
}

type fixtureResult struct {
	dir         string
	reachable   map[string]int // asset type → count
	unreachable map[string]int
}

func loadTypedControlTypes(controlsDir string) (map[string][]string, int, int) {
	// asset type → list of control IDs that target it
	typed := map[string][]string{}
	totalTyped, totalUntyped := 0, 0

	err := filepath.Walk(controlsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		if !strings.HasSuffix(path, ".yaml") {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		var ctl control
		if err := yaml.Unmarshal(data, &ctl); err != nil {
			return nil // skip unparseable
		}
		if ctl.ID == "" {
			return nil
		}
		if len(ctl.ApplicableAssetTypes) == 0 {
			totalUntyped++
			return nil
		}
		totalTyped++
		for _, at := range ctl.ApplicableAssetTypes {
			typed[at] = append(typed[at], ctl.ID)
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "walk controls: %v\n", err)
		os.Exit(4)
	}
	return typed, totalTyped, totalUntyped
}

func findFixtureDirs(labsDir string) []string {
	// leaf directories containing .json files
	seen := map[string]bool{}
	err := filepath.Walk(labsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() && strings.HasSuffix(path, ".json") {
			seen[filepath.Dir(path)] = true
		}
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "walk fixtures: %v\n", err)
		os.Exit(4)
	}
	dirs := make([]string, 0, len(seen))
	for d := range seen {
		dirs = append(dirs, d)
	}
	sort.Strings(dirs)
	return dirs
}

func loadFixtureAssetTypes(dir string) map[string]int {
	types := map[string]int{}
	files, _ := filepath.Glob(filepath.Join(dir, "*.json"))
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		var snap snapshot
		if err := json.Unmarshal(data, &snap); err != nil {
			continue
		}
		for _, a := range snap.Assets {
			if a.Type != "" {
				types[a.Type]++
			}
		}
	}
	return types
}

func main() {
	controlsDir := flag.String("controls", "internal/controls", "path to controls directory")
	fixturesDir := flag.String("fixtures", "internal/fixtures/labs", "path to fixtures directory")
	showUnreachable := flag.Bool("unreachable", false, "show only unreachable types")
	ciGate := flag.Bool("ci", false, "exit non-zero if any unreachable observations exist")
	flag.Parse()

	typedIndex, totalTyped, totalUntyped := loadTypedControlTypes(*controlsDir)
	fmt.Printf("Controls: %d typed, %d untyped (excluded)\n", totalTyped, totalUntyped)
	fmt.Printf("Typed controls cover %d asset types\n\n", len(typedIndex))

	fixtureDirs := findFixtureDirs(*fixturesDir)

	globalReachable := map[string]bool{}
	globalUnreachable := map[string]bool{}
	var results []fixtureResult

	for _, dir := range fixtureDirs {
		assetTypes := loadFixtureAssetTypes(dir)
		r := fixtureResult{
			dir:         dir,
			reachable:   map[string]int{},
			unreachable: map[string]int{},
		}
		for at, count := range assetTypes {
			if _, ok := typedIndex[at]; ok {
				r.reachable[at] = count
				globalReachable[at] = true
			} else {
				r.unreachable[at] = count
				globalUnreachable[at] = true
			}
		}
		results = append(results, r)
	}

	if *showUnreachable {
		types := make([]string, 0, len(globalUnreachable))
		for t := range globalUnreachable {
			types = append(types, t)
		}
		sort.Strings(types)
		fmt.Printf("UNREACHABLE asset types (%d):\n", len(types))
		for _, t := range types {
			fmt.Printf("  %s\n", t)
		}
		return
	}

	// Per-fixture summary
	fixturesWithGaps := 0
	for _, r := range results {
		total := len(r.reachable) + len(r.unreachable)
		if len(r.unreachable) == 0 {
			continue
		}
		fixturesWithGaps++
		rel, _ := filepath.Rel(".", r.dir)
		if rel == "" {
			rel = r.dir
		}
		fmt.Printf("%-70s  %d/%d reachable\n", rel, len(r.reachable), total)
		unreachTypes := make([]string, 0, len(r.unreachable))
		for t := range r.unreachable {
			unreachTypes = append(unreachTypes, t)
		}
		sort.Strings(unreachTypes)
		for _, t := range unreachTypes {
			fmt.Printf("  UNREACHABLE: %s (%d obs)\n", t, r.unreachable[t])
		}
	}

	// Global summary
	totalTypes := len(globalReachable) + len(globalUnreachable)
	pct := 0.0
	if totalTypes > 0 {
		pct = float64(len(globalReachable)) / float64(totalTypes) * 100
	}
	fmt.Printf("\n=== BASELINE ===\n")
	fmt.Printf("Fixture asset types:   %d\n", totalTypes)
	fmt.Printf("Reachable:             %d (%.1f%%)\n", len(globalReachable), pct)
	fmt.Printf("Unreachable:           %d (%.1f%%)\n", len(globalUnreachable), 100-pct)
	fmt.Printf("Fixtures with gaps:    %d / %d\n", fixturesWithGaps, len(fixtureDirs))

	// Categorize unreachable: contextual vs catalog gap
	unreachTypes := make([]string, 0, len(globalUnreachable))
	for t := range globalUnreachable {
		unreachTypes = append(unreachTypes, t)
	}
	sort.Strings(unreachTypes)

	contextual := []string{}
	catalogGap := []string{}
	for _, t := range unreachTypes {
		if isContextual(t) {
			contextual = append(contextual, t)
		} else {
			catalogGap = append(catalogGap, t)
		}
	}

	if len(catalogGap) > 0 {
		fmt.Printf("\nCatalog gaps (%d) — typed controls needed:\n", len(catalogGap))
		for _, t := range catalogGap {
			fmt.Printf("  %s\n", t)
		}
	}
	if len(contextual) > 0 {
		fmt.Printf("\nContextual (%d) — fixture-internal types, not catalog targets:\n", len(contextual))
		for _, t := range contextual {
			fmt.Printf("  %s\n", t)
		}
	}

	if *ciGate && len(globalUnreachable) > 0 {
		os.Exit(3)
	}
}

// ponytail: simple heuristic — refine list as catalog grows
func isContextual(assetType string) bool {
	contextualPrefixes := []string{
		"DEFAULT",
		"Private",
	}
	for _, p := range contextualPrefixes {
		if strings.HasPrefix(assetType, p) {
			return true
		}
	}
	return false
}
