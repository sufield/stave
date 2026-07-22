package toolmap

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"

	policy "github.com/sufield/stave/internal/core/controldef"
)

// ControlLoaderFunc loads all controls from a root directory.
type ControlLoaderFunc func(rootDir string) ([]policy.ControlDefinition, error)

// Gap describes a tool prerequisite not fully covered by
// chains and controls.
type Gap struct {
	Tool       string   `json:"tool"`
	Capability string   `json:"capability"`
	FieldPath  string   `json:"field_path"`
	HasChain   bool     `json:"has_chain"`
	HasControl bool     `json:"has_control"`
	ChainIDs   []string `json:"chain_ids,omitempty"`
	ControlIDs []string `json:"control_ids,omitempty"`
}

// CoverageResult holds the output of a three-way join.
type CoverageResult struct {
	Covered []Gap `json:"covered"`
	Gaps    []Gap `json:"gaps"`
}

// Analyze performs the three-way join:
//
//	chains × controls × tool prerequisites
//
// For each tool prerequisite, it checks:
//  1. Does any chain's postcondition match the capability?
//  2. Does any control's predicate reference the field path?
//
// A prerequisite with both is "covered". Anything missing is a gap.
func Analyze(registry *Registry, chainsDir string, loadControls ControlLoaderFunc, controlsDir string) (*CoverageResult, error) {
	chains, err := loadChains(chainsDir)
	if err != nil {
		return nil, fmt.Errorf("load chains: %w", err)
	}

	controls, err := loadControls(controlsDir)
	if err != nil {
		return nil, fmt.Errorf("load controls: %w", err)
	}

	capToChains := buildCapabilityIndex(chains)
	fieldToControls := buildFieldIndex(controls)

	var result CoverageResult
	for _, tool := range registry.All() {
		for _, prereq := range tool.Prerequisites {
			chainIDs := capToChains[prereq.Capability]
			controlIDs := fieldToControls[prereq.FieldPath]

			gap := Gap{
				Tool:       tool.Name,
				Capability: prereq.Capability,
				FieldPath:  prereq.FieldPath,
				HasChain:   len(chainIDs) > 0,
				HasControl: len(controlIDs) > 0,
				ChainIDs:   chainIDs,
				ControlIDs: controlIDs,
			}

			if gap.HasChain && gap.HasControl {
				result.Covered = append(result.Covered, gap)
			} else {
				result.Gaps = append(result.Gaps, gap)
			}
		}
	}
	return &result, nil
}

func loadChains(dir string) ([]policy.ChainDefinition, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read dir %s: %w", dir, err)
	}

	var chains []policy.ChainDefinition
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name())) //nolint:gosec // directory entries, not user input
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", e.Name(), err)
		}
		var ch policy.ChainDefinition
		if err := yaml.Unmarshal(data, &ch); err != nil {
			return nil, fmt.Errorf("parse %s: %w", e.Name(), err)
		}
		chains = append(chains, ch)
	}
	return chains, nil
}

// buildCapabilityIndex maps capability tokens to the chain IDs whose
// postconditions include them.
func buildCapabilityIndex(chains []policy.ChainDefinition) map[string][]string {
	idx := make(map[string][]string)
	for i := range chains {
		for _, post := range chains[i].Postconditions {
			idx[post] = append(idx[post], string(chains[i].ID))
		}
	}
	return idx
}

// buildFieldIndex maps property paths to the control IDs whose
// predicates reference them.
func buildFieldIndex(controls []policy.ControlDefinition) map[string][]string {
	idx := make(map[string][]string)
	for i := range controls {
		if controls[i].UnsafePredicate.IsEmpty() {
			continue
		}
		for _, path := range extractFieldPaths(controls[i].UnsafePredicate) {
			idx[path] = append(idx[path], string(controls[i].ID))
		}
	}
	return idx
}

func extractFieldPaths(pred policy.UnsafePredicate) []string {
	seen := make(map[string]struct{})
	var paths []string

	var walk func(rules []policy.PredicateRule)
	walk = func(rules []policy.PredicateRule) {
		for i := range rules {
			walk(rules[i].All)
			walk(rules[i].Any)
			if rules[i].Field.IsZero() {
				continue
			}
			path := rules[i].Field.String()
			if _, dup := seen[path]; !dup {
				seen[path] = struct{}{}
				paths = append(paths, path)
			}
		}
	}
	walk(pred.All)
	walk(pred.Any)
	return paths
}
