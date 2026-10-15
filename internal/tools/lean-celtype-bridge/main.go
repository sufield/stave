// Command lean-celtype-bridge exports the Stave catalog as JSONL for
// the Lean 4 CEL type system bridge checker.
//
// Emits four record kinds to stdout:
//   - catalog_summary: aggregate counts (controls, asset types, operators)
//   - control: per-control identity + predicate field paths
//   - contract_field: per-field from collector-contract.yaml
//   - capability: per-capability with chain reference count
//
// Usage: go run ./internal/tools/lean-celtype-bridge > bridge.jsonl
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

type catalogSummary struct {
	Kind           string `json:"kind"`
	ControlCount   int    `json:"control_count"`
	AssetTypeCount int    `json:"asset_type_count"`
	OperatorCount  int    `json:"operator_count"`
}

type controlRecord struct {
	Kind              string   `json:"kind"`
	ID                string   `json:"id"`
	Severity          string   `json:"severity"`
	Type              string   `json:"type"`
	Classification    string   `json:"classification"`
	AssetTypes        []string `json:"asset_types"`
	FieldPaths        []string `json:"field_paths"`
	ObservationFields []string `json:"observation_fields"`
}

type contractFieldRecord struct {
	Kind          string   `json:"kind"`
	Path          string   `json:"path"`
	FieldType     string   `json:"type"`
	ConsumerCount int      `json:"consumer_count"`
	Consumers     []string `json:"consumers"`
}

type capabilityRecord struct {
	Kind       string `json:"kind"`
	Name       string `json:"name"`
	ChainCount int    `json:"chain_count"`
}

type controlYAML struct {
	ID                   string            `yaml:"id"`
	Severity             string            `yaml:"severity"`
	Type                 string            `yaml:"type"`
	Classification       string            `yaml:"classification"`
	ApplicableAssetTypes []string          `yaml:"applicable_asset_types"`
	ObservationFields    []string          `yaml:"observation_fields"`
	UnsafePredicate      predicateYAML     `yaml:"unsafe_predicate"`
}

type predicateYAML struct {
	Any []ruleYAML `yaml:"any"`
	All []ruleYAML `yaml:"all"`
}

type ruleYAML struct {
	Field string     `yaml:"field"`
	Op    string     `yaml:"op"`
	Any   []ruleYAML `yaml:"any"`
	All   []ruleYAML `yaml:"all"`
}

type contractEntry struct {
	Field     string   `yaml:"field"`
	Type      string   `yaml:"type"`
	Consumers []string `yaml:"consumers"`
}

type contractFile struct {
	Contracts []contractEntry `yaml:"contracts"`
}

type chainYAML struct {
	Preconditions  []string `yaml:"preconditions"`
	Postconditions []string `yaml:"postconditions"`
}

func extractFieldPaths(rules []ruleYAML) []string {
	var paths []string
	for _, r := range rules {
		if r.Field != "" {
			paths = append(paths, r.Field)
		}
		paths = append(paths, extractFieldPaths(r.Any)...)
		paths = append(paths, extractFieldPaths(r.All)...)
	}
	return paths
}

func main() {
	controlsDir := "internal/controls"
	contractPath := "data/collector-contract.yaml"
	chainsDir := "internal/chains"

	// Walk controls
	assetTypes := map[string]bool{}
	operators := map[string]bool{}
	var controls []controlRecord

	err := filepath.Walk(controlsDir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == "_triage" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".yaml" || strings.HasPrefix(info.Name(), "_") {
			return nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		var ctl controlYAML
		if err := yaml.Unmarshal(data, &ctl); err != nil {
			return nil
		}
		if ctl.ID == "" {
			return nil
		}

		fieldPaths := extractFieldPaths(ctl.UnsafePredicate.Any)
		fieldPaths = append(fieldPaths, extractFieldPaths(ctl.UnsafePredicate.All)...)

		// collect operators
		collectOps(ctl.UnsafePredicate.Any, operators)
		collectOps(ctl.UnsafePredicate.All, operators)

		for _, at := range ctl.ApplicableAssetTypes {
			assetTypes[at] = true
		}

		controls = append(controls, controlRecord{
			Kind:              "control",
			ID:                ctl.ID,
			Severity:          ctl.Severity,
			Type:              ctl.Type,
			Classification:    ctl.Classification,
			AssetTypes:        ctl.ApplicableAssetTypes,
			FieldPaths:        fieldPaths,
			ObservationFields: ctl.ObservationFields,
		})
		return nil
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "walk controls: %v\n", err)
		os.Exit(1)
	}

	sort.Slice(controls, func(i, j int) bool {
		return controls[i].ID < controls[j].ID
	})

	// Parse contract
	var contractFields []contractFieldRecord
	contractData, err := os.ReadFile(contractPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "read contract: %v\n", err)
		os.Exit(1)
	}
	var cf contractFile
	if err := yaml.Unmarshal(contractData, &cf); err != nil {
		fmt.Fprintf(os.Stderr, "parse contract: %v\n", err)
		os.Exit(1)
	}
	for _, e := range cf.Contracts {
		contractFields = append(contractFields, contractFieldRecord{
			Kind:          "contract_field",
			Path:          e.Field,
			FieldType:     e.Type,
			ConsumerCount: len(e.Consumers),
			Consumers:     e.Consumers,
		})
	}

	// Parse chains for capability references
	capChainCount := map[string]int{}
	if entries, err := os.ReadDir(chainsDir); err == nil {
		for _, e := range entries {
			if filepath.Ext(e.Name()) != ".yaml" {
				continue
			}
			data, err := os.ReadFile(filepath.Join(chainsDir, e.Name()))
			if err != nil {
				continue
			}
			var ch chainYAML
			if err := yaml.Unmarshal(data, &ch); err != nil {
				continue
			}
			for _, cap := range ch.Preconditions {
				capChainCount[cap]++
			}
			for _, cap := range ch.Postconditions {
				capChainCount[cap]++
			}
		}
	}

	// Write JSONL
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)

	// Summary
	enc.Encode(catalogSummary{
		Kind:           "catalog_summary",
		ControlCount:   len(controls),
		AssetTypeCount: len(assetTypes),
		OperatorCount:  len(operators),
	})

	// Controls
	for _, c := range controls {
		enc.Encode(c)
	}

	// Contract fields
	for _, f := range contractFields {
		enc.Encode(f)
	}

	// Capabilities
	caps := make([]string, 0, len(capChainCount))
	for k := range capChainCount {
		caps = append(caps, k)
	}
	sort.Strings(caps)
	for _, name := range caps {
		enc.Encode(capabilityRecord{
			Kind:       "capability",
			Name:       name,
			ChainCount: capChainCount[name],
		})
	}
}

func collectOps(rules []ruleYAML, ops map[string]bool) {
	for _, r := range rules {
		if r.Op != "" {
			ops[r.Op] = true
		}
		collectOps(r.Any, ops)
		collectOps(r.All, ops)
	}
}
