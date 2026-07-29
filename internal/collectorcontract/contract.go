// Package collectorcontract loads the embedded collector contract and
// validates observation snapshots against it. The contract defines
// semantic postconditions on pre-computed boolean fields that collectors
// produce and the CEL predicate engine trusts.
package collectorcontract

import (
	_ "embed"
	"fmt"

	"gopkg.in/yaml.v3"
)

//go:embed collector-contract.yaml
var contractData []byte

// Contract is the top-level contract document.
type Contract struct {
	Version string  `yaml:"version"`
	Entries []Entry `yaml:"contracts"`
}

// Entry is a single contracted field with its type, postcondition, and consumers.
type Entry struct {
	Field          string   `yaml:"field"`
	Type           string   `yaml:"type"`
	Postcondition  string   `yaml:"postcondition"`
	HAZOPReference string   `yaml:"hazop_reference,omitempty"`
	Consumers      []string `yaml:"consumers,omitempty"`
}

// Load parses the embedded collector contract.
func Load() (*Contract, error) {
	var c Contract
	if err := yaml.Unmarshal(contractData, &c); err != nil {
		return nil, fmt.Errorf("parse collector contract: %w", err)
	}
	return &c, nil
}

// FieldIndex returns a map from field name to Entry for fast lookup.
func (c *Contract) FieldIndex() map[string]*Entry {
	if c == nil {
		return nil
	}
	idx := make(map[string]*Entry, len(c.Entries))
	for i := range c.Entries {
		idx[c.Entries[i].Field] = &c.Entries[i]
	}
	return idx
}
