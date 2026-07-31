package prove

import (
	"embed"
	"fmt"

	"gopkg.in/yaml.v3"
)

//go:embed proof-mappings.yaml
var proofMappingsFS embed.FS

// ProofMappings is the top-level structure of the compliance mapping file.
type ProofMappings struct {
	Properties map[string]PropertyMapping `yaml:"properties"`
}

// PropertyMapping maps one proof property to its compliance requirements.
type PropertyMapping struct {
	Description string                          `yaml:"description"`
	Mappings    map[string][]MappingRequirement `yaml:"mappings"`
}

// MappingRequirement is one regulatory requirement satisfied by a proof.
type MappingRequirement struct {
	ID          string `yaml:"id"`
	Description string `yaml:"description"`
}

// LoadProofMappings reads the embedded compliance mapping file.
func LoadProofMappings() (*ProofMappings, error) {
	data, err := proofMappingsFS.ReadFile("proof-mappings.yaml")
	if err != nil {
		return nil, fmt.Errorf("read embedded proof-mappings.yaml: %w", err)
	}
	var m ProofMappings
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parse proof-mappings.yaml: %w", err)
	}
	return &m, nil
}
