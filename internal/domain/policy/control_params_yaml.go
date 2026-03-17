package policy

import (
	"encoding/json"

	"gopkg.in/yaml.v3"
)

// UnmarshalYAML decodes a YAML mapping into the inner map.
func (p *ControlParams) UnmarshalYAML(node *yaml.Node) error {
	var m map[string]any
	if err := node.Decode(&m); err != nil {
		return err
	}
	p.m = m
	return nil
}

// MarshalYAML returns the inner map for YAML encoding.
func (p ControlParams) MarshalYAML() (any, error) { return p.m, nil }

// UnmarshalJSON decodes JSON into the inner map.
func (p *ControlParams) UnmarshalJSON(data []byte) error {
	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return err
	}
	p.m = m
	return nil
}

// MarshalJSON encodes the inner map to JSON.
func (p ControlParams) MarshalJSON() ([]byte, error) { return json.Marshal(p.m) }
