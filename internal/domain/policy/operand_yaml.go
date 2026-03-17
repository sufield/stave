package policy

import "gopkg.in/yaml.v3"

// UnmarshalYAML decodes a YAML node into the Operand's raw value.
func (o *Operand) UnmarshalYAML(node *yaml.Node) error {
	var v any
	if err := node.Decode(&v); err != nil {
		return err
	}
	o.raw = v
	return nil
}

// MarshalYAML returns the raw value for YAML encoding.
func (o Operand) MarshalYAML() (any, error) { return o.raw, nil }
