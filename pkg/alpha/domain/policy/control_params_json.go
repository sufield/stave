package policy

import "encoding/json"

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
