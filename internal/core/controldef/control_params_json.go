package controldef

import (
	"bytes"
	"encoding/json"
)

// UnmarshalJSON decodes JSON into the inner map.
// Handles null by clearing the map. Uses atomic assignment to avoid
// leaving the map in an inconsistent state on decode failure.
func (p *ControlParams) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		p.m = nil
		return nil
	}
	var temp map[string]any
	if err := json.Unmarshal(data, &temp); err != nil {
		return err
	}
	p.m = temp
	return nil
}

// MarshalJSON encodes the inner map to JSON.
// A nil map produces "{}" instead of "null" for predictable output.
func (p ControlParams) MarshalJSON() ([]byte, error) {
	if p.m == nil {
		return []byte("{}"), nil
	}
	return json.Marshal(p.m)
}
