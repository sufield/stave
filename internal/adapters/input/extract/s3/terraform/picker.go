package terraform

import (
	"encoding/json"
)

// MapPicker provides type-safe access to map[string]any values.
type MapPicker struct {
	data map[string]any
}

func newMapPicker(data map[string]any) *MapPicker {
	if data == nil {
		return &MapPicker{data: map[string]any{}}
	}
	return &MapPicker{data: data}
}

func (p *MapPicker) String(key string) string {
	if p == nil {
		return ""
	}
	if v, ok := p.data[key].(string); ok {
		return v
	}
	return ""
}

func (p *MapPicker) Bool(key string) bool {
	if p == nil {
		return false
	}
	if v, ok := p.data[key].(bool); ok {
		return v
	}
	return false
}

func (p *MapPicker) Int(key string) int {
	if p == nil {
		return 0
	}
	switch v := p.data[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case json.Number:
		i, err := v.Int64()
		if err == nil {
			return int(i)
		}
	}
	return 0
}

func (p *MapPicker) StringMap(key string) map[string]string {
	result := make(map[string]string)
	if p == nil {
		return result
	}
	tagMap, ok := p.data[key].(map[string]any)
	if !ok {
		return result
	}
	for k, v := range tagMap {
		if s, ok := v.(string); ok {
			result[k] = s
		}
	}
	return result
}

// Dig enters a Terraform nested block at index 0 (e.g. rule[0].expiration[0]).
func (p *MapPicker) Dig(key string) *MapPicker {
	if p == nil {
		return newMapPicker(nil)
	}
	raw, ok := p.data[key].([]any)
	if !ok || len(raw) == 0 {
		return newMapPicker(nil)
	}
	child, ok := raw[0].(map[string]any)
	if !ok {
		return newMapPicker(nil)
	}
	return newMapPicker(child)
}

func (p *MapPicker) IsEmpty() bool {
	return p == nil || len(p.data) == 0
}

func (p *MapPicker) AnySlice(key string) []any {
	if p == nil {
		return nil
	}
	if out, ok := p.data[key].([]any); ok {
		return out
	}
	return nil
}

func getString(m map[string]any, key string) string {
	return newMapPicker(m).String(key)
}
