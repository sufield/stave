package resource

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/samber/lo"
)

func ContainsSubstring(values []string, target string) bool {
	return lo.SomeBy(values, func(v string) bool { return strings.Contains(v, target) })
}

// ToMap marshals a typed model into map[string]any for asset.Asset.Properties.
func ToMap(v any) map[string]any {
	data, err := json.Marshal(v)
	if err != nil {
		return map[string]any{}
	}

	var out map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if err := decoder.Decode(&out); err != nil {
		return map[string]any{}
	}
	return normalizeNumbers(out).(map[string]any)
}

func normalizeNumbers(v any) any {
	switch typed := v.(type) {
	case map[string]any:
		for key, child := range typed {
			typed[key] = normalizeNumbers(child)
		}
		return typed
	case []any:
		for i, child := range typed {
			typed[i] = normalizeNumbers(child)
		}
		return typed
	case json.Number:
		if intVal, err := typed.Int64(); err == nil {
			return int(intVal)
		}
		if floatVal, err := typed.Float64(); err == nil {
			return floatVal
		}
	}
	return v
}
