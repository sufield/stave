package controldef

// resolvePropertyValue looks up a field path in asset properties.
// If the path starts with "properties", the prefix is stripped.
// A path of just ["properties"] returns the entire property map.
func resolvePropertyValue(props map[string]any, parts []string) (any, bool) {
	if len(parts) == 0 {
		return nil, false
	}
	if parts[0] == "properties" {
		if len(parts) == 1 {
			return props, true
		}
		return getNestedValue(props, parts[1:])
	}
	return getNestedValue(props, parts)
}

// getNestedValue performs an iterative lookup through nested maps.
// Handles map[string]any, map[string]string, and map[any]any
// (the latter appears in some YAML decoders).
func getNestedValue(data any, parts []string) (any, bool) {
	if len(parts) == 0 {
		return data, true
	}

	current := data
	for _, part := range parts {
		if current == nil {
			return nil, false
		}
		switch m := current.(type) {
		case map[string]any:
			val, ok := m[part]
			if !ok {
				return nil, false
			}
			current = val
		case map[string]string:
			val, ok := m[part]
			if !ok {
				return nil, false
			}
			current = val
		case map[any]any:
			val, ok := m[part]
			if !ok {
				return nil, false
			}
			current = val
		default:
			return nil, false
		}
	}
	return current, true
}
