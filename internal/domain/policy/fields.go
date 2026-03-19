package policy

// resolvePropertyValue looks up a field path in asset properties.
// If the path starts with "properties", the prefix is stripped.
// Otherwise the full path is used as a property key chain.
// Used by evidence extraction (collectFields) only.
func resolvePropertyValue(props map[string]any, parts []string) (any, bool) {
	if len(parts) == 0 {
		return nil, false
	}
	if parts[0] == "properties" {
		return getNestedValue(props, parts[1:])
	}
	return getNestedValue(props, parts)
}

// getNestedValue performs a recursive lookup in nested maps.
func getNestedValue(props map[string]any, parts []string) (any, bool) {
	if props == nil || len(parts) == 0 {
		return nil, false
	}

	var current any = props
	for _, part := range parts {
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
		default:
			return nil, false
		}
	}
	return current, true
}
