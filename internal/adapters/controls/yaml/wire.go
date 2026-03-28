package yaml

import (
	"fmt"

	policy "github.com/sufield/stave/internal/core/controldef"
	"gopkg.in/yaml.v3"
)

// ParsePredicate transforms a generic value (typically a map[string]any) into
// a domain-typed UnsafePredicate using a YAML round-trip.
//
// This is used during evaluation to resolve dynamic or nested predicate nodes
// that arrive as map[string]any from the initial YAML unmarshal. The round-trip
// ensures all yaml tags and Unmarshaler interfaces in the policy package are
// strictly respected.
func ParsePredicate(v any) (*policy.UnsafePredicate, error) {
	if v == nil {
		return nil, nil
	}

	data, err := yaml.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal generic predicate: %w", err)
	}

	var dto yamlUnsafePredicate
	if err := yaml.Unmarshal(data, &dto); err != nil {
		return nil, fmt.Errorf("failed to parse predicate structure: %w", err)
	}

	pred := unsafePredicateToDomain(dto)
	return &pred, nil
}
