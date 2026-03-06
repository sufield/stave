// Package testutil provides test helpers that bridge adapter-layer dependencies
// for domain-layer tests without leaking external imports into the domain.
package testutil

import (
	"github.com/sufield/stave/internal/domain/policy"
	"gopkg.in/yaml.v3"
)

// YAMLPredicateParser returns a YAML-based nested predicate parser function
// suitable for use in tests that exercise any_match controls.
func YAMLPredicateParser() func(any) (*policy.UnsafePredicate, error) {
	return func(v any) (*policy.UnsafePredicate, error) {
		data, err := yaml.Marshal(v)
		if err != nil {
			return nil, err
		}
		var pred policy.UnsafePredicate
		if err := yaml.Unmarshal(data, &pred); err != nil {
			return nil, err
		}
		return &pred, nil
	}
}
