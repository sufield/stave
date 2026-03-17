// Package testutil provides test helpers that bridge adapter-layer dependencies
// for domain-layer tests without leaking external imports into the domain.
package testutil

import (
	controlyaml "github.com/sufield/stave/internal/adapters/input/controls/yaml"
	"github.com/sufield/stave/internal/domain/policy"
)

// YAMLPredicateParser returns a YAML-based nested predicate parser function
// suitable for use in tests that exercise any_match controls.
func YAMLPredicateParser() func(any) (*policy.UnsafePredicate, error) {
	return controlyaml.ParsePredicate
}
