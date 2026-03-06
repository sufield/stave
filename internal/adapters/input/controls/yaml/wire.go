package yaml

import (
	"github.com/sufield/stave/internal/domain/policy"
	"gopkg.in/yaml.v3"
)

// YAMLPredicateParser re-marshals an arbitrary value through YAML to produce
// a typed UnsafePredicate. This is used at evaluation time (policy/rule.go)
// to parse nested predicate nodes that arrive as map[string]any from the
// initial YAML unmarshal.
func YAMLPredicateParser(v any) (*policy.UnsafePredicate, error) {
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
