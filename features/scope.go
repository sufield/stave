// Package features holds the versioned out-of-scope manifest for Stave
// and parses it. The in-scope half of `stave features` is discovered
// dynamically from the live registries (see cmd/features); only the
// deliberately-out-of-scope declarations are versioned here so they are
// reviewed in PRs alongside code changes.
package features

import (
	_ "embed"
	"fmt"

	"gopkg.in/yaml.v3"
)

//go:embed scope.yaml
var scopeYAML []byte

// OutOfScopeEntry is one deliberately-excluded capability.
type OutOfScopeEntry struct {
	ID           string   `yaml:"id"           json:"id"`
	Label        string   `yaml:"label"        json:"label"`
	Reason       string   `yaml:"reason"       json:"reason"`
	Alternatives []string `yaml:"alternatives" json:"alternatives"`
	// Forbids lists CLI command names (at any depth of the command
	// tree) that would re-introduce this out-of-scope capability. The
	// scope-drift lint (cmd/features_scope_lint_test.go) fails if any
	// of these names is registered. Empty when the capability has no
	// command-name guard (it is enforced by other means, e.g. the
	// air-gap policy for credential_management). It is a lint-internal
	// detail, so it is omitted from the `stave features` JSON output.
	Forbids []string `yaml:"forbids" json:"-"`
}

type scopeDoc struct {
	OutOfScope []OutOfScopeEntry `yaml:"out_of_scope"`
}

// OutOfScope returns the parsed out-of-scope manifest in declared order.
// It parses embedded data, so it cannot fail at runtime in a built
// binary; a malformed manifest is caught by the package test.
func OutOfScope() ([]OutOfScopeEntry, error) {
	var doc scopeDoc
	if err := yaml.Unmarshal(scopeYAML, &doc); err != nil {
		return nil, fmt.Errorf("parse embedded features/scope.yaml: %w", err)
	}
	return doc.OutOfScope, nil
}

// OutOfScopeIDs returns just the ids, for the CI lint that blocks a PR
// adding a capability whose name collides with an out-of-scope id.
func OutOfScopeIDs() ([]string, error) {
	entries, err := OutOfScope()
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(entries))
	for i, e := range entries {
		ids[i] = e.ID
	}
	return ids, nil
}
