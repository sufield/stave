package controldef

import (
	"errors"
	"fmt"

	"github.com/sufield/stave/internal/core/kernel"
)

// ChainDefinition describes a safety chain — a set of controls whose
// co-failure creates a compound risk greater than the sum of individual
// findings. When the number of failing controls meets the escalation
// threshold, the chain engine emits a compound finding.
type ChainDefinition struct {
	ID                  kernel.ChainID     `yaml:"id"                  json:"id"`
	Description         string             `yaml:"description"         json:"description"`
	ControlIDs          []kernel.ControlID `yaml:"controls"            json:"controls"`
	EscalationThreshold int                `yaml:"escalation_threshold" json:"escalation_threshold"`
	CompoundSeverity    Severity           `yaml:"compound_severity"   json:"compound_severity"`
	Preconditions       []string           `yaml:"preconditions,omitempty"  json:"preconditions,omitempty"`
	Postconditions      []string           `yaml:"postconditions,omitempty" json:"postconditions,omitempty"`

	// ScopeField is the optional property path used to group failing
	// controls before threshold detection. When empty (the default),
	// chains group by asset.ID — the legacy behaviour. When set
	// (e.g. "properties.identity.cognito.user_pool_id"), the chain
	// engine resolves the value at that path on each failing asset and
	// uses it as the grouping key. Two failing controls on different
	// asset.IDs that share a scope value count as co-failures on the
	// same logical scope.
	//
	// Use this when a chain's member predicates force one logical
	// resource to surface as multiple Stave assets (e.g., per-trigger
	// Cognito ghost predicates). Each Lambda trigger fires on its own
	// asset.ID, but the chain semantically lives at the user-pool
	// level — scope_field reunites them.
	ScopeField string `yaml:"scope_field,omitempty" json:"scope_field,omitempty"`
}

// CapabilityRegistry is the contract for resolving whether a capability
// string belongs to the closed vocabulary the catalog has registered.
// Core owns the contract; the catalog layer (internal/builtin/) owns
// the data.
type CapabilityRegistry interface {
	IsValid(capability string) bool
}

// CapabilitySet is the standard string-set implementation of
// CapabilityRegistry. The catalog layer constructs one from its
// capability list and passes it into chain validation.
type CapabilitySet map[string]struct{}

// IsValid reports whether the capability string is in the set.
func (s CapabilitySet) IsValid(capability string) bool {
	_, ok := s[capability]
	return ok
}

// Validate performs structural validation on the chain definition: ID
// presence, control count, threshold sanity. Capability vocabulary is
// validated separately via ValidateCapabilities so the engine does not
// need to know the catalog's vocabulary.
func (c *ChainDefinition) Validate() error {
	if c.ID == "" {
		return errors.New("chain: missing id")
	}
	if len(c.ControlIDs) < 2 {
		return fmt.Errorf("chain %s: requires at least 2 controls", c.ID)
	}
	if c.EscalationThreshold < 1 {
		return fmt.Errorf("chain %s: escalation_threshold must be >= 1", c.ID)
	}
	if c.EscalationThreshold > len(c.ControlIDs) {
		return fmt.Errorf("chain %s: escalation_threshold (%d) > control count (%d)",
			c.ID, c.EscalationThreshold, len(c.ControlIDs))
	}
	return nil
}

// ValidateCapabilities checks that every precondition and postcondition
// string is present in the supplied registry. Loaders call this after
// Validate to reject typos and undeclared capabilities.
func (c *ChainDefinition) ValidateCapabilities(registry CapabilityRegistry) error {
	if registry == nil {
		return nil
	}
	for _, cap := range c.Preconditions {
		if !registry.IsValid(cap) {
			return fmt.Errorf("chain %s: unknown precondition capability %q", c.ID, cap)
		}
	}
	for _, cap := range c.Postconditions {
		if !registry.IsValid(cap) {
			return fmt.Errorf("chain %s: unknown postcondition capability %q", c.ID, cap)
		}
	}
	return nil
}

// ChainRefIssue records one chain that references controls missing
// from the catalog passed to [ValidateChainRefs]. Consumers format
// the list into user-facing warnings or errors.
type ChainRefIssue struct {
	ChainID        kernel.ChainID
	MissingControl []kernel.ControlID
}

// ValidateChainRefs cross-checks every chain's control references
// against the provided catalog. The returned slice has one entry
// per chain that references at least one control not present in
// catalog; chains with all references present produce no entry.
//
// Callers decide whether the result is fatal (strict validation)
// or advisory (runtime profile filtering). The function itself
// makes no policy choice — it returns data.
func ValidateChainRefs(chains []ChainDefinition, catalog []ControlDefinition) []ChainRefIssue {
	if len(chains) == 0 {
		return nil
	}
	known := make(map[kernel.ControlID]struct{}, len(catalog))
	for i := range catalog {
		known[catalog[i].ID] = struct{}{}
	}
	var issues []ChainRefIssue
	for i := range chains {
		chain := &chains[i]
		var missing []kernel.ControlID
		for _, ref := range chain.ControlIDs {
			if _, ok := known[ref]; !ok {
				missing = append(missing, ref)
			}
		}
		if len(missing) > 0 {
			issues = append(issues, ChainRefIssue{
				ChainID:        chain.ID,
				MissingControl: missing,
			})
		}
	}
	return issues
}
