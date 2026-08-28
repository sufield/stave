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

	// Scope controls how failing controls are grouped before threshold
	// detection. When empty or "asset" (the default), chains group by
	// asset.ID. When "global", all failures for the chain land in one
	// bucket regardless of which asset they came from — use this for
	// cross-asset chains whose member controls target different asset
	// types (e.g. shadow infrastructure chains where an SCP control
	// fires on aws_organization while a service control fires on
	// aws_account).
	Scope ChainScope `yaml:"scope,omitempty" json:"scope,omitempty"`

	// ScopeField is the optional property path used to group failing
	// controls before threshold detection. When empty (the default),
	// chains group by asset.ID — the legacy behaviour. When set
	// (e.g. "properties.identity.cognito.user_pool_id"), the chain
	// engine resolves the value at that path on each failing asset and
	// uses it as the grouping key. Two failing controls on different
	// asset.IDs that share a scope value count as co-failures on the
	// same logical scope. Ignored when Scope is "global".
	//
	// Use this when a chain's member predicates force one logical
	// resource to surface as multiple Stave assets (e.g., per-trigger
	// Cognito ghost predicates). Each Lambda trigger fires on its own
	// asset.ID, but the chain semantically lives at the user-pool
	// level — scope_field reunites them.
	ScopeField string `yaml:"scope_field,omitempty" json:"scope_field,omitempty"`

	// ImplicitDependencies declares computations this chain's correctness
	// depends on that are not member controls. The Fallback field on each
	// entry determines evaluator behavior when the dependency has not run.
	ImplicitDependencies []ImplicitDependency `yaml:"implicit_dependencies,omitempty" json:"implicit_dependencies,omitempty"`

	// Complexity classifies how difficult the chain is to exploit.
	// Human-authored per chain; validated by lint.
	Complexity          ChainComplexity `yaml:"complexity,omitempty"           json:"complexity,omitempty"`
	ComplexityRationale string          `yaml:"complexity_rationale,omitempty" json:"complexity_rationale,omitempty"`

	// CompensatingControls lists controls that, when passing, reduce
	// the chain's exploitability even if all member controls fail.
	CompensatingControls []CompensatingControl `yaml:"compensating_controls,omitempty" json:"compensating_controls,omitempty"`

	// IncidentPrecedent records a real-world breach that this chain models.
	IncidentPrecedent *IncidentPrecedent `yaml:"incident_precedent,omitempty" json:"incident_precedent,omitempty"`
}

// IncidentPrecedent records a named real-world incident that a chain models.
type IncidentPrecedent struct {
	Name      string `yaml:"name"      json:"name"`
	Impact    string `yaml:"impact"    json:"impact"`
	Reference string `yaml:"reference" json:"reference"`
}

// ChainScope controls how failing controls are grouped before
// threshold detection.
type ChainScope string

const (
	// ScopeAsset groups by asset.ID (the default when empty).
	ScopeAsset ChainScope = "asset"

	// ScopeGlobal puts all failures in one bucket, enabling
	// cross-asset-type chains.
	ScopeGlobal ChainScope = "global"

	// ScopeAccount groups by account_id, enabling cross-asset-type
	// chains that must fire within a single account. Observations
	// without account_id are not evaluable and never join any group.
	ScopeAccount ChainScope = "account"
)

// IsGlobal reports whether the chain uses global (cross-asset) grouping.
func (s ChainScope) IsGlobal() bool { return s == ScopeGlobal }

// IsAccount reports whether the chain uses account-level grouping.
func (s ChainScope) IsAccount() bool { return s == ScopeAccount }

// ChainComplexity classifies how difficult a chain is to exploit.
type ChainComplexity string

const (
	// ComplexityAutomated means exploitation can be fully automated
	// with known tooling (Stratus Red Team, Pacu). No application
	// vulnerability required.
	ComplexityAutomated ChainComplexity = "automated"

	// ComplexityManual means exploitation requires manual steps:
	// lateral movement, social engineering, multi-step credential
	// theft.
	ComplexityManual ChainComplexity = "manual"

	// ComplexityDependent means exploitation requires a precondition
	// outside the configuration snapshot (an application vulnerability,
	// a compromised insider, a supply chain attack).
	ComplexityDependent ChainComplexity = "dependent"
)

// IsValid reports whether the complexity is one of the recognized values.
func (c ChainComplexity) IsValid() bool {
	switch c {
	case ComplexityAutomated, ComplexityManual, ComplexityDependent:
		return true
	default:
		return false
	}
}

// CompensatingControl declares a control that, when passing, reduces
// the chain's exploitability.
type CompensatingControl struct {
	ControlID string             `yaml:"control_id" json:"control_id"`
	Effect    CompensatingEffect `yaml:"effect"     json:"effect"`
	Rationale string             `yaml:"rationale"  json:"rationale"`
}

// CompensatingEffect determines how a passing compensating control
// modifies chain exploitability.
type CompensatingEffect string

const (
	EffectDowngrade CompensatingEffect = "downgrades_to_one_away"
	EffectBlocks    CompensatingEffect = "blocks_path"
)

// IsValid reports whether the effect is recognized.
func (e CompensatingEffect) IsValid() bool {
	return e == EffectDowngrade || e == EffectBlocks
}

// ImplicitDependency declares a computation this chain's correctness
// depends on that is not a member control. The Fallback field
// determines evaluator behavior when the dependency has not run.
type ImplicitDependency struct {
	// Source identifies the upstream computation.
	// Convention: dot-separated path matching the internal package
	// structure — e.g. "observation.sensitivity_classifier",
	// "reasoning.souffle.reachable_resource".
	Source string `yaml:"source" json:"source"`

	// Fallback determines behavior when the dependency has not run
	// or produced no output.
	Fallback DependencyFallback `yaml:"fallback" json:"fallback"`

	// Diagnostic is the human-readable message emitted when the
	// fallback fires. Required for fail_closed and cross_validate.
	Diagnostic string `yaml:"diagnostic" json:"diagnostic"`
}

// DependencyFallback controls what happens when an implicit dependency
// has not run or produced no output.
type DependencyFallback string

const (
	// FallbackFailClosed demotes exploitability to one_away and
	// attaches the diagnostic.
	FallbackFailClosed DependencyFallback = "fail_closed"

	// FallbackFailOpen evaluates as if the dependency is satisfied.
	// Exists so accidental fail-open can be declared rather than silent.
	FallbackFailOpen DependencyFallback = "fail_open"

	// FallbackCrossValidate fires the chain but emits a divergence
	// diagnostic if two sources disagree.
	FallbackCrossValidate DependencyFallback = "cross_validate"
)

// DependencyResolver answers whether an implicit dependency's upstream
// computation has run and produced output for this evaluation.
// Implementations live in the evaluation workflow; the chain engine
// consumes the interface.
type DependencyResolver interface {
	Status(source string) DependencyStatus
}

// DependencyStatus represents the resolution state of an implicit dependency.
type DependencyStatus int

const (
	DependencyUnknown  DependencyStatus = iota // resolver doesn't recognize the source
	DependencyNotRun                           // recognized but has not executed
	DependencyRanEmpty                         // executed but produced zero facts
	DependencyRanOK                            // executed and produced facts
)

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
	if c.Scope != "" && c.Scope != ScopeAsset && c.Scope != ScopeGlobal && c.Scope != ScopeAccount {
		return fmt.Errorf("chain %s: invalid scope %q (must be \"asset\", \"global\", or \"account\")", c.ID, c.Scope)
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
